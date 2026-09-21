// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Message, Transport};
use crate::analysis::{
    application::{Error, Limits},
    provenance::SourceSet,
    reassembly::tcp::ScopedFlowKey,
};
use serde::Serialize;
use std::{collections::BTreeMap, time::SystemTime};

/// The terminal state of a query/response transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionStatus {
    /// A response matching the query's key was captured.
    Matched,
    /// No matching response was captured before the transaction closed.
    Unanswered,
    /// A response arrived for which no query was ever seen.
    OrphanResponse,
    /// A second response arrived after one already matched the query.
    DuplicateResponse,
}
/// Difference between response's first captured byte and query's last captured
/// byte. Negative intervals remain visible, including capture-clock regressions and
/// queries whose reassembly completes after their response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Latency {
    pub nanoseconds: u128,
    pub negative: bool,
}
impl Latency {
    fn between(query: SystemTime, response: SystemTime) -> Self {
        match response.duration_since(query) {
            Ok(elapsed) => Self {
                nanoseconds: elapsed.as_nanos(),
                negative: false,
            },
            Err(error) => Self {
                nanoseconds: error.duration().as_nanos(),
                negative: true,
            },
        }
    }
}
/// A settled query/response transaction, keyed on wire identity and questions.
#[derive(Clone, Debug)]
pub struct Transaction {
    pub status: TransactionStatus,
    pub transport: Transport,
    pub stream: u64,
    pub generation: u64,
    /// Query direction, including for orphan responses.
    pub flow: ScopedFlowKey,
    pub dns_id: u16,
    pub queries: Vec<u64>,
    pub response: Option<u64>,
    pub original_response: Option<u64>,
    pub first_query_latency: Option<Latency>,
    pub latest_query_latency: Option<Latency>,
    pub sources: SourceSet,
}
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    transport: Transport,
    stream: u64,
    generation: u64,
    flow: ScopedFlowKey,
    id: u16,
    opcode: u8,
    questions: Vec<(Vec<Vec<u8>>, u16, u16)>,
}
impl Key {
    fn from(message: &Message) -> Option<Self> {
        let dns = message.dns.as_ref()?;
        Some(Self {
            transport: message.transport,
            stream: message.stream,
            generation: message.generation,
            flow: if dns.response {
                message.flow.reverse()
            } else {
                message.flow.clone()
            },
            id: dns.id,
            opcode: dns.opcode,
            questions: dns
                .questions
                .iter()
                .map(|q| {
                    (
                        q.name
                            .labels()
                            .iter()
                            .map(|label| label.iter().map(u8::to_ascii_lowercase).collect())
                            .collect(),
                        q.query_type,
                        q.class,
                    )
                })
                .collect(),
        })
    }
}
struct Pending {
    queries: Vec<u64>,
    first: SystemTime,
    last: SystemTime,
    sources: SourceSet,
}
struct Answered {
    queries: Vec<u64>,
    response: u64,
    sources: SourceSet,
}
struct Waiting {
    index: u64,
    sources: SourceSet,
}
pub(super) struct Tracker {
    limits: Limits,
    pending: BTreeMap<Key, Pending>,
    answered: BTreeMap<Key, Answered>,
    waiting: BTreeMap<Key, Vec<Waiting>>,
    charged: usize,
}
impl Tracker {
    pub(super) fn new(limits: Limits) -> Self {
        Self {
            limits,
            pending: BTreeMap::new(),
            answered: BTreeMap::new(),
            waiting: BTreeMap::new(),
            charged: 0,
        }
    }
    pub(super) fn observe(&mut self, message: &Message) -> Result<Vec<Transaction>, Error> {
        let Some(key) = Key::from(message) else {
            return Ok(Vec::new());
        };
        let dns = message.dns.as_ref().expect("key requires decoded DNS");
        let last = message
            .sources
            .frames()
            .last()
            .ok_or(Error::Sources { number: 0 })?
            .timestamp;
        self.charged = self.charged.saturating_add(
            512 + key
                .questions
                .iter()
                .map(|(labels, _, _)| {
                    labels.iter().map(|label| label.len() + 32).sum::<usize>() + 64
                })
                .sum::<usize>(),
        );
        self.limits.check_retained(self.charged)?;
        if !dns.response {
            self.answered.remove(&key);
            if let Some(pending) = self.pending.get_mut(&key) {
                pending.queries.push(message.index);
                pending.last = last;
                pending.sources = pending.sources.union(&message.sources)?;
            } else {
                self.pending.insert(
                    key.clone(),
                    Pending {
                        queries: vec![message.index],
                        first: last,
                        last,
                        sources: message.sources.clone(),
                    },
                );
            }
            // A query can finish reassembly after its response. Link it only
            // when captured query bytes already preceded the response; a later
            // independent query must not absorb an older orphan response.
            let first_query_frame = self.pending[&key].sources.frames()[0].number;
            let mut waiting = self.waiting.remove(&key).unwrap_or_default();
            waiting.sort_by_key(|response| response.sources.frames()[0].number);
            let mut output = Vec::new();
            let mut older = Vec::new();
            for response in waiting {
                if response.sources.frames()[0].number > first_query_frame {
                    if let Some(pending) = self.pending.remove(&key) {
                        output.push(self.matched(&key, pending, response)?);
                    } else {
                        output.push(self.duplicate(&key, response)?);
                    }
                } else {
                    older.push(response);
                }
            }
            if !older.is_empty() {
                self.waiting.insert(key, older);
            }
            return Ok(output);
        }
        let response = Waiting {
            index: message.index,
            sources: message.sources.clone(),
        };
        if let Some(pending) = self.pending.remove(&key) {
            return Ok(vec![self.matched(&key, pending, response)?]);
        }
        if self.answered.contains_key(&key) {
            return Ok(vec![self.duplicate(&key, response)?]);
        }
        self.waiting.entry(key).or_default().push(response);
        Ok(Vec::new())
    }
    fn response(key: &Key, response: Waiting) -> Transaction {
        Transaction {
            status: TransactionStatus::OrphanResponse,
            transport: key.transport,
            stream: key.stream,
            generation: key.generation,
            flow: key.flow.clone(),
            dns_id: key.id,
            queries: Vec::new(),
            response: Some(response.index),
            original_response: None,
            first_query_latency: None,
            latest_query_latency: None,
            sources: response.sources,
        }
    }
    fn matched(
        &mut self,
        key: &Key,
        pending: Pending,
        response: Waiting,
    ) -> Result<Transaction, Error> {
        let first = response.sources.frames()[0].timestamp;
        let response_index = response.index;
        let mut transaction = Self::response(key, response);
        transaction.status = TransactionStatus::Matched;
        transaction.queries = pending.queries.clone();
        transaction.first_query_latency = Some(Latency::between(pending.first, first));
        transaction.latest_query_latency = Some(Latency::between(pending.last, first));
        transaction.sources = pending.sources.union(&transaction.sources)?;
        self.answered.insert(
            key.clone(),
            Answered {
                queries: pending.queries,
                response: response_index,
                sources: transaction.sources.clone(),
            },
        );
        Ok(transaction)
    }
    fn duplicate(&self, key: &Key, response: Waiting) -> Result<Transaction, Error> {
        let answered = &self.answered[key];
        let mut transaction = Self::response(key, response);
        transaction.status = TransactionStatus::DuplicateResponse;
        transaction.queries = answered.queries.clone();
        transaction.original_response = Some(answered.response);
        transaction.sources = answered.sources.union(&transaction.sources)?;
        Ok(transaction)
    }
    pub(super) fn finish(&mut self) -> Vec<Transaction> {
        let mut transactions: Vec<_> = std::mem::take(&mut self.pending)
            .into_iter()
            .map(|(key, pending)| Transaction {
                status: TransactionStatus::Unanswered,
                transport: key.transport,
                stream: key.stream,
                generation: key.generation,
                flow: key.flow,
                dns_id: key.id,
                queries: pending.queries,
                response: None,
                original_response: None,
                first_query_latency: None,
                latest_query_latency: None,
                sources: pending.sources,
            })
            .collect();
        transactions.extend(std::mem::take(&mut self.waiting).into_iter().flat_map(
            |(key, responses)| {
                responses
                    .into_iter()
                    .map(move |response| Self::response(&key, response))
            },
        ));
        transactions.sort_by_key(|transaction| {
            transaction
                .response
                .or_else(|| transaction.queries.first().copied())
        });
        transactions
    }
}
