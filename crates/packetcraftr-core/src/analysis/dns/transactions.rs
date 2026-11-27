// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::Message;
use crate::analysis::{
    ScopedFlowKey, StreamTransport,
    application::{Error, Retained},
    provenance::{Accumulator, SourceFrame, SourceSet},
};
use serde::Serialize;
use std::{collections::BTreeMap, time::SystemTime};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionStatus {
    Matched,
    Unanswered,
    OrphanResponse,
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
#[derive(Clone, Debug)]
pub struct Transaction {
    pub status: TransactionStatus,
    pub transport: StreamTransport,
    pub stream: u64,
    pub generation: u64,
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
    transport: StreamTransport,
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
    sources: Accumulator,
}
struct Answered {
    queries: Vec<u64>,
    response: u64,
    sources: SourceSet,
}
struct Observation {
    index: u64,
    response: bool,
    sources: SourceSet,
}
impl Observation {
    fn first(&self) -> &SourceFrame {
        &self.sources.frames()[0]
    }

    fn end_time(&self) -> SystemTime {
        self.sources
            .frames()
            .last()
            .expect("observation has sources")
            .timestamp
    }
}

pub(super) struct Tracker {
    observations: BTreeMap<Key, Vec<Observation>>,
}
impl Tracker {
    pub(super) fn new() -> Self {
        Self {
            observations: BTreeMap::new(),
        }
    }

    pub(super) fn observe(
        &mut self,
        message: &Message,
        retained: &mut Retained,
    ) -> Result<(), Error> {
        let Some(key) = Key::from(message) else {
            return Ok(());
        };
        let dns = message.dns.as_ref().expect("key requires decoded DNS");
        if message.sources.frames().is_empty() {
            return Err(Error::Sources { number: 0 });
        }
        retained.charge_amount(
            512 + key
                .questions
                .iter()
                .map(|(labels, _, _)| {
                    labels.iter().map(|label| label.len() + 32).sum::<usize>() + 64
                })
                .sum::<usize>(),
        )?;
        self.observations.entry(key).or_default().push(Observation {
            index: message.index,
            response: dns.response,
            sources: message.sources.clone(),
        });
        Ok(())
    }

    pub(super) fn finish(
        &mut self,
        mut check: impl FnMut() -> Result<(), Error>,
        mut emit: impl FnMut(Transaction) -> Result<(), Error>,
    ) -> Result<(), Error> {
        for (key, mut observations) in std::mem::take(&mut self.observations) {
            check()?;
            // A query must start in a strictly earlier physical frame than its response.
            observations
                .sort_unstable_by_key(|entry| (entry.first().number, !entry.response, entry.index));
            let mut pending: Option<Pending> = None;
            let mut answered: Option<Answered> = None;
            for entry in observations {
                check()?;
                if !entry.response {
                    answered = None;
                    let last = entry.end_time();
                    if let Some(pending) = &mut pending {
                        pending.queries.push(entry.index);
                        pending.last = last;
                        pending.sources.insert(&entry.sources)?;
                    } else {
                        pending = Some(Pending {
                            queries: vec![entry.index],
                            first: last,
                            last,
                            sources: Accumulator::new(&entry.sources)?,
                        });
                    }
                    continue;
                }
                let first = entry.first().timestamp;
                let mut transaction = Transaction {
                    status: TransactionStatus::OrphanResponse,
                    transport: key.transport,
                    stream: key.stream,
                    generation: key.generation,
                    flow: key.flow.clone(),
                    dns_id: key.id,
                    queries: Vec::new(),
                    response: Some(entry.index),
                    original_response: None,
                    first_query_latency: None,
                    latest_query_latency: None,
                    sources: entry.sources,
                };
                if let Some(mut pending) = pending.take() {
                    pending.sources.insert(&transaction.sources)?;
                    transaction.status = TransactionStatus::Matched;
                    transaction.queries = pending.queries;
                    transaction.first_query_latency = Some(Latency::between(pending.first, first));
                    transaction.latest_query_latency = Some(Latency::between(pending.last, first));
                    transaction.sources = pending.sources.freeze()?;
                    answered = Some(Answered {
                        queries: transaction.queries.clone(),
                        response: entry.index,
                        sources: transaction.sources.clone(),
                    });
                } else if let Some(answered) = &answered {
                    transaction.status = TransactionStatus::DuplicateResponse;
                    transaction.queries.clone_from(&answered.queries);
                    transaction.original_response = Some(answered.response);
                    transaction.sources = answered.sources.union(&transaction.sources)?;
                }
                emit(transaction)?;
            }
            if let Some(pending) = pending {
                check()?;
                emit(Transaction {
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
                    sources: pending.sources.freeze()?,
                })?;
            }
        }
        Ok(())
    }
}
