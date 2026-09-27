// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Header-transaction evidence: the association a request/response head pair
//! settles into, and the physical capture observations that made each header
//! boundary available to the parser. Timing is capture-observed availability,
//! never an inferred wire time; clock regressions stay signed intervals.

use super::{Connection, RequestKey};
use crate::analysis::reassembly::tcp::ScopedFlowKey;
use serde::Serialize;
use std::time::SystemTime;

/// Conservative retained-byte charge for one pending request's transaction
/// metadata, in addition to the existing header/message charges.
pub(super) const PENDING_REQUEST_BYTES: usize = 512;
/// Conservative retained-byte charge for one informational response index a
/// pending request accumulates.
pub(super) const INFORMATIONAL_BYTES: usize = 32;
/// Conservative retained-byte charge for one emitted transaction.
pub(super) const TRANSACTION_BYTES: usize = 512;

/// The physical capture frame whose processing made one header boundary
/// available to the parser, with its capture timestamp. A reassembled or
/// gap-filled delivery marks the frame that released the bytes, not the
/// earliest contributing source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Availability {
    pub frame: u64,
    pub timestamp: SystemTime,
}

/// A signed interval between two availability markers. Negative intervals
/// from capture-clock regressions stay visible; a zero interval is never
/// negative. This is a difference of parser-availability observations, not a
/// measurement of wire transit or server processing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Interval {
    pub nanoseconds: u128,
    pub negative: bool,
}
impl Interval {
    /// `end - start`, retaining a negative result's magnitude and sign.
    pub(super) fn between(start: SystemTime, end: SystemTime) -> Self {
        match end.duration_since(start) {
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

/// How a settled request/response header association ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionOutcome {
    /// A parsed response head consumed a pending request.
    Paired,
    /// A request saw no consuming response before its stream retired.
    Unanswered,
    /// A response head had no pending request to consume.
    OrphanResponse,
}

/// One settled header association: the message indices the existing request
/// queue linked, plus the availability markers and signed intervals the
/// capture observed. Header association alone says nothing about body
/// completeness; message statuses remain the authority there.
#[derive(Clone, Debug)]
pub struct Transaction {
    /// Emission index within the run, numbered from 1; separate from message
    /// indices.
    pub index: u64,
    /// Capture-global conversation index, matching the linked messages.
    pub stream: u64,
    /// Connection generation within `stream`, matching the linked messages.
    pub generation: u64,
    /// The request direction's scoped flow when a request was seen; the
    /// observed response direction for an orphan response.
    pub flow: ScopedFlowKey,
    pub outcome: TransactionOutcome,
    /// The request message index, when the association has a request.
    pub request: Option<u64>,
    /// The consuming response index for `paired`, the observed response index
    /// for `orphan_response`, and `None` for `unanswered`.
    pub response: Option<u64>,
    /// The parsed response status in 100..=599, when a response was seen.
    pub response_status: Option<u16>,
    /// Informational (1xx except 101) response indices the request
    /// accumulated before settling, in observed header-parse order.
    pub informational: Vec<u64>,
    /// The observation that completed the request head.
    pub request_headers_available: Option<Availability>,
    /// The observation whose parser consumed the response head's first byte.
    pub response_started: Option<Availability>,
    /// The observation that completed the response head.
    pub response_headers_available: Option<Availability>,
    /// `response_started - request_headers_available`, when both exist.
    pub response_header_wait: Option<Interval>,
    /// `response_headers_available - response_started`, when both exist.
    pub response_header_span: Option<Interval>,
}
impl Transaction {
    /// The row a final response head settles by consuming `request`.
    pub(super) fn paired(
        key: &RequestKey,
        request: u64,
        state: Option<PendingTransaction>,
        response: u64,
        status: u16,
        started: Option<Availability>,
        available: Option<Availability>,
    ) -> Self {
        let request_available = state.as_ref().map(|state| state.request_headers_available);
        Self {
            index: 0,
            stream: key.0.0,
            generation: key.0.1,
            flow: key.1.clone(),
            outcome: TransactionOutcome::Paired,
            request: Some(request),
            response: Some(response),
            response_status: Some(status),
            informational: state.map_or_else(Vec::new, |state| state.informational),
            request_headers_available: request_available,
            response_started: started,
            response_headers_available: available,
            response_header_wait: request_available
                .zip(started)
                .map(|(request, started)| Interval::between(request.timestamp, started.timestamp)),
            response_header_span: started.zip(available).map(|(started, available)| {
                Interval::between(started.timestamp, available.timestamp)
            }),
        }
    }

    /// The row a retired pending request settles into without a final
    /// response: it keeps its marker and informational observations and has
    /// no response markers or intervals.
    pub(super) fn unanswered(
        key: &RequestKey,
        request: u64,
        state: Option<PendingTransaction>,
    ) -> Self {
        let (request_available, informational) = state.map_or_else(
            || (None, Vec::new()),
            |state| (Some(state.request_headers_available), state.informational),
        );
        Self {
            index: 0,
            stream: key.0.0,
            generation: key.0.1,
            flow: key.1.clone(),
            outcome: TransactionOutcome::Unanswered,
            request: Some(request),
            response: None,
            response_status: None,
            informational,
            request_headers_available: request_available,
            response_started: None,
            response_headers_available: None,
            response_header_wait: None,
            response_header_span: None,
        }
    }

    /// The row a response head settles into when no request is pending,
    /// including orphan informational responses: no request marker or wait,
    /// and no pairing with any later final response is guessed.
    pub(super) fn orphan(
        connection: Connection,
        flow: ScopedFlowKey,
        response: u64,
        status: u16,
        started: Option<Availability>,
        available: Option<Availability>,
    ) -> Self {
        Self {
            index: 0,
            stream: connection.0,
            generation: connection.1,
            flow,
            outcome: TransactionOutcome::OrphanResponse,
            request: None,
            response: Some(response),
            response_status: Some(status),
            informational: Vec::new(),
            request_headers_available: None,
            response_started: started,
            response_headers_available: available,
            response_header_wait: None,
            response_header_span: started.zip(available).map(|(started, available)| {
                Interval::between(started.timestamp, available.timestamp)
            }),
        }
    }
}

/// Outcome counters across every transaction the run emitted. Negative
/// counters tally only emitted non-null negative intervals.
#[derive(Clone, Debug, Default, Serialize)]
pub struct TransactionSummary {
    pub transactions: u64,
    pub paired: u64,
    pub unanswered: u64,
    pub orphan_responses: u64,
    pub negative_header_waits: u64,
    pub negative_header_spans: u64,
}

/// The transaction metadata one pending request retains while the collection
/// is enabled: the observation that completed its head and the informational
/// responses that stayed pending on it.
pub(super) struct PendingTransaction {
    pub request_headers_available: Availability,
    pub informational: Vec<u64>,
}

/// Numbering and counters for emitted transactions; present only while the
/// collection is enabled.
pub(super) struct Transactions {
    next: u64,
    pub(super) summary: TransactionSummary,
}
impl Transactions {
    pub(super) fn new() -> Self {
        Self {
            next: 1,
            summary: TransactionSummary::default(),
        }
    }
    /// Numbers a settled row in emission order and folds it into the summary.
    pub(super) fn emit(&mut self, mut transaction: Transaction) -> Transaction {
        transaction.index = self.next;
        self.next += 1;
        self.summary.transactions += 1;
        match transaction.outcome {
            TransactionOutcome::Paired => self.summary.paired += 1,
            TransactionOutcome::Unanswered => self.summary.unanswered += 1,
            TransactionOutcome::OrphanResponse => self.summary.orphan_responses += 1,
        }
        if transaction
            .response_header_wait
            .is_some_and(|interval| interval.negative)
        {
            self.summary.negative_header_waits += 1;
        }
        if transaction
            .response_header_span
            .is_some_and(|interval| interval.negative)
        {
            self.summary.negative_header_spans += 1;
        }
        transaction
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn interval_between_keeps_sign_and_never_marks_zero_negative() {
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let forward = Interval::between(base, base + Duration::from_nanos(125_000_000));
        assert_eq!(forward.nanoseconds, 125_000_000);
        assert!(!forward.negative);

        let backward = Interval::between(base + Duration::from_nanos(2_000_000), base);
        assert_eq!(backward.nanoseconds, 2_000_000);
        assert!(backward.negative);

        let zero = Interval::between(base, base);
        assert_eq!(zero.nanoseconds, 0);
        assert!(!zero.negative);
    }

    #[test]
    fn emit_numbers_from_one_and_counts_outcomes_and_negative_intervals() {
        let mut transactions = Transactions::new();
        let key: RequestKey = ((7, 2), flow());
        let at = |seconds: u64| {
            Some(Availability {
                frame: seconds,
                timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(seconds),
            })
        };

        let paired = transactions.emit(Transaction::paired(
            &key,
            3,
            Some(PendingTransaction {
                request_headers_available: at(5).unwrap(),
                informational: vec![4, 5],
            }),
            6,
            200,
            at(4),
            at(7),
        ));
        assert_eq!(paired.index, 1);
        assert_eq!(paired.informational, [4, 5]);
        let wait = paired.response_header_wait.expect("paired wait");
        assert!(wait.negative);
        assert_eq!(wait.nanoseconds, 1_000_000_000);
        let span = paired.response_header_span.expect("paired span");
        assert!(!span.negative);
        assert_eq!(span.nanoseconds, 3_000_000_000);

        let unanswered = transactions.emit(Transaction::unanswered(
            &key,
            8,
            Some(PendingTransaction {
                request_headers_available: at(5).unwrap(),
                informational: vec![9],
            }),
        ));
        assert_eq!(unanswered.index, 2);
        assert_eq!(unanswered.informational, [9]);
        assert!(unanswered.response.is_none());

        let orphan = transactions.emit(Transaction::orphan((7, 2), flow(), 10, 404, at(8), at(8)));
        assert_eq!(orphan.index, 3);
        assert!(orphan.request.is_none());
        assert_eq!(orphan.response_header_span.unwrap().nanoseconds, 0);
        assert!(!orphan.response_header_span.unwrap().negative);

        let missing_markers =
            transactions.emit(Transaction::paired(&key, 11, None, 12, 200, None, None));
        assert_eq!(missing_markers.index, 4);
        assert!(missing_markers.response_header_wait.is_none());
        assert!(missing_markers.response_header_span.is_none());

        let summary = &transactions.summary;
        assert_eq!(summary.transactions, 4);
        assert_eq!(summary.paired, 2);
        assert_eq!(summary.unanswered, 1);
        assert_eq!(summary.orphan_responses, 1);
        assert_eq!(summary.negative_header_waits, 1);
        assert_eq!(summary.negative_header_spans, 0);
    }

    fn flow() -> ScopedFlowKey {
        use crate::analysis::{reassembly::tcp::FlowKey, scope::Interner};
        use std::net::{IpAddr, Ipv4Addr};
        ScopedFlowKey {
            scope: Interner::new()
                .intern(None, Vec::new())
                .expect("scope interns"),
            flow: FlowKey {
                source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                source_port: 40_000,
                destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
                destination_port: 80,
            },
        }
    }
}
