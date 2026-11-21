// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Differential testing: one Intent under several Variants, with Verdicts
//! proven by a cooperating Responder.

pub mod canary;
pub mod catalog;
pub mod dns;
pub mod tcp_vantage;

mod engine;
mod error;
mod plan;
mod report;
mod request;
mod responder;

pub use error::Error;
pub use plan::{PlanRow, PlanSummary};
pub use report::{
    Aggregate, AttemptEvidence, Collector, Event, NatBehavior, NatMapping, ReceptionRecord, Report,
    ResponderAggregate, ResponderCollector, ResponderEvent, ResponderReport, Row,
    SensorObservation, VantageRow, Verdict, hex, join_receptions, nat_mapping, rows_for,
    three_vantage, verdict_for,
};
pub use request::{
    DEFAULT_PAYLOAD_LEN, DEFAULT_REPEATS, DEFAULT_SOURCE_PORT, MAX_PAYLOAD_LEN, MAX_REPEATS,
    Request, ResponderRequest, generate_token,
};
pub use responder::respond;
