// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Multi-packet capture-ready exchange contracts.

mod accumulator;
mod capture;
mod contract;
mod correlation;
mod execution;
mod finalization;
mod options;
mod preparation;
mod retention;
mod route_cache;
mod send_sequence;
mod shutdown;
mod transaction;

pub(crate) use accumulator::{
    ExchangeAccumulator, ExchangeProcessContext, ExchangeProcessOutcome, WorkflowPromotionContext,
    WorkflowResponseMatcher,
};
pub use contract::{
    DEFAULT_MAX_UNSOLICITED_FRAMES, ExchangeOptions as Options, ExchangeResult as Result,
    MAX_EXCHANGE_TIMEOUT, MatchedResponse as Response,
};
pub(crate) use contract::{ExchangeOptions, ExchangeResult};
pub(crate) use preparation::{PreparedExchange, PreparedExchangePacket};
pub(crate) use shutdown::CaptureGuard;
pub(crate) use transaction::ExchangeTransaction;
