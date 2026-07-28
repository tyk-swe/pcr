// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Multi-packet capture-ready exchange contracts.

mod accumulator;
mod contract;
mod guard;
mod options;
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
pub(crate) use guard::CaptureGuard;
pub(crate) use transaction::{
    ExchangeTransaction, PlannedExchangePacket, PreparedExchange, PreparedExchangePacket,
};
