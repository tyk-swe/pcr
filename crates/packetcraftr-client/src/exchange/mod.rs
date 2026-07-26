// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Multi-packet capture-ready exchange contracts.

mod contract;
mod options;
mod transaction;

pub(crate) use contract::{
    CaptureGuard, ExchangeAccumulator, ExchangeOptions, ExchangeProcessContext,
    ExchangeProcessOutcome, ExchangeResult, PlannedExchangePacket, PreparedExchangePacket,
    WorkflowPromotionContext, WorkflowResponseMatcher, drain_available,
};
pub use contract::{
    DEFAULT_MAX_UNSOLICITED_FRAMES, ExchangeOptions as Options, ExchangeResult as Result,
    MAX_EXCHANGE_TIMEOUT, MatchedResponse as Response,
};
pub(crate) use transaction::{ExchangeTransaction, PreparedExchange};
