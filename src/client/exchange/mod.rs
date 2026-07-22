//! Multi-packet capture-ready exchange contracts.

mod contract;

pub(crate) use contract::{
    CaptureGuard, ExchangeAccumulator, ExchangeOptions, ExchangeProcessContext,
    ExchangeProcessOutcome, ExchangeResult, PlannedExchangePacket, PreparedExchangePacket,
    WorkflowPromotionContext, WorkflowResponseMatcher, drain_available,
};
pub use contract::{
    DEFAULT_MAX_UNSOLICITED_FRAMES, ExchangeOptions as Options, ExchangeResult as Result,
    MAX_EXCHANGE_TIMEOUT, MatchedResponse as Response,
};
