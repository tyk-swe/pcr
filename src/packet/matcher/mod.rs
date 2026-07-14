//! Response-correlation extension contracts.

mod contract;

pub use contract::{MatchResult as Result, ResponseMatcher as Matcher};
pub(crate) use contract::{MatchResult, ResponseMatcher};
