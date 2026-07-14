//! Live traffic authorization policy.

mod authorization;
mod contract;

pub use contract::{DEFAULT_MAX_RESOLVED_ADDRESSES, MAX_RESOLVED_ADDRESSES};
pub use contract::{TrafficPolicy as Policy, TrafficPolicyError as Error};
pub(crate) use contract::{TrafficPolicy, TrafficPolicyError};
