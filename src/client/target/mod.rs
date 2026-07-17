//! Live target resolution.

mod contract;

pub use contract::{
    Hostname, HostnameResolver as Resolver, IpVersion, LiveTarget as Target,
    ResolvedTarget as Resolved, SystemHostnameResolver as SystemResolver,
    TargetResolutionError as Error,
};
pub(crate) use contract::{HostnameResolver, LiveTarget, ResolvedTarget, TargetResolutionError};
