// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Policy-gated packet transmission and response exchange.

mod internal;

pub use internal::{client::Client, send::ClientError as Error, stats::OperationStats as Stats};

/// Live target resolution.
pub mod target {
    pub use super::internal::policy::{DEFAULT_MAX_RESOLVED_ADDRESSES, MAX_RESOLVED_ADDRESSES};
    pub use super::internal::target::{
        Hostname, HostnameResolver as Resolver, IpVersion, LiveTarget as Target,
        ResolvedTarget as Resolved, SystemHostnameResolver as SystemResolver,
        TargetResolutionError as Error,
    };
}

/// Live traffic authorization policy.
pub mod policy {
    pub use super::internal::policy::{TrafficPolicy as Policy, TrafficPolicyError as Error};
}

/// Single-packet send contracts.
pub mod send {
    pub use super::internal::send::{SendOptions as Options, SendReport as Report};
}

/// Multi-packet capture-ready exchange contracts.
pub mod exchange {
    pub use super::internal::exchange::{
        DEFAULT_MAX_UNSOLICITED_FRAMES, ExchangeOptions as Options, ExchangeResult as Result,
        MAX_EXCHANGE_TIMEOUT, MatchedResponse as Response, ObservedError, Progress,
        ProgressObserver,
    };
}

#[cfg(test)]
mod public_api_tests {
    use super::policy::Policy;
    use super::target::{IpVersion, SystemResolver, Target};

    #[test]
    fn resolved_target_exposes_typed_ip_version_selection() {
        let address = "10.0.0.1".parse().unwrap();
        let target = Target::Address(address);
        let resolved = Policy::default()
            .resolve_target(&target, &SystemResolver)
            .unwrap();

        assert_eq!(resolved.address_for_version(IpVersion::V4), Some(address));
        assert_eq!(resolved.address_for_version(IpVersion::V6), None);
    }
}
