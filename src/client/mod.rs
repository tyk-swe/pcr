// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Policy-gated packet transmission and response exchange.

#[allow(clippy::module_inception)]
mod client;
pub mod exchange;
mod helpers;
pub mod policy;
pub mod send;
mod stats;
pub mod target;

pub use client::Client;
pub use send::contract::ClientError as Error;
pub use stats::OperationStats as Stats;

#[cfg(test)]
mod tests;

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
