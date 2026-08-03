// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// Address family selection shared by target-oriented workflows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressFamily {
    #[default]
    Any,
    Ipv4,
    Ipv6,
}

impl AddressFamily {
    pub(crate) fn accepts(self, address: IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::Ipv4 => address.is_ipv4(),
            Self::Ipv6 => address.is_ipv6(),
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Any => "requested",
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::AddressFamily;

    #[test]
    fn any_address_family_accepts_both_ip_versions() {
        assert!(AddressFamily::Any.accepts(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(AddressFamily::Any.accepts(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn explicit_address_families_reject_the_other_ip_version() {
        assert!(AddressFamily::Ipv4.accepts(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!AddressFamily::Ipv4.accepts(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(AddressFamily::Ipv6.accepts(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!AddressFamily::Ipv6.accepts(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn address_family_labels_are_stable_and_any_is_default() {
        assert_eq!(AddressFamily::default(), AddressFamily::Any);
        assert_eq!(AddressFamily::Any.label(), "requested");
        assert_eq!(AddressFamily::Ipv4.label(), "IPv4");
        assert_eq!(AddressFamily::Ipv6.label(), "IPv6");
    }
}
