// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::str::FromStr;

use crate::domain::net::MacAddress;
use trust_dns_proto::rr::RecordType;

pub(crate) fn mac_address_validator(s: &str) -> Result<String, String> {
    MacAddress::from_str(s)
        .map(|_| s.to_string())
        .map_err(|_| format!("invalid MAC address: {s} (expected format xx:xx:xx:xx:xx:xx)"))
}

pub(crate) fn socket_addr_validator(s: &str) -> Result<String, String> {
    std::net::SocketAddr::from_str(s)
        .map(|_| s.to_string())
        .map_err(|_| {
            format!("invalid socket address: {s} (expected format host:port, e.g., 127.0.0.1:9898)")
        })
}

pub(crate) fn dns_record_type_validator(s: &str) -> Result<String, String> {
    RecordType::from_str(&s.to_uppercase())
        .map(|_| s.to_string())
        .map_err(|_| {
            format!(
                "unsupported DNS record type: {s} (valid types are those supported by trust-dns-proto)"
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_address_validator_accepts_supported_forms() {
        assert_eq!(
            mac_address_validator("aa:bb:cc:dd:ee:ff").unwrap(),
            "aa:bb:cc:dd:ee:ff"
        );
        assert_eq!(
            mac_address_validator("aa-bb-cc-dd-ee-ff").unwrap(),
            "aa-bb-cc-dd-ee-ff"
        );
    }

    #[test]
    fn mac_address_validator_rejects_invalid_input_with_context() {
        let err = mac_address_validator("aa:bb:cc").unwrap_err();

        assert!(err.contains("invalid MAC address: aa:bb:cc"));
        assert!(err.contains("xx:xx:xx:xx:xx:xx"));
    }

    #[test]
    fn socket_addr_validator_accepts_ipv4_and_bracketed_ipv6() {
        assert_eq!(
            socket_addr_validator("127.0.0.1:9898").unwrap(),
            "127.0.0.1:9898"
        );
        assert_eq!(socket_addr_validator("[::1]:9898").unwrap(), "[::1]:9898");
    }

    #[test]
    fn socket_addr_validator_rejects_missing_port() {
        let err = socket_addr_validator("127.0.0.1").unwrap_err();

        assert!(err.contains("invalid socket address: 127.0.0.1"));
        assert!(err.contains("host:port"));
    }

    #[test]
    fn dns_record_type_validator_accepts_case_insensitive_types() {
        assert_eq!(dns_record_type_validator("a").unwrap(), "a");
        assert_eq!(dns_record_type_validator("AAAA").unwrap(), "AAAA");
        assert_eq!(dns_record_type_validator("mx").unwrap(), "mx");
    }

    #[test]
    fn dns_record_type_validator_rejects_unknown_type() {
        let err = dns_record_type_validator("notatype").unwrap_err();

        assert!(err.contains("unsupported DNS record type: notatype"));
    }
}
