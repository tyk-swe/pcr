// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::str::FromStr;

use crate::domain::net::MacAddress;
use trust_dns_proto::rr::RecordType;

pub fn mac_address_validator(s: &str) -> Result<String, String> {
    MacAddress::from_str(s)
        .map(|_| s.to_string())
        .map_err(|_| format!("invalid MAC address: {s} (expected format xx:xx:xx:xx:xx:xx)"))
}

pub fn socket_addr_validator(s: &str) -> Result<String, String> {
    std::net::SocketAddr::from_str(s)
        .map(|_| s.to_string())
        .map_err(|_| {
            format!("invalid socket address: {s} (expected format host:port, e.g., 127.0.0.1:9898)")
        })
}

pub fn dns_record_type_validator(s: &str) -> Result<String, String> {
    RecordType::from_str(&s.to_uppercase())
        .map(|_| s.to_string())
        .map_err(|_| {
            format!(
                "unsupported DNS record type: {s} (valid types are those supported by trust-dns-proto)"
            )
        })
}
