// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt::Write as _;
use std::net::IpAddr;

use super::{Name, Record, RecordValue};

/// PTR name: reversed IPv4 octets under `in-addr.arpa` or IPv6 nibbles under `ip6.arpa`.
pub fn reverse_name(address: IpAddr) -> String {
    match address {
        IpAddr::V4(address) => {
            let [a, b, c, d] = address.octets();
            format!("{d}.{c}.{b}.{a}.in-addr.arpa")
        }
        IpAddr::V6(address) => {
            let mut name = String::with_capacity(32 * 2 + "ip6.arpa".len());
            for byte in address.octets().iter().rev() {
                for nibble in [byte & 0x0f, byte >> 4] {
                    let _ = write!(name, "{nibble:x}.");
                }
            }
            name.push_str("ip6.arpa");
            name
        }
    }
}

/// Distinct PTR names among a [validated response](super::ValidatedResponse)'s
/// answers, in answer order. Validation keeps only the query name's CNAME
/// chain, so a classless delegation (RFC 2317) still yields its names.
pub fn ptr_names(answers: &[Record]) -> Vec<Name> {
    let mut names: Vec<Name> = Vec::new();
    for record in answers {
        if let RecordValue::Ptr(name) = &record.value
            && !names.contains(name)
        {
            names.push(name.clone());
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(owner: &str, value: RecordValue) -> Record {
        Record {
            owner: owner.parse().unwrap(),
            class: 1,
            ttl: 60,
            value,
        }
    }

    #[test]
    fn ptr_names_follow_the_validated_chain_once_each() {
        let query = "10.2.0.192.in-addr.arpa";
        let delegated = "10.0-25.2.0.192.in-addr.arpa";
        let host: Name = "host.example.".parse().unwrap();
        let answers = [
            record(query, RecordValue::Cname(delegated.parse().unwrap())),
            record(delegated, RecordValue::Ptr(host.clone())),
            record(
                delegated,
                RecordValue::Ptr("HOST.example.".parse().unwrap()),
            ),
            record(
                delegated,
                RecordValue::Ptr("alias.example.".parse().unwrap()),
            ),
        ];
        assert_eq!(
            ptr_names(&answers),
            [host, "alias.example.".parse().unwrap()]
        );
        assert!(ptr_names(&[]).is_empty());
    }
}
