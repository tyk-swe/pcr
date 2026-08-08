// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_live::dns;

#[test]
fn dns_names_and_response_codes_are_canonical_and_bounded() {
    assert_eq!(
        dns::canonical_query_name("WWW.Example.COM").expect("name must be valid"),
        "www.example.com."
    );
    assert_eq!(
        dns::canonical_query_name(".").expect("root must be valid"),
        "."
    );
    assert!(dns::canonical_query_name("bad..name").is_err());
    assert_eq!(dns::response_code_name(3), "name_error");
    assert_eq!(dns::response_code_name(u16::MAX), "unknown");
}
