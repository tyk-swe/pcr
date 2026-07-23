// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv4Addr;

use crate::packet::matcher::ResponseMatcher;

use super::super::EchoMatcher;
use super::super::tests::echo;

#[test]
fn echo_matcher_requires_reversed_network_endpoints() {
    let request = echo(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2), 8);
    let unrelated = echo(Ipv4Addr::new(10, 0, 0, 3), Ipv4Addr::new(10, 0, 0, 1), 0);
    let response = echo(Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 1), 0);

    assert!(!EchoMatcher::v4().matches(&request, &unrelated).matched);
    assert!(EchoMatcher::v4().matches(&request, &response).matched);
}
