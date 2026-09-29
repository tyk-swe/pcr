// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv4Addr;
use std::time::Duration;

use packetcraftr::dns;
use packetcraftr::target::{Family, Target};

pub(crate) fn tcp_request(name: &str) -> dns::Request {
    dns::Request {
        server: Target::Address(Ipv4Addr::LOCALHOST.into()),
        address_family: Family::Any,
        server_port: 53,
        source_port: 40_000,
        query_name: name.to_owned(),
        query_type: dns::QueryType::A,
        transaction_id: 0x1234,
        recursion_desired: true,
        edns: None,
        transport: dns::TransportMode::Tcp,
        attempts: 1,
        timeout: Duration::from_millis(200),
        queries_per_second: None,
        limits: dns::Limits::default(),
        route: Default::default(),
        collection: Default::default(),
    }
}
