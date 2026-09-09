// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use packetcraftr::{Client, policy::Policy, progress::Runtime};
use packetcraftr_netio::{Error, neighbor, route, transmit};

#[derive(Debug)]
struct Refuse;
impl transmit::Sender for Refuse {
    fn send(&self, _: transmit::Frame<'_>) -> Result<transmit::Report, Error> {
        panic!("constructing a client must not transmit")
    }
}
#[test]
fn native_and_application_adapters_compose_without_io() {
    let runtime = Runtime::new(2);
    let client = Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        route::SystemProvider,
        neighbor::SystemResolver::default(),
        Refuse,
        Policy::default(),
    )
    .with_progress_runtime(runtime.clone());
    assert_eq!(client.progress_runtime().capacity(), 2);
    assert_eq!(runtime.snapshot().active, 0);
    assert!(!packetcraftr_netio::resources::native_snapshot().supported);
}
