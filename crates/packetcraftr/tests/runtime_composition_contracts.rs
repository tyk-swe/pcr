// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use common::{FixedRoutes, NeverTransmit};
use packetcraftr::{
    Client,
    policy::Policy,
    progress::{Runtime, Worker},
};

fn client() -> Client<common::FakeProviders<FixedRoutes, NeverTransmit>> {
    Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        Policy::default(),
        common::providers(FixedRoutes, NeverTransmit),
    )
}

#[test]
fn clients_share_only_the_runtime_selected_by_the_embedder() {
    let runtime = Runtime::new(1);
    let first = client().with_runtime(runtime.clone());
    let second = client().with_runtime(runtime.clone());
    let isolated = client();
    let worker = Worker::<()>::new_in(first.runtime(), |_| Ok(())).unwrap();
    assert!(Worker::<()>::new_in(second.runtime(), |_| Ok(())).is_err());
    assert_eq!(runtime.snapshot().active, 1);
    assert_eq!(second.runtime().snapshot().rejected_admissions, 1);
    let independent = Worker::<()>::new_in(isolated.runtime(), |_| Ok(())).unwrap();
    assert_eq!(isolated.runtime().snapshot().rejected_admissions, 0);
    drop(first);
    assert_eq!(second.runtime().snapshot().active, 1);
    drop(worker);
    drop(independent);
}
