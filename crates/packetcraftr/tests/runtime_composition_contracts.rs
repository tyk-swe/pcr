// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod support;

use packetcraftr::{
    Client,
    policy::Policy,
    progress::{Runtime, Sink},
};
use support::{FixedRoutes, NeverNeighbors, NeverTransmit};

fn client() -> Client<FixedRoutes, NeverNeighbors, NeverTransmit> {
    Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        FixedRoutes,
        NeverNeighbors,
        NeverTransmit,
        Policy::default(),
    )
}

#[test]
fn clients_share_only_the_runtime_selected_by_the_embedder() {
    let runtime = Runtime::new(1);
    let first = client().with_progress_runtime(runtime.clone());
    let second = client().with_progress_runtime(runtime.clone());
    let isolated = client();
    let sink = Sink::<()>::new_in(first.progress_runtime(), |_| Ok(())).unwrap();
    assert!(Sink::<()>::new_in(second.progress_runtime(), |_| Ok(())).is_err());
    assert_eq!(runtime.snapshot().active, 1);
    assert_eq!(second.progress_runtime().snapshot().rejected_admissions, 1);
    let independent = Sink::<()>::new_in(isolated.progress_runtime(), |_| Ok(())).unwrap();
    assert_eq!(
        isolated.progress_runtime().snapshot().rejected_admissions,
        0
    );
    drop(first);
    assert_eq!(second.progress_runtime().snapshot().active, 1);
    drop(sink);
    drop(independent);
}
