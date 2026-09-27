// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core::budget::{Cancellation, Deadline, Interrupted};
use packetcraftr_netio::{deadline::detach, tcp};

#[test]
fn detaching_preserves_cancellation_inherited_without_a_local_signal() {
    let signal = Cancellation::default();
    let parent = Deadline::new(Duration::from_secs(60)).with_cancellation(Some(signal.clone()));
    let child = Deadline::new(Duration::from_secs(30)).with_parent(Some(Arc::new(parent)));
    let detached = detach(&child).unwrap();
    assert!(detached.check_cancelled().is_ok());
    signal.cancel();
    assert!(child.check_cancelled().is_err());
    assert!(matches!(detached.enforce(), Err(Interrupted::Cancelled(_))));
}

#[test]
fn repeated_detachment_preserves_every_parent_and_local_signal() {
    for cancelled in 0..4 {
        let signals: [Cancellation; 4] = Default::default();
        let deadline = |index: usize| {
            Deadline::new(Duration::from_secs(60)).with_cancellation(Some(signals[index].clone()))
        };
        let ancestor = Arc::new(deadline(0));
        let parent = Arc::new(deadline(1).with_parent(Some(ancestor)));
        let sibling = Arc::new(deadline(2));
        let child = deadline(3)
            .with_parent(Some(parent))
            .with_parent(Some(sibling));
        let detached = detach(&child).unwrap();
        let detached_again = detach(&detached).unwrap();
        signals[cancelled].cancel();
        assert!(child.check_cancelled().is_err());
        assert!(detached.check_cancelled().is_err(), "signal {cancelled}");
        assert!(
            detached_again.check_cancelled().is_err(),
            "signal {cancelled}"
        );
        for (index, signal) in signals.iter().enumerate() {
            assert_eq!(signal.is_cancelled(), index == cancelled);
        }
    }
}

#[test]
fn tcp_workers_observe_parent_cancellation_after_dispatch() {
    struct CancelParent(Cancellation);

    impl tcp::Provider for CancelParent {
        type Stream = tcp::SystemStream;

        fn connect(&self, _: SocketAddr, deadline: &Deadline) -> Result<Self::Stream, tcp::Error> {
            self.0.cancel();
            deadline.check_cancelled()?;
            Err(io::Error::from(io::ErrorKind::ConnectionRefused).into())
        }
    }

    let signal = Cancellation::default();
    let parent = Deadline::new(Duration::from_secs(5)).with_cancellation(Some(signal.clone()));
    let child = Deadline::new(Duration::from_secs(1)).with_parent(Some(Arc::new(parent)));
    let mut pending = tcp::start_connect(
        Arc::new(CancelParent(signal)),
        "127.0.0.1:9".parse().unwrap(),
        &child,
    )
    .unwrap();
    let outcome = pending
        .wait(&Deadline::new(Duration::from_secs(1)))
        .unwrap()
        .expect("the provider completes immediately");
    assert!(outcome.attempted);
    assert!(matches!(outcome.result, Err(tcp::Error::Cancelled(_))));
}
