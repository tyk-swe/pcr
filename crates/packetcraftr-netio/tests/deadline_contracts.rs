// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core::budget::{Cancellation, Deadline, Interrupted};
use packetcraftr_netio::deadline::detach;

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
