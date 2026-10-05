// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core::budget::{Cancellation, Deadline, Interrupted};
use packetcraftr_netio::deadline::detach;

#[test]
fn detaching_cancel_inherited_no_local_signal() {
    let signal = Cancellation::default();
    let parent = Deadline::new(Duration::from_secs(60)).with_cancellation(Some(signal.clone()));
    let child = Deadline::new(Duration::from_secs(30)).with_parent(Some(Arc::new(parent)));
    let detached = detach(&child).unwrap();
    assert!(detached.check_cancelled().is_ok());
    signal.cancel();
    assert!(child.check_cancelled().is_err());
    assert!(matches!(detached.enforce(), Err(Interrupted::Cancelled(_))));
}
