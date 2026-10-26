// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    net::IpAddr,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use packetcraftr_core::{
    budget::{Cancellation, Deadline},
    frame::LinkType,
    packet::Packet,
};
use packetcraftr_netio::{
    interface,
    link::{Capability, Mode},
    route::{Decision, Provider, Scope, SelectionReason},
};

use super::CachedProvider;
use crate::route::{self, Error};

fn decision() -> Decision {
    Decision {
        interface: interface::Id {
            name: "test0".into(),
            index: 1,
        },
        source_mac: None,
        selected_source: Some("127.0.0.1".parse().unwrap()),
        preferred_source: None,
        next_hop: None,
        selection_reason: SelectionReason::Local,
        destination_scope: Scope::Host,
        mtu: 1500,
        capability: Capability::Layer3,
        link_type: LinkType::RAW,
    }
}

struct Routes {
    calls: AtomicUsize,
    cancel: Option<Cancellation>,
    invalid: bool,
}

impl Provider for Routes {
    type Error = packetcraftr_netio::route::Error;

    fn lookup_with_preferences(
        &self,
        _: IpAddr,
        _: Option<&interface::Id>,
        _: Option<IpAddr>,
        _: &Deadline,
    ) -> Result<Decision, Self::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(cancel) = &self.cancel {
            cancel.cancel();
        }
        let mut answer = decision();
        if self.invalid {
            answer.interface.index = 0;
        }
        Ok(answer)
    }
}

#[test]
fn route_deadline_cache_and_identity() {
    let provider = Routes {
        calls: AtomicUsize::new(0),
        cancel: None,
        invalid: false,
    };
    let cached = CachedProvider::new(&provider);
    let address = "127.0.0.2".parse().unwrap();
    cached
        .lookup_with_preferences(address, None, None, &Deadline::new(Duration::from_secs(1)))
        .unwrap();
    assert!(matches!(
        cached.lookup_with_preferences(address, None, None, &Deadline::immediate(None)),
        Err(Error::Interrupted(_))
    ));
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    let cancel = Cancellation::default();
    let late = Routes {
        calls: AtomicUsize::new(0),
        cancel: Some(cancel.clone()),
        invalid: false,
    };
    let options = route::Options {
        link_mode: Mode::Layer3,
        ..Default::default()
    };
    assert!(matches!(
        route::plan(
            &Packet::new(),
            Some(address),
            &options,
            &late,
            &Deadline::new(Duration::from_secs(1)).with_cancellation(Some(cancel))
        ),
        Err(Error::Interrupted(_))
    ));
    let invalid = Routes {
        calls: AtomicUsize::new(0),
        cancel: None,
        invalid: true,
    };
    assert!(matches!(
        route::plan(
            &Packet::new(),
            Some(address),
            &options,
            &invalid,
            &Deadline::new(Duration::from_secs(1))
        ),
        Err(Error::InvalidRouteIdentity { .. })
    ));
    assert!(matches!(
        route::plan(
            &Packet::new(),
            Some(address),
            &options,
            &provider,
            &Deadline::immediate(None)
        ),
        Err(Error::Interrupted(_))
    ));
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
}
