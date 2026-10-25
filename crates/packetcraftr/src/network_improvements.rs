// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    clock::{Clock, SystemClock},
    route,
    target::{Error as TargetError, Hostname, Resolver, Target},
};
use packetcraftr_core::{
    budget::{Cancellation, Deadline},
    frame::LinkType,
    packet::Packet,
};
use packetcraftr_netio::{
    interface,
    link::{Capability, Mode},
    route::{Decision, Scope, SelectionReason},
};
use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

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
fn info(id: interface::Id) -> interface::Info {
    interface::Info {
        id,
        description: None,
        mac_address: None,
        addresses: vec![],
        flags: Default::default(),
        mtu: Some(1500),
        capability: Capability::Layer3,
        link_type: LinkType::RAW,
    }
}
struct Routes {
    calls: AtomicUsize,
    cancel: Option<Cancellation>,
    invalid: bool,
}
impl packetcraftr_netio::route::Provider for Routes {
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
struct Interfaces {
    values: Vec<interface::Id>,
    cancel: Option<Cancellation>,
}
impl interface::Provider for Interfaces {
    fn interfaces(&self, _: &Deadline) -> Result<Vec<interface::Info>, interface::Error> {
        if let Some(cancel) = &self.cancel {
            cancel.cancel();
        }
        Ok(self.values.iter().cloned().map(info).collect())
    }
}
#[test]
fn network_improvements_absolute_hostname_and_resolver_spelling() {
    struct Recording;
    impl Resolver for Recording {
        fn resolve(&self, host: &Hostname, _: usize) -> Result<Vec<IpAddr>, TargetError> {
            assert_eq!(host.as_str(), "example.test.");
            Ok(vec!["127.0.0.1".parse().unwrap()])
        }
    }
    let absolute: Hostname = "Example.TEST.".parse().unwrap();
    assert_eq!(absolute.to_string(), "example.test.");
    assert_eq!(
        serde_json::to_string(&absolute).unwrap(),
        "\"example.test.\""
    );
    assert_ne!(absolute, "example.test".parse::<Hostname>().unwrap());
    let policy = crate::policy::Policy {
        allow_hostname_resolution: true,
        ..Default::default()
    };
    assert!(
        policy
            .resolve_target(
                &Target::Hostname(absolute),
                &Recording,
                &Deadline::new(Duration::from_secs(1))
            )
            .is_ok()
    );
}
#[test]
fn network_improvements_clock_stops_at_spent_deadline() {
    let start = std::time::Instant::now();
    SystemClock
        .sleep(Duration::from_secs(10), &Deadline::immediate(None))
        .unwrap();
    assert!(start.elapsed() < Duration::from_secs(1));
}
#[test]
fn network_improvements_interface_ambiguity_and_late_enumeration() {
    let selector = route::Interface::Name("test0".into());
    let first = decision().interface;
    let second = interface::Id {
        name: first.name.clone(),
        index: 2,
    };
    let resolve = route::ResolvedInterface::default();
    assert!(matches!(
        resolve.resolve(
            &selector,
            &Interfaces {
                values: vec![first.clone(), second],
                cancel: None
            },
            &Deadline::new(Duration::from_secs(1))
        ),
        Err(route::Error::AmbiguousInterface { .. })
    ));
    let index = route::Interface::Index(std::num::NonZeroU32::new(1).unwrap());
    assert!(matches!(
        resolve.resolve(
            &index,
            &Interfaces {
                values: vec![
                    first.clone(),
                    interface::Id {
                        name: "other".into(),
                        index: 1
                    }
                ],
                cancel: None
            },
            &Deadline::new(Duration::from_secs(1))
        ),
        Err(route::Error::AmbiguousInterface { .. })
    ));
    let cancel = Cancellation::default();
    assert!(matches!(
        resolve.resolve(
            &selector,
            &Interfaces {
                values: vec![first],
                cancel: Some(cancel.clone())
            },
            &Deadline::new(Duration::from_secs(1)).with_cancellation(Some(cancel))
        ),
        Err(route::Error::Interrupted(_))
    ));
}
#[test]
fn network_improvements_route_deadline_cache_and_identity() {
    use packetcraftr_netio::route::Provider;
    let provider = Routes {
        calls: AtomicUsize::new(0),
        cancel: None,
        invalid: false,
    };
    let cached = route::CachedProvider::new(&provider);
    let address = "127.0.0.2".parse().unwrap();
    cached
        .lookup_with_preferences(address, None, None, &Deadline::new(Duration::from_secs(1)))
        .unwrap();
    assert!(matches!(
        cached.lookup_with_preferences(address, None, None, &Deadline::immediate(None)),
        Err(route::Error::Interrupted(_))
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
        Err(route::Error::Interrupted(_))
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
        Err(route::Error::InvalidRouteIdentity { .. })
    ));
    assert!(matches!(
        route::plan(
            &Packet::new(),
            Some(address),
            &options,
            &provider,
            &Deadline::immediate(None)
        ),
        Err(route::Error::Interrupted(_))
    ));
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
}
#[test]
fn network_improvements_numeric_and_custom_resolution_boundaries() {
    struct Late(Cancellation);
    impl Resolver for Late {
        fn resolve(&self, _: &Hostname, _: usize) -> Result<Vec<IpAddr>, TargetError> {
            unreachable!()
        }
        fn resolve_controlled(
            &self,
            _: &Hostname,
            _: usize,
            _: &Deadline,
        ) -> Result<Vec<IpAddr>, TargetError> {
            self.0.cancel();
            Ok(vec!["127.0.0.1".parse().unwrap()])
        }
    }
    let policy = crate::policy::Policy {
        allow_hostname_resolution: true,
        ..Default::default()
    };
    let cancel = Cancellation::default();
    let resolver = Late(cancel.clone());
    assert!(matches!(
        policy.resolve_target(
            &"127.0.0.1".parse().unwrap(),
            &resolver,
            &Deadline::immediate(None)
        ),
        Err(crate::policy::ResolutionError::Target(
            TargetError::Control(_)
        ))
    ));
    let parent = Deadline::new(Duration::from_secs(1)).with_cancellation(Some(cancel));
    let deadline = Deadline::new(Duration::from_secs(1)).with_parent(Some(Arc::new(parent)));
    assert!(matches!(
        policy.resolve_target(&"example.test".parse().unwrap(), &resolver, &deadline),
        Err(crate::policy::ResolutionError::Target(
            TargetError::Control(_)
        ))
    ));
}
#[test]
fn network_improvements_distinct_resolver_order_and_limit() {
    let hostname = "test.local".parse().unwrap();
    let a = "127.0.0.1".parse().unwrap();
    let b = "127.0.0.2".parse().unwrap();
    assert_eq!(
        crate::target::distinct_addresses(&hostname, [b, a, b, a], 2).unwrap(),
        [b, a]
    );
    assert!(matches!(
        crate::target::distinct_addresses(&hostname, [b, a, b], 1),
        Err(TargetError::AddressLimit { .. })
    ));
}
