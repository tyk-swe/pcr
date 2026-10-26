// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_core::{
    budget::{Cancellation, Deadline},
    frame::LinkType,
};
use packetcraftr_netio::{
    interface,
    link::Capability,
    route::{Decision, Scope, SelectionReason},
};

use super::{Interface, ResolvedInterface};
use crate::route::Error;

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
fn interface_ambiguity_and_late_enumeration() {
    let selector = Interface::Name("test0".into());
    let first = decision().interface;
    let second = interface::Id {
        name: first.name.clone(),
        index: 2,
    };
    let resolve = ResolvedInterface::default();
    assert!(matches!(
        resolve.resolve(
            &selector,
            &Interfaces {
                values: vec![first.clone(), second],
                cancel: None
            },
            &Deadline::new(Duration::from_secs(1))
        ),
        Err(Error::AmbiguousInterface { .. })
    ));
    let index = Interface::Index(std::num::NonZeroU32::new(1).unwrap());
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
        Err(Error::AmbiguousInterface { .. })
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
        Err(Error::Interrupted(_))
    ));
}
