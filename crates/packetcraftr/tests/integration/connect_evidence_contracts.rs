// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use packetcraftr::policy::Policy;
use packetcraftr::scan::{self, connect};
use packetcraftr::target::{self, Family, Hostname, Resolver, Target, Zone};
use packetcraftr::{Client, ProviderSet};
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::BoundaryError;
use packetcraftr_netio::interface;

use crate::common::ScriptedTcp;

struct ScopedResolver;

impl Resolver for ScopedResolver {
    fn resolve(&self, _: &Hostname, _: usize) -> Result<Vec<IpAddr>, target::Error> {
        panic!("the fixture uses a literal address")
    }

    fn resolve_zone(&self, zone: &Zone, _: &Deadline) -> Result<interface::Id, target::Error> {
        Ok(interface::Id {
            name: zone.as_str().to_owned(),
            index: 1,
        })
    }
}

#[test]
fn scoped_evidence_is_charged_before_publication() {
    let zone = "z".repeat(128);
    let target: Target = format!("fe80::1%{zone}").parse().unwrap();
    let cost =
        std::mem::size_of::<connect::ProbeEvidence>() + 2 * zone.len() + "fixture refusal".len();
    let client = Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        Policy::default(),
        ProviderSet::tcp(ScriptedTcp::default(), ScopedResolver),
    );
    for (attempts, budget, expected_published) in [
        (1, cost - 1, 0),
        (1, cost, 1),
        (2, 2 * cost - 1, 1),
        (2, 2 * cost, 2),
    ] {
        let request = scan::Request {
            target_sources: Vec::new(),
            targets: target.clone().into(),
            udp_payload: bytes::Bytes::new(),
            udp_profiles: Default::default(),
            address_family: Family::Any,
            endpoints: vec![packetcraftr::probe::ProbeEndpoint::Tcp { port: 443 }],
            attempts,
            timeout: Duration::from_secs(5),
            probes_per_second: None,
            max_in_flight: 1,
            limits: scan::Limits {
                max_evidence_bytes: budget,
                ..Default::default()
            },
            route: Default::default(),
            collection: Default::default(),
        };
        let published = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&published);
        let result = client.scan_connect(
            request,
            move |_: connect::Event| -> Result<(), BoundaryError> {
                observed.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );
        assert_eq!(published.load(Ordering::SeqCst), expected_published);
        if expected_published == attempts as usize {
            let report = result.expect("the exact budget admits all evidence");
            assert_eq!(report.stats.retained_evidence_bytes, budget);
            assert_eq!(report.stats.connections_scheduled, u64::from(attempts));
        } else {
            assert!(matches!(
                result,
                Err(scan::Error::InvalidLimit {
                    field: "max_evidence_bytes",
                    value,
                    ..
                }) if value == budget as u64
            ));
        }
    }
}
