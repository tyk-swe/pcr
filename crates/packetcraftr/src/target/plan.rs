// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use packetcraftr_core::budget::Cancelled;
use packetcraftr_core::error::{BoundaryError, Classification, Classified, Coordinate, Kind};

use super::{
    DeclaredTargets, Family, FamilyGate, SelectedAddress, Selection, SelectionError, Specification,
    Target, admit_selection, wire_limits,
};
use crate::Client;
use crate::clock::Clock;
use crate::providers::TargetProviders;

#[derive(Clone, Debug, Serialize)]
pub struct SelectedAddressRecord {
    #[serde(flatten)]
    pub selected: SelectedAddress,
    pub declarations: Vec<u32>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub declared: String,
    pub targets: Vec<SelectedAddressRecord>,
    pub resolution_performed: bool,
    pub duplicates: Vec<u32>,
}

impl Report {
    pub fn resolved_addresses(&self) -> Vec<IpAddr> {
        self.targets
            .iter()
            .map(|target| target.selected.address)
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct Request {
    pub selection: Selection,
    pub family: Family,
    pub max_targets: usize,
    pub max_duration: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Cancelled(#[from] Cancelled),
    #[error("target selection failed")]
    TargetSelection(#[from] SelectionError),
    #[error("invalid target-plan limit {field}={value}: {reason}")]
    InvalidLimit {
        field: &'static str,
        value: u64,
        reason: String,
    },
    #[error("target plan authorization failed")]
    Authorization(#[source] BoundaryError),
    #[error("resolved targets have no {family} address selected for this plan")]
    Family { family: &'static str },
    #[error("target plan duration {actual:?} exceeds the configured limit of {limit:?}")]
    DurationLimit { actual: Duration, limit: Duration },
}

crate::deadline::deadline_error_conversions!(Error);

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Cancelled(source) => source.classification(),
            Self::TargetSelection(source) => source.classification(),
            Self::Authorization(source) => source.classification(),
            Self::InvalidLimit { .. } => Classification::new(
                "cli.scan_limit",
                Kind::Usage,
                Some("use finite non-zero target, duration, and budget limits"),
            ),
            Self::Family { .. } => Classification::new(
                "packet.target_address_family",
                Kind::Packet,
                Some("select an address family returned by the authorized target resolution"),
            ),
            Self::DurationLimit { .. } => Classification::new(
                "policy.scan_duration_limit",
                Kind::Policy,
                Some("reduce declarations or deliberately raise the finite duration limit"),
            ),
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Authorization(source) => source.as_causes(),
            _ => packetcraftr_core::error::source_chain(self),
        }
    }

    fn context(&self) -> Option<Coordinate> {
        match self {
            Self::Authorization(source) => source.context(),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct SelectionPlan;

impl crate::execution::Errors for SelectionPlan {
    type Error = Error;
    type Step = u64;

    fn invalid_limit(&self, field: &'static str, value: u64, reason: String) -> Error {
        Error::InvalidLimit {
            field,
            value,
            reason,
        }
    }

    fn authorization(&self, source: BoundaryError) -> Error {
        Error::Authorization(source)
    }

    fn duration_limit(
        &self,
        _step: u64,
        source: packetcraftr_core::budget::DeadlineExceeded,
    ) -> Error {
        source.into()
    }

    fn interrupted(&self, _step: u64, source: packetcraftr_core::budget::Interrupted) -> Error {
        source.into()
    }

    fn clock(&self, _step: u64, _source: Box<dyn std::error::Error + Send + Sync>) -> Error {
        BoundaryError::internal_execution(
            "target planning never waits on a clock",
            "internal.target_plan",
            "report the unexpected selection path",
        )
        .into()
    }

    fn execution(&self, _step: u64, source: BoundaryError) -> Error {
        Error::Authorization(source)
    }

    fn invalid_evidence(&self, _step: u64, _source: crate::evidence::Error) -> Error {
        BoundaryError::internal_execution(
            "target planning produces no evidence",
            "internal.target_plan",
            "report the unexpected selection path",
        )
        .into()
    }

    fn stats_overflow(&self, _step: u64, _source: crate::StatsOverflow) -> Error {
        BoundaryError::internal_execution(
            "target planning accumulates no statistics",
            "internal.target_plan",
            "report the unexpected selection path",
        )
        .into()
    }
}

impl From<BoundaryError> for Error {
    fn from(source: BoundaryError) -> Self {
        Self::Authorization(source)
    }
}

impl<P: TargetProviders, K: Clock> Client<P, K> {
    pub fn plan_targets(&self, request: Request) -> Result<Report, Error> {
        request.selection.validate().map_err(Error::from)?;
        if !(1..=super::selection::MAX_CANDIDATES).contains(&request.max_targets) {
            return Err(Error::InvalidLimit {
                field: "max_targets",
                value: request.max_targets as u64,
                reason: format!("must be in 1..={}", super::selection::MAX_CANDIDATES),
            });
        }
        if request.max_duration.is_zero()
            || request.max_duration > packetcraftr_netio::deadline::MAX_WAIT
        {
            return Err(Error::InvalidLimit {
                field: "max_duration",
                value: 0,
                reason: format!(
                    "must be finite and at most {:?}",
                    packetcraftr_netio::deadline::MAX_WAIT
                ),
            });
        }
        let deadline = self.deadline(request.max_duration);
        let mut admission = self.admission();
        let (selected, ()) = admit_selection(
            &mut admission,
            &deadline,
            &SelectionPlan,
            DeclaredTargets {
                selection: &request.selection,
                family: FamilyGate::new(request.family, |family| Error::Family {
                    family: family.label(),
                }),
                max_targets: request.max_targets,
            },
            Error::TargetSelection,
            |_| Ok(()),
            |_| Ok(wire_limits(0, 0)),
        )?;
        let resolution_performed = declares_hostname(&request.selection);
        Ok(Report {
            declared: selected.declared,
            targets: selected
                .targets
                .into_iter()
                .zip(selected.declarations)
                .map(|(selected, declarations)| SelectedAddressRecord {
                    selected,
                    declarations,
                })
                .collect(),
            resolution_performed,
            duplicates: selected.duplicates,
        })
    }
}

fn declares_hostname(selection: &Selection) -> bool {
    let mut seen = HashSet::new();
    selection
        .include
        .iter()
        .filter(|specification| seen.insert(*specification))
        .any(|specification| matches!(specification, Specification::Target(Target::Hostname(_))))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use packetcraftr_netio::interface::Id as InterfaceId;

    use super::*;
    use crate::policy::Policy;
    use crate::target::Family;
    use crate::test_support::{Call, ZoneMapResolver, fake_client};

    fn selection(targets: &[&str], excludes: &[&str]) -> Selection {
        Selection {
            include: targets
                .iter()
                .map(|target| target.parse().expect("fixture specification"))
                .collect(),
            exclude: excludes
                .iter()
                .map(|network| network.parse().expect("fixture network"))
                .collect(),
        }
    }

    fn request(selection: Selection) -> Request {
        Request {
            selection,
            family: Family::Any,
            max_targets: 16,
            max_duration: Duration::from_secs(5),
        }
    }

    fn error_chain(error: &Error) -> String {
        let mut chain = error.to_string();
        let mut source = std::error::Error::source(error);
        while let Some(cause) = source {
            chain.push_str(&format!(": {cause}"));
            source = std::error::Error::source(cause);
        }
        chain
    }

    fn addr(text: &str) -> IpAddr {
        text.parse().expect("fixture address")
    }

    fn addresses(report: &Report) -> Vec<IpAddr> {
        report
            .targets
            .iter()
            .map(|target| target.selected.address)
            .collect()
    }

    #[test]
    fn numeric_plan_lists_targets_with_origins_and_zero_provider_calls() {
        let (client, providers) = fake_client();
        let report = client
            .plan_targets(request(selection(
                &["192.0.2.1", "10.0.0.0/30", "192.0.2.1"],
                &[],
            )))
            .expect("numeric plan");

        assert_eq!(
            addresses(&report),
            [
                addr("192.0.2.1"),
                addr("10.0.0.0"),
                addr("10.0.0.1"),
                addr("10.0.0.2"),
                addr("10.0.0.3"),
            ]
        );
        assert_eq!(report.targets[0].declarations, [0, 2]);
        assert_eq!(report.targets[1].declarations, [1]);
        assert_eq!(report.duplicates, [2]);
        assert!(!report.resolution_performed);
        assert!(
            providers.calls().is_empty(),
            "numeric planning made provider calls: {:?}",
            providers.calls()
        );
    }

    #[test]
    fn exclusions_and_family_narrowing_apply_to_the_plan() {
        let (client, providers) = fake_client();
        let mut request = request(selection(
            &["192.0.2.0/29", "2001:db8::1"],
            &["192.0.2.1", "192.0.2.7"],
        ));
        request.family = Family::Ipv4;
        let report = client.plan_targets(request).expect("narrowed plan");
        assert_eq!(
            addresses(&report),
            [
                addr("192.0.2.0"),
                addr("192.0.2.2"),
                addr("192.0.2.3"),
                addr("192.0.2.4"),
                addr("192.0.2.5"),
                addr("192.0.2.6"),
            ]
        );
        assert!(providers.calls().is_empty());
    }

    #[test]
    fn family_filter_that_removes_everything_fails_the_gate() {
        let (client, _) = fake_client();
        let mut request = request(selection(&["2001:db8::1"], &[]));
        request.family = Family::Ipv4;
        let error = client
            .plan_targets(request)
            .expect_err("empty family selection");
        assert!(matches!(error, Error::Family { .. }));
    }

    #[test]
    fn hostname_plan_reports_resolution_and_resolved_targets() {
        let (_, providers) = fake_client();
        let providers = crate::test_support::FakeProviders {
            routes: providers.routes.clone(),
            calls: providers.calls.clone(),
            addresses: vec![
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            ],
        };
        let policy = Policy {
            allow_hostname_resolution: true,
            ..Policy::default()
        };
        let client = crate::Client::new(
            packetcraftr_core::protocol::builtin::registry(),
            policy,
            providers.clone(),
        );
        let mut request = request(selection(&["documentation.invalid"], &[]));
        request.family = Family::Ipv4;
        let report = client.plan_targets(request).expect("hostname plan");

        assert!(report.resolution_performed);
        assert_eq!(addresses(&report), [addr("192.0.2.7")]);
        assert!(matches!(
            providers.calls().as_slice(),
            [Call::Resolve(host)] if host == "documentation.invalid"
        ));
    }

    #[test]
    fn dns_denied_before_the_resolver_is_called() {
        let (client, providers) = fake_client();
        let error = client
            .plan_targets(request(selection(&["documentation.invalid"], &[])))
            .expect_err("hostname resolution is not opted in");
        assert!(
            !providers
                .calls()
                .iter()
                .any(|call| matches!(call, Call::Resolve(_))),
            "{:?}",
            providers.calls()
        );
        drop(error);
    }

    #[test]
    fn a_denied_dns_answer_fails_policy_before_family_filtering() {
        let providers = crate::test_support::FakeProviders {
            addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))],
            ..crate::test_support::FakeProviders::default()
        };
        let policy = Policy {
            allow_hostname_resolution: true,
            allowed_destinations: vec!["10.0.0.0/8".parse().expect("allowlist")],
            ..Policy::default()
        };
        let client = crate::Client::new(
            packetcraftr_core::protocol::builtin::registry(),
            policy,
            providers.clone(),
        );
        let mut request = request(selection(&["documentation.invalid"], &[]));
        request.family = Family::Ipv6;
        let error = client
            .plan_targets(request)
            .expect_err("the denied answer fails before family filtering");
        assert!(
            matches!(error, Error::Authorization(_)),
            "expected authorization error, got {error:?}"
        );
    }

    #[test]
    fn oversized_candidate_expansion_fails_before_any_resolution() {
        let (client, providers) = fake_client();
        let error = client
            .plan_targets(request(selection(&["0.0.0.0/7"], &[])))
            .expect_err("an oversized expansion is rejected");
        assert!(
            matches!(
                error,
                Error::TargetSelection(SelectionError::Limit {
                    field: "target_candidates",
                    ..
                }) | Error::InvalidLimit { .. }
            ),
            "{error:?}"
        );
        assert!(providers.calls().is_empty());
    }

    #[test]
    fn max_targets_bounds_the_plan() {
        let (client, _) = fake_client();
        let mut request = request(selection(&["192.0.2.0/29"], &[]));
        request.max_targets = 2;
        let error = client
            .plan_targets(request)
            .expect_err("max_targets bounds the selection");
        assert!(matches!(
            error,
            Error::TargetSelection(SelectionError::Limit {
                field: "max_targets",
                ..
            })
        ));
    }

    #[test]
    fn invalid_plan_limits_are_rejected() {
        let (client, _) = fake_client();
        for max_targets in [0usize, super::super::selection::MAX_CANDIDATES + 1] {
            let mut request = request(selection(&["192.0.2.1"], &[]));
            request.max_targets = max_targets;
            assert!(matches!(
                client.plan_targets(request),
                Err(Error::InvalidLimit {
                    field: "max_targets",
                    ..
                })
            ));
        }
        let mut request = request(selection(&["192.0.2.1"], &[]));
        request.max_duration = Duration::ZERO;
        assert!(matches!(
            client.plan_targets(request),
            Err(Error::InvalidLimit {
                field: "max_duration",
                ..
            })
        ));
    }

    #[test]
    fn scoped_targets_resolve_zones_and_dedup_aliases() {
        let (client, providers) = fake_client();
        let report = client
            .plan_targets(request(selection(
                &["fe80::1%fixture0", "fe80::1%1", "fe80::2%fixture0"],
                &[],
            )))
            .expect("scoped plan");

        assert_eq!(addresses(&report), [addr("fe80::1"), addr("fe80::2"),]);
        let first = &report.targets[0];
        assert_eq!(first.declarations, [0, 1], "aliases merge their origins");
        let scope = first.selected.scope.as_ref().expect("scope");
        assert_eq!(scope.interface.index, 1);
        assert_eq!(scope.zone.as_str(), "fixture0");
        assert!(
            providers
                .calls()
                .iter()
                .any(|call| matches!(call, Call::Interfaces))
        );
    }

    #[test]
    fn different_zones_stay_distinct() {
        let resolver = ZoneMapResolver::new(vec![
            InterfaceId {
                name: "alpha".to_owned(),
                index: 2,
            },
            InterfaceId {
                name: "beta".to_owned(),
                index: 3,
            },
        ]);
        let providers = crate::providers::ProviderSet::<(), (), (), (), (), _> {
            route: (),
            interface: (),
            capture: (),
            transmit: (),
            tcp: (),
            resolver,
        };
        let client = crate::Client::new(
            packetcraftr_core::protocol::builtin::registry(),
            Policy::default(),
            providers,
        );
        let report = client
            .plan_targets(request(selection(&["fe80::1%alpha", "fe80::1%beta"], &[])))
            .expect("two interfaces keep two selected targets");

        assert_eq!(report.targets.len(), 2);
        let zones: Vec<u32> = report
            .targets
            .iter()
            .map(|target| target.selected.scope.as_ref().unwrap().interface.index)
            .collect();
        assert_eq!(zones, [2, 3]);
    }

    #[test]
    fn unknown_and_ambiguous_zones_fail_before_work() {
        let resolver = ZoneMapResolver::new(vec![
            InterfaceId {
                name: "dup".to_owned(),
                index: 2,
            },
            InterfaceId {
                name: "dup".to_owned(),
                index: 3,
            },
        ]);
        let providers = crate::providers::ProviderSet::<(), (), (), (), (), _> {
            route: (),
            interface: (),
            capture: (),
            transmit: (),
            tcp: (),
            resolver,
        };
        let client = crate::Client::new(
            packetcraftr_core::protocol::builtin::registry(),
            Policy::default(),
            providers,
        );
        let ambiguous = client
            .plan_targets(request(selection(&["fe80::1%dup"], &[])))
            .expect_err("ambiguous zone");
        assert!(
            matches!(ambiguous, Error::Authorization(_)),
            "{ambiguous:?}"
        );
        let unknown = client
            .plan_targets(request(selection(&["fe80::1%missing"], &[])))
            .expect_err("unknown zone");
        assert!(matches!(unknown, Error::Authorization(_)), "{unknown:?}");
    }

    #[test]
    fn a_denied_scoped_destination_fails_before_zone_enumeration() {
        let resolver = ZoneMapResolver::new(vec![InterfaceId {
            name: "fixture0".to_owned(),
            index: 1,
        }]);
        let calls = Arc::clone(&resolver.calls);
        let providers = crate::providers::ProviderSet::<(), (), (), (), (), _> {
            route: (),
            interface: (),
            capture: (),
            transmit: (),
            tcp: (),
            resolver,
        };
        let policy = Policy {
            allowed_destinations: vec!["10.0.0.0/8".parse().expect("allowlist")],
            ..Policy::default()
        };
        let client = crate::Client::new(
            packetcraftr_core::protocol::builtin::registry(),
            policy,
            providers,
        );
        let error = client
            .plan_targets(request(selection(&["fe80::1%fixture0"], &[])))
            .expect_err("denied destination");
        assert!(matches!(error, Error::Authorization(_)));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "zone lookup ran for a denied address"
        );
    }

    #[test]
    fn link_local_without_scope_is_rejected_before_work() {
        let (client, providers) = fake_client();
        let selection = Selection {
            include: vec![Specification::Target(Target::Address(IpAddr::V6(
                "fe80::1".parse().expect("link-local"),
            )))],
            exclude: Vec::new(),
        };
        let error = client
            .plan_targets(request(selection))
            .expect_err("unscoped link-local");
        assert!(matches!(error, Error::Authorization(_)));
        assert!(providers.calls().is_empty());
    }

    #[test]
    fn an_exact_duplicate_hostname_resolves_only_once() {
        let resolver = crate::test_support::ScriptedResolver::new(vec![
            vec![addr("192.0.2.10")],
            vec![addr("198.51.100.99")],
        ]);
        let resolve_calls = resolver.calls.clone();
        let providers = crate::providers::ProviderSet::<(), (), (), (), (), _> {
            route: (),
            interface: (),
            capture: (),
            transmit: (),
            tcp: (),
            resolver,
        };
        let client = crate::Client::new(
            packetcraftr_core::protocol::builtin::registry(),
            Policy {
                allow_hostname_resolution: true,
                ..Policy::default()
            },
            providers,
        );
        let report = client
            .plan_targets(request(selection(
                &["documentation.invalid", "documentation.invalid"],
                &[],
            )))
            .expect("duplicate hostname plan");

        assert_eq!(addresses(&report), [addr("192.0.2.10")]);
        assert_eq!(report.targets[0].declarations, [0, 1]);
        assert_eq!(report.duplicates, [1]);
        assert_eq!(
            resolve_calls.load(Ordering::SeqCst),
            1,
            "a repeated specification never re-resolves"
        );
    }

    #[test]
    fn a_repeated_scoped_target_enumerates_its_zone_once() {
        let resolver = ZoneMapResolver::new(vec![InterfaceId {
            name: "fixture0".to_owned(),
            index: 1,
        }]);
        let zone_calls = resolver.calls.clone();
        let providers = crate::providers::ProviderSet::<(), (), (), (), (), _> {
            route: (),
            interface: (),
            capture: (),
            transmit: (),
            tcp: (),
            resolver,
        };
        let client = crate::Client::new(
            packetcraftr_core::protocol::builtin::registry(),
            Policy::default(),
            providers,
        );
        let report = client
            .plan_targets(request(selection(
                &["fe80::1%fixture0", "fe80::1%fixture0"],
                &[],
            )))
            .expect("repeated scoped plan");

        assert_eq!(report.targets.len(), 1);
        assert_eq!(report.targets[0].declarations, [0, 1]);
        assert_eq!(report.duplicates, [1]);
        assert_eq!(zone_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn overlapping_numeric_and_network_declarations_link_once_per_spec() {
        let (client, _) = fake_client();
        let report = client
            .plan_targets(request(selection(
                &["192.0.2.1", "192.0.2.0/30", "192.0.2.1"],
                &[],
            )))
            .expect("overlapping plan");

        assert_eq!(addresses(&report)[0], addr("192.0.2.1"));
        assert_eq!(report.targets[0].declarations, [0, 1, 2]);
        assert_eq!(report.duplicates, [2]);
    }

    #[test]
    fn a_repeated_large_network_keeps_origin_links_bounded() {
        let (client, providers) = fake_client();
        let mut request = request(selection(&["10.0.0.0/16", "10.0.0.0/16"], &[]));
        request.max_targets = 100_000;
        let error = client
            .plan_targets(request)
            .expect_err("origin links above the candidate bound");

        assert!(matches!(
            error,
            Error::TargetSelection(SelectionError::Limit {
                field: "target_origins",
                limit: 100_000
            })
        ));
        assert!(providers.calls().is_empty());
    }

    #[test]
    fn a_numeric_zone_matches_by_index_only() {
        let resolver = ZoneMapResolver::new(vec![InterfaceId {
            name: "7".to_owned(),
            index: 9,
        }]);
        let zone_calls = resolver.calls.clone();
        let providers = crate::providers::ProviderSet::<(), (), (), (), (), _> {
            route: (),
            interface: (),
            capture: (),
            transmit: (),
            tcp: (),
            resolver,
        };
        let client = crate::Client::new(
            packetcraftr_core::protocol::builtin::registry(),
            Policy::default(),
            providers,
        );
        let error = client
            .plan_targets(request(selection(&["fe80::1%7"], &[])))
            .expect_err("a numeric zone never resolves by name");

        assert!(error_chain(&error).contains("did not resolve"), "{error}");
        assert_eq!(zone_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn overlapping_large_networks_link_origins_without_reexpansion() {
        let (client, providers) = fake_client();
        let mut request = request(selection(&["10.0.0.0/16", "10.0.0.0/17"], &[]));
        request.max_targets = 65_536;
        let report = client.plan_targets(request).expect("overlapping CIDR plan");

        assert_eq!(report.targets.len(), 65_536);
        assert_eq!(report.targets[0].declarations, [0, 1]);
        assert_eq!(report.targets[32_767].declarations, [0, 1]);
        assert_eq!(report.targets[32_768].declarations, [0]);
        assert_eq!(report.targets[65_535].declarations, [0]);
        assert!(report.duplicates.is_empty());
        assert!(providers.calls().is_empty());
    }

    #[test]
    fn a_resolved_interface_with_zero_index_or_empty_name_is_rejected() {
        for (target, interface) in [
            (
                "fe80::1%fixture0",
                InterfaceId {
                    name: "fixture0".to_owned(),
                    index: 0,
                },
            ),
            (
                "fe80::1%4",
                InterfaceId {
                    name: String::new(),
                    index: 4,
                },
            ),
        ] {
            let resolver = ZoneMapResolver::new(vec![interface]);
            let providers = crate::providers::ProviderSet::<(), (), (), (), (), _> {
                route: (),
                interface: (),
                capture: (),
                transmit: (),
                tcp: (),
                resolver,
            };
            let client = crate::Client::new(
                packetcraftr_core::protocol::builtin::registry(),
                Policy::default(),
                providers,
            );
            let error = client
                .plan_targets(request(selection(&[target], &[])))
                .expect_err("invalid resolved interface identity");
            assert!(
                error_chain(&error).contains("invalid interface identity"),
                "{error}"
            );
        }
    }
}
