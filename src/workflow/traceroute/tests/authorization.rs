use std::collections::VecDeque;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::result::Result;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use super::super::*;
use super::support::{
    CountingRejectExecutor, NoopClock, UndecodedExecutor, udp_traceroute_request,
};
use crate::client::policy::Policy as TrafficPolicy;
use crate::client::target::{Error as TargetResolutionError, Resolver as HostnameResolver};
use crate::protocol::builtin::registry as default_registry;
use crate::workflow::target::Authorized;
use crate::workflow::target_adapter::PolicyAuthorizer;

fn private_traceroute_policy() -> TrafficPolicy {
    TrafficPolicy {
        max_packets_per_operation: 1_000,
        max_bytes_per_operation: 1_000_000,
        ..TrafficPolicy::default()
    }
}

struct AddressListAuthorizer {
    addresses: Vec<IpAddr>,
}

impl Authorizer for AddressListAuthorizer {
    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
        Ok(Authorized {
            declared: target.to_string(),
            addresses: self.addresses.clone(),
        })
    }

    fn authorize_operation(
        &mut self,
        _packets: u64,
        _maximum_wire_bytes: u64,
    ) -> Result<(), BoundaryError> {
        Ok(())
    }
}

struct ScriptedResolver {
    calls: Arc<AtomicUsize>,
    answers: Mutex<VecDeque<Vec<IpAddr>>>,
}

impl ScriptedResolver {
    fn new(answers: impl IntoIterator<Item = Vec<IpAddr>>) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            answers: Mutex::new(answers.into_iter().collect()),
        }
    }
}

impl HostnameResolver for ScriptedResolver {
    fn resolve(
        &self,
        _hostname: &crate::client::target::Hostname,
        _limit: usize,
    ) -> Result<Vec<IpAddr>, TargetResolutionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .answers
            .lock()
            .unwrap()
            .pop_front()
            .expect("scripted resolver answer"))
    }
}

#[test]
fn duplicate_resolved_addresses_preserve_first_seen_order_after_family_filtering() {
    let first = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let second = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10));
    let excluded = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let mut operation = udp_traceroute_request(Target::Hostname("ordered.example".to_owned()));
    operation.address_family = AddressFamily::Ipv4;
    operation.max_hops = 1;
    operation.probes_per_hop = 1;
    let result = traceroute(
        &operation,
        &mut AddressListAuthorizer {
            addresses: vec![excluded, first, first, second, first, excluded],
        },
        &default_registry().unwrap(),
        &mut UndecodedExecutor,
        &mut NoopClock::default(),
    )
    .unwrap();

    assert_eq!(result.resolved_addresses, vec![first, second]);
    assert_eq!(result.destination, first);
}

#[test]
fn hostname_policy_precedes_dns_and_every_answer_precedes_probe_execution() {
    let registry = default_registry().unwrap();
    let private = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));

    let resolver = ScriptedResolver::new([vec![private]]);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut executor = CountingRejectExecutor(Arc::clone(&calls));
    let policy = private_traceroute_policy();
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);
    let error = traceroute(
        &udp_traceroute_request(Target::Hostname("lab.example".to_owned())),
        &mut authorizer,
        &registry,
        &mut executor,
        &mut NoopClock::default(),
    )
    .unwrap_err();
    assert_eq!(error.classification().code, "policy.hostname_resolution");
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let resolver = ScriptedResolver::new([vec![private, "8.8.8.8".parse().unwrap()]]);
    let mut policy = private_traceroute_policy();
    policy.allow_hostname_resolution = true;
    let mut operation = udp_traceroute_request(Target::Hostname("mixed.example".to_owned()));
    operation.address_family = AddressFamily::Ipv6;
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);
    let error = traceroute(
        &operation,
        &mut authorizer,
        &registry,
        &mut executor,
        &mut NoopClock::default(),
    )
    .unwrap_err();
    assert_eq!(error.classification().code, "policy.public_destination");
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn rerun_reauthorizes_rebound_hostname_before_another_probe() {
    let private = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let resolver =
        ScriptedResolver::new([vec![private], vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]]);
    let mut policy = private_traceroute_policy();
    policy.allow_hostname_resolution = true;
    let registry = default_registry().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut executor = CountingRejectExecutor(Arc::clone(&calls));
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);
    let operation = udp_traceroute_request(Target::Hostname("changing.example".to_owned()));

    assert!(matches!(
        traceroute(
            &operation,
            &mut authorizer,
            &registry,
            &mut executor,
            &mut NoopClock::default(),
        ),
        Err(TracerouteError::Execution { .. })
    ));
    assert!(matches!(
        traceroute(
            &operation,
            &mut authorizer,
            &registry,
            &mut executor,
            &mut NoopClock::default(),
        ),
        Err(TracerouteError::Authorization(_))
    ));
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
