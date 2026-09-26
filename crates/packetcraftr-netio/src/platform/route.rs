// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Route lookup and interface enumeration backends: route netlink on Linux,
//! routing sockets on macOS, and IP Helper on Windows.
//!
//! The helpers below are shared by exactly the backends named on each one.
//! They stay beside those backends because only a target gate says which
//! ones use them; platform-neutral normalization lives in
//! `crate::route::normalize`.

#[cfg(target_os = "macos")]
pub(in crate::platform) mod af_route;
#[cfg(windows)]
pub(in crate::platform) mod iphelper;
#[cfg(target_os = "linux")]
pub(in crate::platform) mod netlink;

#[cfg(any(target_os = "macos", target_os = "windows", test))]
use std::net::IpAddr;

use crate::{
    interface::{self, Id as InterfaceId},
    route::SystemError,
};

/// Wraps a native failure as the operating-system route diagnostic.
///
/// Windows keeps its own because it also renders the Win32 status code.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn os_error(
    operation: &'static str,
    error: impl std::error::Error + Send + Sync + 'static,
) -> SystemError {
    SystemError::OperatingSystem {
        operation,
        message: "the operating system refused the request".to_owned(),
        source: Some(std::sync::Arc::new(error)),
    }
}

/// The route failure for a full native worker pool.
fn refused(exhausted: crate::workers::Exhausted) -> SystemError {
    SystemError::OperatingSystem {
        operation: "reserve native worker",
        message: format!("native worker capacity {} is exhausted", exhausted.capacity),
        source: Some(std::sync::Arc::new(exhausted)),
    }
}

/// Runs a route backend's synchronous native calls on the worker pool. The
/// caller waits at most until its deadline; calls still running then finish
/// on their pooled thread, which keeps its slot, reported as retained
/// cleanup, until they return. `query` receives what the deadline allows.
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn on_worker<T: Send + 'static>(
    deadline: &packetcraftr_core::budget::Deadline,
    operation: &'static str,
    query: impl FnOnce(&packetcraftr_core::budget::Deadline) -> Result<T, SystemError> + Send + 'static,
) -> Result<T, SystemError> {
    use crate::workers::{Class, Waited};

    let detached = crate::deadline::detach(deadline)
        .map_err(|interrupted| SystemError::interrupted(interrupted, operation))?;
    let permit = crate::workers::shared()
        .admit(Class::Native)
        .map_err(refused)?;
    let task =
        permit
            .spawn(move || query(&detached))
            .map_err(|error| SystemError::OperatingSystem {
                operation: "start native route worker",
                message: "the operating system refused the request".to_owned(),
                source: Some(std::sync::Arc::new(error)),
            })?;
    drop(permit);
    match task.wait(deadline) {
        Waited::Finished(Ok(result)) => result,
        Waited::Finished(Err(_)) => Err(SystemError::InvalidResponse {
            message: "native route worker panicked".to_owned(),
        }),
        Waited::Pending(task) => {
            task.retention_marker().mark_retained();
            Err(match deadline.check_cancelled() {
                Err(cancelled) => cancelled.into(),
                Ok(()) => SystemError::DeadlineExceeded { operation },
            })
        }
    }
}

/// Finds the enumerated interface with the requested name and index,
/// reporting a mismatch when only one of them still matches.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn find_interface(
    interfaces: &[interface::Info],
    requested: &InterfaceId,
) -> Result<interface::Info, SystemError> {
    if let Some(interface) = interfaces
        .iter()
        .find(|interface| interface.id == *requested)
    {
        return Ok(interface.clone());
    }
    if let Some(actual) = interfaces.iter().find(|interface| {
        interface.id.name == requested.name || interface.id.index == requested.index
    }) {
        return Err(SystemError::InterfaceMismatch {
            requested: requested.name.clone(),
            requested_index: requested.index,
            actual: actual.id.name.clone(),
            actual_index: actual.id.index,
        });
    }
    Err(SystemError::InterfaceNotFound {
        name: requested.name.clone(),
        index: requested.index,
    })
}

/// An interface a native route query may be pinned to.
#[cfg(any(target_os = "macos", target_os = "windows", test))]
trait InterfaceCandidate: Clone {
    fn interface(&self) -> &interface::Info;
}

#[cfg(any(target_os = "macos", target_os = "windows", test))]
impl InterfaceCandidate for interface::Info {
    fn interface(&self) -> &interface::Info {
        self
    }
}

/// Pins the query to the interface owning `preferred_source`, refusing a
/// `requested` interface that does not own it. Without a preferred source the
/// request passes through unchanged.
#[cfg(any(target_os = "macos", target_os = "windows", test))]
fn constrain_by_preferred_source<T: InterfaceCandidate>(
    available: &[T],
    interface_hint: Option<&InterfaceId>,
    requested: Option<T>,
    preferred_source: Option<IpAddr>,
) -> Result<Option<T>, SystemError> {
    let Some(source) = preferred_source else {
        return Ok(requested);
    };
    let owns_source = |candidate: &T| {
        candidate
            .interface()
            .addresses
            .iter()
            .any(|assigned| assigned.address == source)
    };
    if let Some(requested) = requested {
        if owns_source(&requested) {
            return Ok(Some(requested));
        }
        return Err(SystemError::SourceUnavailable {
            preferred_source: source,
            interface: requested.interface().id.name.clone(),
        });
    }
    available
        .iter()
        .find(|candidate| owns_source(candidate))
        .cloned()
        .map(Some)
        .ok_or_else(|| SystemError::SourceUnavailable {
            preferred_source: source,
            interface: interface_hint
                .map_or_else(|| "any interface".to_owned(), |hint| hint.name.clone()),
        })
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use packetcraftr_core::frame::LinkType;

    use super::*;
    use crate::link::Capability;
    use packetcraftr_core::packet::MacAddress;

    fn interface() -> interface::Info {
        interface::Info {
            id: InterfaceId {
                name: "fixture0".to_owned(),
                index: 7,
            },
            description: Some("fixture interface".to_owned()),
            mac_address: Some(MacAddress([0x02, 0, 0, 0, 0, 1])),
            addresses: vec![
                interface::Address {
                    address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    prefix_length: 8,
                },
                interface::Address {
                    address: IpAddr::V6(Ipv6Addr::LOCALHOST),
                    prefix_length: 128,
                },
            ],
            flags: interface::Flags::default(),
            mtu: Some(1_500),
            capability: Capability::Layer2AndLayer3,
            link_type: LinkType::ETHERNET,
        }
    }

    #[test]
    fn explicit_interface_owns_source_even_when_another_owner_is_enumerated_first() {
        let first = interface();
        let mut selected = first.clone();
        selected.id.name = "fixture1".to_owned();
        selected.id.index = 8;
        let source = first.addresses[0].address;
        for available in [
            vec![first.clone(), selected.clone()],
            vec![selected.clone(), first],
        ] {
            let actual = constrain_by_preferred_source(
                &available,
                Some(&selected.id),
                Some(selected.clone()),
                Some(source),
            )
            .unwrap()
            .unwrap();
            assert_eq!(actual.id, selected.id);
        }
        selected.addresses.clear();
        assert!(
            constrain_by_preferred_source(
                &[interface()],
                Some(&selected.id),
                Some(selected.clone()),
                Some(source)
            )
            .is_err()
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn interface_lookup_requires_the_complete_stable_identity() {
        let available = interface();
        assert_eq!(
            find_interface(std::slice::from_ref(&available), &available.id)
                .expect("exact identity"),
            available
        );

        for requested in [
            InterfaceId {
                name: "fixture0".to_owned(),
                index: 8,
            },
            InterfaceId {
                name: "other0".to_owned(),
                index: 7,
            },
        ] {
            assert!(matches!(
                find_interface(std::slice::from_ref(&available), &requested),
                Err(SystemError::InterfaceMismatch { .. })
            ));
        }
        assert!(matches!(
            find_interface(
                std::slice::from_ref(&available),
                &InterfaceId {
                    name: "missing0".to_owned(),
                    index: 99,
                }
            ),
            Err(SystemError::InterfaceNotFound { .. })
        ));
    }
}

#[cfg(all(test, any(target_os = "macos", target_os = "windows")))]
mod pooled_tests {
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use packetcraftr_core::budget::{Cancellation, Deadline};
    use packetcraftr_core::error::Classified as _;

    use super::*;

    #[test]
    fn a_pooled_route_query_ends_at_the_callers_deadline() {
        let (release, blocked) = mpsc::channel::<()>();
        let started = Instant::now();
        let result = on_worker(
            &Deadline::new(Duration::from_millis(50)),
            "testing a stalled route query",
            move |_| {
                let _ = blocked.recv_timeout(Duration::from_secs(10));
                Ok(())
            },
        );
        match result {
            Err(error @ SystemError::DeadlineExceeded { .. }) => {
                assert_eq!(error.classification().code, "io.deadline_exceeded");
            }
            other => panic!("a stalled query must report the caller's deadline: {other:?}"),
        }
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(release);
    }

    #[test]
    fn a_pooled_route_query_stops_for_a_cancelled_caller_and_returns_answers() {
        let signal = Cancellation::default();
        signal.cancel();
        let cancelled = Deadline::new(Duration::from_secs(5)).with_cancellation(Some(signal));
        assert!(matches!(
            on_worker(&cancelled, "testing", |_| Ok(())),
            Err(SystemError::Cancelled(_))
        ));
        let answer = on_worker(
            &Deadline::new(Duration::from_secs(5)),
            "testing",
            |deadline| Ok(deadline.limit() <= Duration::from_secs(5)),
        );
        assert!(matches!(answer, Ok(true)));
    }
}
