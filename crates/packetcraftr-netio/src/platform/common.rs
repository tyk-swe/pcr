// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native plumbing that more than one capability's backend shares.
//!
//! Each submodule belongs to one backend and holds only what that backend's
//! capabilities have in common: the route-netlink connection worker, the
//! Darwin socket-address parsers, the Npcap library, and libpcap's open
//! handling. `pcap_api` holds the pcap API rules libpcap and Npcap share. The
//! functions below are the route and interface backends' shared failure and
//! worker-pool handling; interface enumeration reports `route::Error` as the
//! native source its capability wraps.

#[cfg(all(native_route, target_os = "macos"))]
pub(in crate::platform) mod af_route;
#[cfg(pcap_backend)]
pub(in crate::platform) mod libpcap;
#[cfg(all(native_route, target_os = "linux"))]
pub(in crate::platform) mod netlink;
#[cfg(npcap_backend)]
pub(in crate::platform) mod npcap;
#[cfg(native_layer2)]
pub(in crate::platform) mod pcap_api;

#[cfg(native_route)]
use packetcraftr_core::error::Source;

#[cfg(native_route)]
use crate::route;

/// Wraps a native failure as the operating-system route diagnostic.
///
/// Windows keeps its own because it also renders the Win32 status code.
#[cfg(all(native_route, any(target_os = "linux", target_os = "macos")))]
pub(in crate::platform) fn os_error(
    operation: &'static str,
    error: impl std::error::Error + Send + Sync + 'static,
) -> route::Error {
    route::Error::OperatingSystem {
        operation,
        message: "the operating system refused the request".to_owned(),
        source: Some(Source::new(error)),
    }
}

/// The route failure for a full native worker pool.
#[cfg(native_route)]
pub(in crate::platform) fn refused(exhausted: crate::workers::Exhausted) -> route::Error {
    route::Error::OperatingSystem {
        operation: "reserve native worker",
        message: format!("native worker capacity {} is exhausted", exhausted.capacity),
        source: Some(Source::new(exhausted)),
    }
}

/// Runs a route or interface backend's synchronous native calls on the
/// worker pool. The
/// caller waits at most until its deadline; calls still running then finish
/// on their pooled thread, which keeps its slot, reported as retained
/// cleanup, until they return. `query` receives what the deadline allows.
#[cfg(all(native_route, any(target_os = "macos", target_os = "windows")))]
pub(in crate::platform) fn on_worker<T: Send + 'static>(
    deadline: &packetcraftr_core::budget::Deadline,
    operation: &'static str,
    query: impl FnOnce(&packetcraftr_core::budget::Deadline) -> Result<T, route::Error> + Send + 'static,
) -> Result<T, route::Error> {
    use crate::workers::{Class, Waited};

    let detached = crate::deadline::detach(deadline)
        .map_err(|interrupted| route::Error::interrupted(interrupted, operation))?;
    let permit = crate::workers::shared()
        .admit(Class::Native)
        .map_err(refused)?;
    let task =
        permit
            .spawn(move || query(&detached))
            .map_err(|error| route::Error::OperatingSystem {
                operation: "start native route worker",
                message: "the operating system refused the request".to_owned(),
                source: Some(Source::new(error)),
            })?;
    drop(permit);
    match task.wait(deadline) {
        Waited::Finished(Ok(result)) => result,
        Waited::Finished(Err(_)) => Err(route::Error::InvalidResponse {
            message: "native route worker panicked".to_owned(),
        }),
        Waited::Pending(task) => {
            task.retention_marker().mark_retained();
            Err(match deadline.check_cancelled() {
                Err(cancelled) => cancelled.into(),
                Ok(()) => route::Error::DeadlineExceeded { operation },
            })
        }
    }
}

#[cfg(all(test, native_route, any(target_os = "macos", target_os = "windows")))]
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
            Err(error @ route::Error::DeadlineExceeded { .. }) => {
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
            Err(route::Error::Cancelled(_))
        ));
        let answer = on_worker(
            &Deadline::new(Duration::from_secs(5)),
            "testing",
            |deadline| Ok(deadline.limit() <= Duration::from_secs(5)),
        );
        assert!(matches!(answer, Ok(true)));
    }
}
