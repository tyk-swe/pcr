// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Owned blocking hostname lookups. Cancellation stops waiting, while admitted
//! work and its native capacity remain owned until the resolver actually returns.

use crate::{
    resources::NativeSnapshot,
    workers::{self, Pool, Waited},
};
use packetcraftr_core::{
    budget::Deadline,
    error::{BoundaryError, Classification, Kind},
};
use std::{
    net::{IpAddr, ToSocketAddrs},
    sync::{Arc, OnceLock},
};

/// Nested lookup allocation; the process-wide native root must also admit work.
pub const MAX_PENDING_LOOKUPS: usize = 4;
static LOOKUPS: OnceLock<Arc<Pool>> = OnceLock::new();
fn lookups() -> &'static Arc<Pool> {
    LOOKUPS.get_or_init(|| Arc::new(Pool::new(MAX_PENDING_LOOKUPS)))
}

#[must_use]
pub fn snapshot() -> NativeSnapshot {
    lookups().snapshot()
}

fn failure(message: impl Into<String>) -> BoundaryError {
    BoundaryError::new(
        message,
        Classification::new("io.hostname_resolution", Kind::Io, None),
        Vec::new(),
    )
}

fn failure_with_source(
    message: &'static str,
    error: impl std::error::Error + Send + Sync + 'static,
) -> BoundaryError {
    let causes = std::iter::once(error.to_string())
        .chain(packetcraftr_core::error::source_chain(&error))
        .collect();
    BoundaryError::with_source(
        message,
        Classification::new("io.hostname_resolution", Kind::Io, None),
        causes,
        error,
    )
}

/// Adapt an owned synchronous resolver invocation. The closure must own every
/// input it needs; abandoning its result never releases unfinished admission.
/// Both admissions are finite and nonblocking. Replacing cached executor threads
/// may wait under the same effective deadline while actual retirement completes.
pub fn blocking_lookup(
    deadline: &Deadline,
    lookup: impl FnOnce() -> Result<Vec<IpAddr>, BoundaryError> + Send + 'static,
) -> Result<Vec<IpAddr>, BoundaryError> {
    blocking_lookup_on(deadline, lookup, lookups(), workers::shared())
}

pub(crate) fn blocking_lookup_on(
    deadline: &Deadline,
    lookup: impl FnOnce() -> Result<Vec<IpAddr>, BoundaryError> + Send + 'static,
    lookup_pool: &Arc<Pool>,
    root: &Arc<Pool>,
) -> Result<Vec<IpAddr>, BoundaryError> {
    let wait = deadline.detach().map_err(BoundaryError::from_error)?;
    let lookup_permit = lookup_pool
        .admit()
        .map_err(|error| failure_with_source("hostname lookup admission refused", error))?;
    let retained_lookup = lookup_permit.retention_marker();
    let permit = root
        .admit()
        .map_err(|error| failure_with_source("native hostname lookup admission refused", error))?;
    let execution = wait.clone();
    let task = permit
        .spawn_with_control(&wait, move || {
            let result = workers::unwind_after_cleanup(|| {
                execution.enforce().map_err(BoundaryError::from_error)?;
                lookup()
            });
            drop(lookup_permit);
            result
        })
        .map_err(|error| match wait.enforce() {
            Err(interrupted) => BoundaryError::from_error(interrupted),
            Ok(()) => failure_with_source("start hostname lookup failed", error),
        })?;
    match task.wait(&wait) {
        Waited::Finished(Ok(result)) => {
            deadline.enforce().map_err(BoundaryError::from_error)?;
            result
        }
        Waited::Finished(Err(_)) => Err(failure("hostname resolver panicked")),
        Waited::Pending(task) => {
            task.retention_marker().mark_retained();
            retained_lookup.mark_retained();
            drop(task);
            Err(wait
                .enforce()
                .err()
                .map(BoundaryError::from_error)
                .unwrap_or_else(|| failure("hostname lookup did not complete")))
        }
    }
}

/// Preserve the platform's hosts-file/NSS/search-domain and address-order rules.
/// Result retention is bounded; duplicates do not consume the address allocation.
pub fn system(
    hostname: &str,
    limit: usize,
    deadline: &Deadline,
) -> Result<Vec<IpAddr>, BoundaryError> {
    let hostname = hostname.to_owned();
    blocking_lookup(deadline, move || {
        let resolved = (hostname.as_str(), 0).to_socket_addrs().map_err(|error| {
            BoundaryError::with_source(
                "system hostname lookup failed",
                Classification::new("io.hostname_resolution", Kind::Io, None),
                Vec::new(),
                error,
            )
        })?;
        retain_addresses(&hostname, resolved.map(|socket| socket.ip()), limit)
    })
}

fn retain_addresses(
    hostname: &str,
    resolved: impl IntoIterator<Item = IpAddr>,
    limit: usize,
) -> Result<Vec<IpAddr>, BoundaryError> {
    let mut addresses = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for address in resolved {
        if !seen.insert(address) {
            continue;
        }
        if addresses.len() >= limit {
            return Err(BoundaryError::new(
                format!("hostname {hostname} exceeds the {limit}-address limit"),
                Classification::new("io.hostname_address_limit", Kind::Io, None),
                Vec::new(),
            ));
        }
        addresses.push(address);
    }
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_resolver_retains_unique_addresses_in_first_seen_order() {
        let a = "127.0.0.1".parse().unwrap();
        let b = "127.0.0.2".parse().unwrap();
        assert_eq!(
            retain_addresses("test.local", [b, a, b, a], 2).unwrap(),
            [b, a]
        );
        assert!(retain_addresses("test.local", [b, b, a], 1).is_err());
        assert!(retain_addresses("test.local", [a], 0).is_err());
        assert!(retain_addresses("test.local", [], 0).unwrap().is_empty());
    }
}
