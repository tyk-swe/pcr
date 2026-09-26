// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The kernel scan and traceroute share: batches of homogeneous probes run
//! through the execution context, batch-evidence processing, and the probe
//! vocabulary their requests and reports use.

mod error;
mod limits;
mod model;
pub(crate) mod runner;
#[cfg(test)]
pub(crate) mod test_support;

pub use crate::correlation::Transport;
pub use error::{Error, ErrorKind, Workflow};
pub use model::{ProbeEndpoint, ProbeStatus};
pub use runner::{Batch, Execution};

// The executor contract lives in the private `execution` module. It stays
// reachable here until every workflow runs through the client.
pub use crate::execution::{ExchangeExecutor, Executor, PipelineEvent, PipelineOptions, Request};

pub(crate) use limits::{check_probe_count, check_probe_duration};

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use packetcraftr_core::budget::Deadline;

use crate::target::GateErrors;

/// Fails the workflow when its finite duration budget is exhausted. Scan and
/// traceroute share this gate; the workflow tag keeps the code and remediation
/// workflow-specific.
pub(crate) fn enforce_deadline(workflow: Workflow, deadline: &Deadline) -> Result<(), Error> {
    deadline
        .enforce()
        .map_err(|interrupted| workflow.interrupted(interrupted))
}

/// Returns the live collector entry for `key`, pushing `make()` first when
/// absent. The shared scan/traceroute collector fan-out uses this so neither
/// collector indexes the vector it just pushed to.
pub(crate) fn index_or_push<'a, K, V>(
    values: &'a mut Vec<V>,
    indices: &'a mut HashMap<K, usize>,
    key: K,
    make: impl FnOnce() -> V,
) -> &'a mut V
where
    K: Eq + std::hash::Hash,
{
    let index = match indices.entry(key) {
        Entry::Occupied(entry) => *entry.get(),
        Entry::Vacant(entry) => {
            let index = values.len();
            values.push(make());
            *entry.insert(index)
        }
    };
    values
        .get_mut(index)
        .expect("collector index points at a live entry")
}
