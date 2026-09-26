// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The kernel scan and traceroute share: batches of homogeneous probes run
//! through the execution context, batch-evidence processing, and the probe
//! vocabulary their requests and reports use.

mod limits;
mod model;
pub(crate) mod runner;
#[cfg(test)]
pub(crate) mod test_support;

pub use crate::correlation::Transport;
pub use model::{ProbeEndpoint, ProbeStatus};
pub(crate) use runner::{Batch, Evidence};

pub(crate) use limits::{check_probe_count, check_probe_duration};

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use packetcraftr_core::budget::Deadline;

use crate::execution::evidence::EvidenceDiagnosticDescriptor;
use crate::execution::{Errors, ExchangeEvidenceError};

/// The probe workflows that share this kernel. The tag selects the
/// workflow's evidence diagnostics and the words its evidence errors use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Workflow {
    Scan,
    Traceroute,
}

impl Workflow {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Scan => "scan",
            Self::Traceroute => "traceroute",
        }
    }

    pub(crate) const fn evidence_diagnostics(self) -> EvidenceDiagnosticDescriptor {
        match self {
            Self::Scan => EvidenceDiagnosticDescriptor::new(
                "scan.evidence_limit",
                "scan.undecoded_limit",
                "scan",
            ),
            Self::Traceroute => EvidenceDiagnosticDescriptor::new(
                "traceroute.evidence_limit",
                "traceroute.undecoded_limit",
                "traceroute",
            ),
        }
    }

    /// What one executed batch is called in evidence errors.
    const fn batch_noun(self) -> &'static str {
        match self {
            Self::Scan => "batch",
            Self::Traceroute => "hop batch",
        }
    }

    /// The message this workflow reports for inconsistent executor evidence.
    pub(crate) fn describe_evidence(self, source: &ExchangeEvidenceError) -> String {
        source.describe(self.batch_noun(), self.as_str())
    }
}

/// Fails the workflow when it was cancelled or its finite duration budget is
/// exhausted. Scan and traceroute share this gate; the adapter keeps the code
/// and remediation workflow-specific.
pub(crate) fn enforce_deadline<G: Errors>(errors: &G, deadline: &Deadline) -> Result<(), G::Error> {
    deadline
        .enforce()
        .map_err(|interrupted| errors.interrupted(G::Step::default(), interrupted))
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
