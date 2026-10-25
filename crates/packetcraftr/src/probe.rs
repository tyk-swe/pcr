// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod limits;
mod model;
mod reply;
pub(crate) mod runner;

pub use model::{Endpoint, Stage, Status, Transport};
pub use reply::Reply;
pub(crate) use runner::{Batch, Evidence};

pub(crate) use limits::{check_collection_evidence, check_probe_count, check_probe_duration};

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use packetcraftr_core::budget::Deadline;

use crate::evidence::retention::EvidenceDiagnosticDescriptor;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Workflow {
    Scan,
    Traceroute,
    Os,
}

impl Workflow {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Scan => "scan",
            Self::Traceroute => "traceroute",
            Self::Os => "os",
        }
    }

    pub(crate) const fn evidence_diagnostics(self) -> EvidenceDiagnosticDescriptor {
        match self {
            Self::Scan => EvidenceDiagnosticDescriptor::new(
                "scan.evidence_limit",
                "scan.undecoded_limit",
                "scan.unattributed_limit",
                "scan",
            ),
            Self::Traceroute => EvidenceDiagnosticDescriptor::new(
                "traceroute.evidence_limit",
                "traceroute.undecoded_limit",
                "traceroute.unattributed_limit",
                "traceroute",
            ),
            Self::Os => EvidenceDiagnosticDescriptor::new(
                "os.evidence_limit",
                "os.undecoded_limit",
                "os.unattributed_limit",
                "os",
            ),
        }
    }

    const fn batch_noun(self) -> &'static str {
        match self {
            Self::Scan => "batch",
            Self::Traceroute => "hop batch",
            Self::Os => "probe batch",
        }
    }

    pub(crate) fn describe_evidence(self, source: &crate::evidence::Error) -> String {
        source.describe(self.batch_noun(), self.as_str())
    }
}

pub(crate) fn enforce_deadline<E>(
    errors: fn(u64, crate::error::Failure) -> E,
    deadline: &Deadline,
) -> Result<(), E> {
    deadline
        .enforce()
        .map_err(|interrupted| (errors)(0_u64, crate::error::Failure::Interrupted(interrupted)))
}

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
