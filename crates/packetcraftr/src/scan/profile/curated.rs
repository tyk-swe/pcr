// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The bundled, curated UDP payloads: project-authored requests for a bounded
//! set of ports, built from the same profile blocks an operator document
//! uses. A matched response check is a configured check that matched, not
//! service identification.

use std::collections::{BTreeMap, btree_map::Entry};
use std::sync::{Arc, LazyLock};

use packetcraftr_core::document::udp_profiles;

use super::UdpProfile;
use crate::probe::ProbeEndpoint;
use crate::scan::DataSet;

/// Matches `dataset.version` in `data/udp-payloads.provenance.yaml`; any
/// change to the payload document bumps both.
pub const CURATED_UDP_PAYLOADS_VERSION: &str = "1.0.0";

const DATA_SET: DataSet = DataSet {
    name: "udp-payloads",
    version: CURATED_UDP_PAYLOADS_VERSION,
};

static BUNDLED: LazyLock<BTreeMap<u16, Arc<UdpProfile>>> = LazyLock::new(|| {
    let assignments = udp_profiles::parse(include_bytes!("../../../data/udp-payloads.json"))
        .expect("bundled UDP payloads are a valid profile document");
    super::compile(assignments).expect("bundled UDP payloads compile")
});

/// The curated profile for each covered UDP port.
pub fn bundled() -> &'static BTreeMap<u16, Arc<UdpProfile>> {
    &BUNDLED
}

pub const fn data_set() -> DataSet {
    DATA_SET
}

/// Operator profiles combined with the curated payloads for the planned UDP
/// endpoints.
#[derive(Clone, Debug, Default)]
pub struct Merged {
    pub profiles: BTreeMap<u16, Arc<UdpProfile>>,
    /// Planned UDP ports that carry a curated payload.
    pub applied: Vec<u16>,
    /// Planned UDP ports where an operator profile replaced the curated one.
    pub overridden: Vec<u16>,
}

/// An operator profile always wins over the curated payload for its port;
/// each such port is reported in `overridden` so the replacement is visible.
pub fn merge(operator: BTreeMap<u16, Arc<UdpProfile>>, endpoints: &[ProbeEndpoint]) -> Merged {
    let mut merged = Merged {
        profiles: operator,
        ..Merged::default()
    };
    for endpoint in endpoints {
        let ProbeEndpoint::Udp { port } = *endpoint else {
            continue;
        };
        let Some(curated) = BUNDLED.get(&port) else {
            continue;
        };
        match merged.profiles.entry(port) {
            Entry::Occupied(_) => merged.overridden.push(port),
            Entry::Vacant(vacant) => {
                vacant.insert(Arc::clone(curated));
                merged.applied.push(port);
            }
        }
    }
    merged.applied.sort_unstable();
    merged.overridden.sort_unstable();
    merged
}

#[cfg(test)]
mod tests;
