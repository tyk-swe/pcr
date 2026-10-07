// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The bundled port catalog: port-name hints and curated presets.
//!
//! Provenance: `crates/packetcraftr/data/port-catalog.provenance.yaml`. Names
//! are hints attached to port numbers, never service identification, and
//! presets are curated lists with no frequency claim.

use std::sync::LazyLock;

use packetcraftr_core::document::port_catalog::{self, Transport as CatalogTransport};
pub use packetcraftr_core::document::port_catalog::{Catalog, Entry, Preset};

use super::DataSet;
use crate::probe::Transport;

static BUNDLED: LazyLock<Catalog> = LazyLock::new(|| {
    port_catalog::parse(include_bytes!("../../data/port-catalog.json"))
        .expect("the bundled port catalog is validated by its unit tests")
});

/// The catalog compiled into this build.
pub fn bundled() -> &'static Catalog {
    &BUNDLED
}

/// The data set identity results publish when they use the bundled catalog.
pub fn data_set() -> DataSet {
    let catalog = bundled();
    DataSet {
        name: &catalog.name,
        version: &catalog.version,
    }
}

/// The bundled hint for a port endpoint; ICMP has no ports to name.
pub fn hint(transport: Transport, port: u16) -> Option<&'static str> {
    let transport = catalog_transport(transport)?;
    bundled()
        .entry(transport, port)
        .map(|entry| entry.name.as_str())
}

pub(crate) const fn catalog_transport(transport: Transport) -> Option<CatalogTransport> {
    match transport {
        Transport::Tcp => Some(CatalogTransport::Tcp),
        Transport::Udp => Some(CatalogTransport::Udp),
        Transport::Icmp => None,
    }
}

#[cfg(test)]
mod tests;
