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
        Transport::Sctp | Transport::Icmp | Transport::Ip => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_catalog_entries_resolve_by_port_name_and_hint() {
        let catalog = bundled();
        assert!(!catalog.entries.is_empty());
        for entry in &catalog.entries {
            assert_eq!(catalog.entry(entry.transport, entry.port), Some(entry));
            assert_eq!(
                catalog
                    .named(entry.transport, &entry.name)
                    .map(|named| named.port),
                Some(entry.port)
            );
        }
        let tcp = catalog
            .entries
            .iter()
            .find(|entry| entry.transport == CatalogTransport::Tcp)
            .expect("bundled catalog names at least one TCP port");
        assert_eq!(hint(Transport::Tcp, tcp.port), Some(tcp.name.as_str()));
        assert_eq!(hint(Transport::Icmp, tcp.port), None);
    }

    #[test]
    fn bundled_catalog_presets_only_name_catalog_entries() {
        let catalog = bundled();
        for preset in &catalog.presets {
            assert_eq!(catalog.preset(&preset.name), Some(preset));
            for (transport, name) in preset.members() {
                assert!(catalog.named(transport, name).is_some(), "{name}");
            }
        }
    }

    #[test]
    fn data_set_publishes_the_bundled_catalog_identity() {
        let published = data_set();
        assert_eq!(published.name, bundled().name);
        assert_eq!(published.version, bundled().version);
    }
}
