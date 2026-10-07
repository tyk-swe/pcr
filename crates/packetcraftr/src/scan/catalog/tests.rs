// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

const MANIFEST: &str = include_str!("../../../data/port-catalog.provenance.yaml");

#[test]
fn bundled_catalog_is_valid_and_matches_its_provenance_record() {
    let catalog = bundled();
    let DataSet { name, version } = data_set();
    assert!(
        MANIFEST.contains(&format!("  name: \"{name}\"\n")),
        "{name}"
    );
    assert!(
        MANIFEST.contains(&format!("  version: \"{version}\"\n")),
        "{version}"
    );
    assert!(MANIFEST.contains("  kind: \"port\"\n"));
    assert!(MANIFEST.contains("  review_outcome: \"accepted\"\n"));
    let all = catalog.preset("all").expect("the catalog-wide preset");
    assert_eq!(all.members().count(), catalog.entries.len());
    for entry in &catalog.entries {
        assert!(entry.reference.starts_with("RFC "), "{}", entry.name);
    }
}

#[test]
fn hints_are_keyed_by_transport_and_absent_for_icmp() {
    assert_eq!(hint(Transport::Tcp, 22), Some("ssh"));
    assert_eq!(hint(Transport::Udp, 22), None);
    assert_eq!(hint(Transport::Udp, 123), Some("ntp"));
    assert_eq!(hint(Transport::Tcp, 123), None);
    assert_eq!(hint(Transport::Icmp, 0), None);
}
