// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The embedded datasets compiled into this crate, one row per file under
//! `data/`, naming its bytes, published schema, and provenance record. The
//! matching parsers live in `packetcraftr_core::document`.

// name, schema, and provenance are read by the dataset net test, not production code.
#[allow(dead_code)]
pub(crate) struct Dataset {
    pub name: &'static str,
    pub bytes: &'static [u8],
    pub schema: Option<&'static str>,
    pub provenance: Option<&'static str>,
}

pub(crate) const OS_FINGERPRINTS: Dataset = Dataset {
    name: "os-fingerprints.v1.json",
    bytes: include_bytes!("../data/os-fingerprints.v1.json"),
    schema: Some("packetcraftr.os-fingerprints.v1.schema.json"),
    provenance: Some("os-fingerprints.provenance.yaml"),
};

pub(crate) const PORT_CATALOG: Dataset = Dataset {
    name: "port-catalog.json",
    bytes: include_bytes!("../data/port-catalog.json"),
    schema: None,
    provenance: Some("port-catalog.provenance.yaml"),
};

pub(crate) const SERVICE_EXCLUSIONS: Dataset = Dataset {
    name: "service-exclusions.json",
    bytes: include_bytes!("../data/service-exclusions.json"),
    schema: Some("packetcraftr.service-exclusions.v1.schema.json"),
    provenance: Some("service-exclusions.provenance.yaml"),
};

pub(crate) const SERVICE_PROBES: Dataset = Dataset {
    name: "service-probes.json",
    bytes: include_bytes!("../data/service-probes.json"),
    schema: Some("packetcraftr.service-probes.v1.schema.json"),
    provenance: Some("service-probes.provenance.yaml"),
};

#[allow(dead_code)] // shipped for external training use; parsed only by the dataset net test
pub(crate) const SERVICE_PROBES_TRAINING: Dataset = Dataset {
    name: "service-probes.training.v1.json",
    bytes: include_bytes!("../data/service-probes.training.v1.json"),
    schema: None,
    provenance: Some("service-probes.provenance.yaml"),
};

pub(crate) const UDP_PAYLOADS: Dataset = Dataset {
    name: "udp-payloads.json",
    bytes: include_bytes!("../data/udp-payloads.json"),
    schema: Some("packetcraftr.udp-profiles.v1.schema.json"),
    provenance: Some("udp-payloads.provenance.yaml"),
};

#[allow(dead_code)] // enumerated by the dataset net test
pub(crate) const ALL: &[&Dataset] = &[
    &OS_FINGERPRINTS,
    &PORT_CATALOG,
    &SERVICE_EXCLUSIONS,
    &SERVICE_PROBES,
    &SERVICE_PROBES_TRAINING,
    &UDP_PAYLOADS,
];

#[cfg(test)]
mod tests {
    use super::*;
    use packetcraftr_core::document::{
        os_fingerprints, port_catalog, service_exclusions, service_probes, udp_profiles,
    };
    use std::path::Path;

    #[test]
    fn every_dataset_parses_and_names_existing_companions() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        for dataset in ALL {
            if let Some(schema) = dataset.schema {
                assert!(
                    root.join("../../schemas").join(schema).is_file(),
                    "{} names missing schema {schema}",
                    dataset.name
                );
            }
            if let Some(provenance) = dataset.provenance {
                assert!(
                    root.join("data").join(provenance).is_file(),
                    "{} names missing provenance {provenance}",
                    dataset.name
                );
            }
        }
        os_fingerprints::parse(OS_FINGERPRINTS.bytes).expect("os fingerprints parse");
        port_catalog::parse(PORT_CATALOG.bytes).expect("port catalog parses");
        service_exclusions::parse(SERVICE_EXCLUSIONS.bytes).expect("service exclusions parse");
        service_probes::parse(SERVICE_PROBES.bytes).expect("service probes parse");
        udp_profiles::parse(UDP_PAYLOADS.bytes).expect("udp payloads parse");
    }

    #[test]
    fn every_data_file_has_a_table_row() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut on_disk: Vec<String> = std::fs::read_dir(root.join("data"))
            .expect("data directory reads")
            .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
            .filter(|name| !name.ends_with(".provenance.yaml"))
            .collect();
        on_disk.sort();
        let mut tabled: Vec<&str> = ALL.iter().map(|dataset| dataset.name).collect();
        tabled.sort();
        assert_eq!(on_disk, tabled);
    }
}
