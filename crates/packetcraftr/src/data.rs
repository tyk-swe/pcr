// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Runtime dataset bytes and test-only inventory of shipped data.

pub(crate) const OS_FINGERPRINTS: &[u8] = include_bytes!("../data/os-fingerprints.v1.json");
pub(crate) const PORT_CATALOG: &[u8] = include_bytes!("../data/port-catalog.json");
pub(crate) const SERVICE_EXCLUSIONS: &[u8] = include_bytes!("../data/service-exclusions.json");
pub(crate) const SERVICE_PROBES: &[u8] = include_bytes!("../data/service-probes.json");
pub(crate) const UDP_PAYLOADS: &[u8] = include_bytes!("../data/udp-payloads.json");

#[cfg(test)]
mod tests {
    use super::*;
    use packetcraftr_core::document::{
        os_fingerprints, port_catalog, service_exclusions, service_probes, udp_profiles,
    };
    use serde::Deserialize;
    use std::{collections::BTreeSet, path::Path};

    struct Dataset {
        name: &'static str,
        bytes: &'static [u8],
        schema: Option<&'static str>,
        provenance: Option<&'static str>,
    }

    const ALL: &[Dataset] = &[
        Dataset {
            name: "os-fingerprints.v1.json",
            bytes: OS_FINGERPRINTS,
            schema: Some("packetcraftr.os-fingerprints.v1.schema.json"),
            provenance: Some("os-fingerprints.provenance.yaml"),
        },
        Dataset {
            name: "port-catalog.json",
            bytes: PORT_CATALOG,
            schema: None,
            provenance: Some("port-catalog.provenance.yaml"),
        },
        Dataset {
            name: "service-exclusions.json",
            bytes: SERVICE_EXCLUSIONS,
            schema: Some("packetcraftr.service-exclusions.v1.schema.json"),
            provenance: Some("service-exclusions.provenance.yaml"),
        },
        Dataset {
            name: "service-probes.json",
            bytes: SERVICE_PROBES,
            schema: Some("packetcraftr.service-probes.v1.schema.json"),
            provenance: Some("service-probes.provenance.yaml"),
        },
        Dataset {
            name: "service-probes.training.v1.json",
            bytes: include_bytes!("../data/service-probes.training.v1.json"),
            schema: None,
            provenance: Some("service-probes.provenance.yaml"),
        },
        Dataset {
            name: "udp-payloads.json",
            bytes: UDP_PAYLOADS,
            schema: Some("packetcraftr.udp-profiles.v1.schema.json"),
            provenance: Some("udp-payloads.provenance.yaml"),
        },
    ];

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Training {
        fixture_version: u32,
        corpus: String,
        corpus_version: String,
        source: String,
        fixtures: Vec<TrainingFixture>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct TrainingFixture {
        id: String,
        rule: String,
        probe: String,
        response: String,
        product: String,
        #[serde(deserialize_with = "Deserialize::deserialize")]
        version: Option<String>,
        #[serde(deserialize_with = "Deserialize::deserialize")]
        hostname: Option<String>,
    }

    fn validate_training(
        bytes: &[u8],
        corpus: &service_probes::Corpus,
    ) -> Result<(), &'static str> {
        let training: Training =
            serde_json::from_slice(bytes).map_err(|_| "invalid training JSON or structure")?;
        if training.fixture_version != 1 {
            return Err("unsupported fixture version");
        }
        if training.corpus != corpus.name || training.corpus_version != corpus.version {
            return Err("corpus name or version mismatch");
        }
        if training.source.trim().is_empty() || training.fixtures.is_empty() {
            return Err("source and fixtures must be nonempty");
        }
        let mut ids = BTreeSet::new();
        for fixture in &training.fixtures {
            if fixture.id.trim().is_empty() || !ids.insert(&fixture.id) {
                return Err("fixture IDs must be nonempty and unique");
            }
            let probe = corpus
                .probes
                .iter()
                .find(|probe| probe.id == fixture.probe)
                .ok_or("unknown probe")?;
            let rule = corpus
                .matches
                .iter()
                .find(|rule| rule.id == fixture.rule)
                .ok_or("unknown rule")?;
            if rule.probe != probe.id {
                return Err("rule belongs to another probe");
            }
            let observation = service_probes::observe(probe, fixture.response.as_bytes(), false);
            let identification = corpus.identify(probe, &observation);
            if identification.outcome != service_probes::MatchOutcome::Matched
                || !identification.candidates.iter().any(|candidate| {
                    candidate.provenance.rule == fixture.rule
                        && candidate.product == fixture.product
                        && candidate.version == fixture.version
                        && candidate.hostname.as_ref().map(|value| &value.value)
                            == fixture.hostname.as_ref()
                })
            {
                return Err("response does not produce expected claim");
            }
        }
        Ok(())
    }

    #[test]
    fn datasets_parse_with_existing_companions() {
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
            match dataset.name {
                "os-fingerprints.v1.json" => {
                    os_fingerprints::parse(dataset.bytes).expect("os fingerprints parse");
                }
                "port-catalog.json" => {
                    port_catalog::parse(dataset.bytes).expect("port catalog parses");
                }
                "service-exclusions.json" => {
                    service_exclusions::parse(dataset.bytes).expect("service exclusions parse");
                }
                "service-probes.json" => {
                    service_probes::parse(dataset.bytes).expect("service probes parse");
                }
                "service-probes.training.v1.json" => {
                    let corpus =
                        service_probes::parse(SERVICE_PROBES).expect("service probes parse");
                    validate_training(dataset.bytes, &corpus).expect("training fixtures validate");
                }
                "udp-payloads.json" => {
                    udp_profiles::parse(dataset.bytes).expect("udp payloads parse");
                }
                name => panic!("no parser for {name}"),
            }
        }
    }

    #[test]
    fn training_rejects_invalid_documents_and_claims() {
        let corpus = service_probes::parse(SERVICE_PROBES).expect("service probes parse");
        let bytes = include_bytes!("../data/service-probes.training.v1.json");
        assert!(validate_training(bytes, &corpus).is_ok());
        assert_eq!(
            validate_training(b"{", &corpus),
            Err("invalid training JSON or structure")
        );
        let original: serde_json::Value = serde_json::from_slice(bytes).expect("valid fixture");
        for (path, value, error) in [
            (
                "fixture_version",
                serde_json::json!(2),
                "unsupported fixture version",
            ),
            (
                "corpus",
                serde_json::json!("other"),
                "corpus name or version mismatch",
            ),
            (
                "corpus_version",
                serde_json::json!("other"),
                "corpus name or version mismatch",
            ),
            (
                "source",
                serde_json::json!(""),
                "source and fixtures must be nonempty",
            ),
            (
                "fixtures",
                serde_json::json!([]),
                "source and fixtures must be nonempty",
            ),
            (
                "fixtures",
                serde_json::json!({}),
                "invalid training JSON or structure",
            ),
        ] {
            let mut document = original.clone();
            document[path] = value;
            assert_eq!(
                validate_training(&serde_json::to_vec(&document).unwrap(), &corpus),
                Err(error),
                "{path}"
            );
        }
        for (field, value, error) in [
            ("probe", serde_json::json!("missing"), "unknown probe"),
            ("rule", serde_json::json!("missing"), "unknown rule"),
            (
                "probe",
                serde_json::json!("ftp-greeting"),
                "rule belongs to another probe",
            ),
            (
                "response",
                serde_json::json!("invalid"),
                "response does not produce expected claim",
            ),
            (
                "product",
                serde_json::json!("wrong"),
                "response does not produce expected claim",
            ),
            (
                "version",
                serde_json::json!("wrong"),
                "response does not produce expected claim",
            ),
            (
                "hostname",
                serde_json::json!(null),
                "response does not produce expected claim",
            ),
        ] {
            let mut document = original.clone();
            document["fixtures"][0][field] = value;
            assert_eq!(
                validate_training(&serde_json::to_vec(&document).unwrap(), &corpus),
                Err(error),
                "{field}"
            );
        }
        let mut duplicate = original.clone();
        duplicate["fixtures"][1]["id"] = duplicate["fixtures"][0]["id"].clone();
        assert_eq!(
            validate_training(&serde_json::to_vec(&duplicate).unwrap(), &corpus),
            Err("fixture IDs must be nonempty and unique")
        );
        let mut missing = original;
        missing["fixtures"][0]
            .as_object_mut()
            .unwrap()
            .remove("hostname");
        assert_eq!(
            validate_training(&serde_json::to_vec(&missing).unwrap(), &corpus),
            Err("invalid training JSON or structure")
        );
    }

    #[test]
    fn data_files_have_table_entries() {
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
