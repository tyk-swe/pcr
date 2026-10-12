// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

use crate::protocol::{
    network::Ipv4,
    transport::{Tcp, TcpOption},
};
use std::io::Read;

#[test]
fn invalid_observed_window_scale_is_inconclusive_and_preserved() {
    let mut observations = observations();
    observations[0].tcp.as_mut().unwrap().window_scale = Some(15);
    assert_eq!(
        evaluate(&corpus(), &observations).unwrap().outcome,
        Outcome::Inconclusive
    );
    observations[0].suitable = false;
    assert_eq!(
        evaluate(&corpus(), &observations).unwrap().outcome,
        Outcome::Inconclusive
    );
    assert_eq!(observations[0].tcp.as_ref().unwrap().window_scale, Some(15));
}

fn observations() -> Vec<Observation> {
    Probe::REQUIRED
        .into_iter()
        .map(|probe| {
            let mut packet = crate::packet::Packet::new();
            packet.push(Ipv4::default());
            packet.push(Tcp {
                flags: if probe == Probe::ClosedSyn {
                    0x14
                } else {
                    0x12
                },
                window: 4096,
                options: if probe == Probe::ClosedSyn {
                    Vec::new()
                } else {
                    vec![TcpOption::Mss(1460)]
                },
                ..Tcp::default()
            });
            extract(probe, &packet).unwrap()
        })
        .collect()
}

fn corpus() -> Corpus {
    Corpus {
        schema: SCHEMA_V1.into(),
        probe_set: PROBE_SET_V1.into(),
        name: "synthetic-tests".into(),
        version: "1.0.0".into(),
        maintainer: "test".into(),
        signatures: vec![Signature {
            id: "synthetic-linux".into(),
            family: Family::Linux,
            address_family: AddressFamily::Ipv4,
            reference: "synthetic fixture, not identification evidence".into(),
            predicates: Probe::REQUIRED
                .into_iter()
                .flat_map(|probe| {
                    [
                        Predicate {
                            probe,
                            test: Test::Flags(if probe == Probe::ClosedSyn {
                                0x14
                            } else {
                                0x12
                            }),
                        },
                        Predicate {
                            probe,
                            test: Test::Window(4096),
                        },
                    ]
                })
                .collect(),
        }],
    }
}

#[test]
fn frozen_independent_linux_kernel_holdout_qualifies_only_suitable_cases() {
    use sha2::{Digest, Sha256};
    let compressed = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/roadmap/evidence/m10/held-out-kernel-7.0.0-34-generic.json.gz"
    ));
    let mut bytes = Vec::new();
    flate2::read::GzDecoder::new(&compressed[..])
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(
        Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        "ff3d2282d46e4fa08e4d7fec167e27d86408ff1dd467b72883800a69c4188b37"
    );
    let held_out: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(held_out["kernel"], "7.0.0-34-generic");
    assert_eq!(held_out["status"], "exercised");
    let corpus = parse(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../packetcraftr/data/os-fingerprints.v1.json"
    )))
    .unwrap();
    let before_evaluation: Corpus = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/roadmap/evidence/m10/signatures-before-evaluation.v1.json"
    )))
    .unwrap();
    assert_eq!(
        corpus, before_evaluation,
        "held-out evidence cannot tune the frozen signatures"
    );
    let mut matched = 0;
    let mut inconclusive = 0;
    for case in held_out["cases"].as_array().unwrap() {
        let terminal = case["records"].as_array().unwrap().last().unwrap();
        let observations: Vec<Observation> =
            serde_json::from_value(terminal["result"]["observations"].clone()).unwrap();
        // Replay exact retained wire bytes rather than trusting stored extraction.
        let decoder = crate::decode::Dissector::new(crate::protocol::builtin::registry());
        let mut replayed = Vec::new();
        for record in case["records"].as_array().unwrap() {
            let events = if case["format"] == "json" {
                record["result"]["evidence"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .collect::<Vec<_>>()
            } else {
                vec![&record["result"]]
            };
            for event in events {
                if event["kind"] != "probe" || event["observation"].is_null() {
                    continue;
                }
                let retained = &event["response"];
                let hex = retained["bytes_hex"].as_str().unwrap();
                let wire: Vec<u8> = (0..hex.len())
                    .step_by(2)
                    .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
                    .collect();
                let frame = crate::frame::Frame::new(
                    std::time::UNIX_EPOCH,
                    crate::frame::LinkType(retained["link_type"].as_u64().unwrap() as u32),
                    wire,
                )
                .unwrap();
                let decoded = decoder
                    .decode(frame, crate::decode::Options::default())
                    .unwrap();
                let probe = serde_json::from_value(event["probe"].clone()).unwrap();
                let observation = extract(probe, &decoded.packet).unwrap();
                assert_eq!(
                    serde_json::to_value(&observation).unwrap(),
                    event["observation"]
                );
                replayed.push(observation);
            }
        }
        assert_eq!(replayed, observations);
        let result = evaluate(&corpus, &replayed).unwrap();
        if case["scenario"] == "suitable" {
            assert_eq!(
                result.outcome,
                Outcome::Matched,
                "{} {}: {}",
                case["family"],
                case["format"],
                result.reason
            );
            assert!(
                result
                    .candidates
                    .iter()
                    .all(|candidate| candidate.family == Family::Linux)
            );
            matched += 1;
        } else {
            assert_eq!(result.outcome, Outcome::Inconclusive);
            assert!(result.candidates.is_empty());
            inconclusive += 1;
        }
    }
    assert_eq!((matched, inconclusive), (4, 8));
    println!(
        "Linux kernel hold-out: 4 suitable matched case-runs, 8 unsuitable inconclusive case-runs; other-family false-positive accuracy unmeasured"
    );
}

#[test]
fn matching_is_conservative_and_ambiguity_preserves_competitors() {
    let mut corpus = corpus();
    let observations = observations();
    let matched = evaluate(&corpus, &observations).unwrap();
    assert_eq!(matched.outcome, Outcome::Matched);
    assert_eq!(matched.candidates[0].observation_indices, vec![0, 1, 2]);
    let mut second = corpus.signatures[0].clone();
    second.id = "synthetic-windows".into();
    second.family = Family::Windows;
    corpus.signatures.push(second);
    let ambiguous = evaluate(&corpus, &observations).unwrap();
    assert_eq!(ambiguous.outcome, Outcome::Ambiguous);
    assert_eq!(ambiguous.candidates.len(), 2);
    corpus.signatures[0].predicates.push(Predicate {
        probe: Probe::OpenSyn,
        test: Test::Mss(1460),
    });
    let ranked = evaluate(&corpus, &observations).unwrap();
    assert_eq!(ranked.outcome, Outcome::Ambiguous);
    assert_eq!(ranked.candidates[0].signature, "synthetic-linux");
}

#[test]
fn missing_unsuitable_contradictory_and_unknown_are_distinct() {
    let corpus = corpus();
    let mut observations = observations();
    assert_eq!(
        evaluate(&corpus, &observations[..2]).unwrap().outcome,
        Outcome::Inconclusive
    );
    observations[0].tcp.as_mut().unwrap().window = 4097;
    assert_eq!(
        evaluate(&corpus, &observations).unwrap().outcome,
        Outcome::Unknown
    );
    let mut conflicting = observations[0].clone();
    conflicting.tcp.as_mut().unwrap().window = 4098;
    observations.push(conflicting);
    assert_eq!(
        evaluate(&corpus, &observations).unwrap().outcome,
        Outcome::Inconclusive
    );
    observations.pop();
    observations[0].suitable = false;
    assert_eq!(
        evaluate(&corpus, &observations).unwrap().outcome,
        Outcome::Inconclusive
    );
}

#[test]
fn dynamic_fields_do_not_identify_an_os() {
    let mut observations = observations();
    let mut repeated = observations[0].clone();
    repeated.observed_hop_limit = 3;
    repeated.ipv4_identification = Some(9999);
    repeated.sequence = Some(123);
    repeated.timestamp_value = Some(456);
    observations.push(repeated);
    assert_eq!(
        evaluate(&corpus(), &observations).unwrap().outcome,
        Outcome::Matched
    );
}

#[test]
fn validates_versions_duplicates_fields_and_bounds() {
    let mut document = corpus();
    assert!(parse(&serde_json::to_vec(&document).unwrap()).is_ok());
    document.signatures.push(document.signatures[0].clone());
    assert!(document.validate().is_err());
    document.signatures.pop();
    let predicate = document.signatures[0].predicates[0].clone();
    document.signatures[0].predicates.push(predicate);
    assert!(document.validate().is_err());
    document.signatures[0].predicates.pop();
    document.signatures[0].predicates.push(Predicate {
        probe: Probe::Echo,
        test: Test::Window(1),
    });
    assert!(document.validate().is_err());
    document.signatures[0].predicates.pop();
    document.probe_set = "future".into();
    assert!(document.validate().is_err());
    assert!(parse(&vec![b' '; MAX_DOCUMENT_BYTES + 1]).is_err());
    let mut wire = serde_json::to_value(corpus()).unwrap();
    wire["signatures"][0]["predicates"][0]["test"] =
        serde_json::json!({"field":"observed_hop_limit","value":64});
    assert!(parse(&serde_json::to_vec(&wire).unwrap()).is_err());
}

#[test]
fn duplicate_or_unknown_tcp_options_are_unsuitable() {
    for options in [
        vec![TcpOption::Mss(1460), TcpOption::Mss(1200)],
        vec![TcpOption::Raw {
            kind: 99,
            data: bytes::Bytes::new(),
        }],
    ] {
        let mut packet = crate::packet::Packet::new();
        packet.push(Ipv4::default());
        packet.push(Tcp {
            options,
            ..Tcp::default()
        });
        assert!(!extract(Probe::OpenSyn, &packet).unwrap().suitable);
    }
}

#[test]
fn fragments_and_quoted_tcp_packets_cannot_qualify_identity() {
    use crate::protocol::network::{Fragment, Icmpv4, Ipv6};
    let mut packet = crate::packet::Packet::new();
    packet.push(Ipv6::default());
    packet.push(Fragment::default());
    packet.push(Tcp::default());
    assert!(!extract(Probe::OpenSyn, &packet).unwrap().suitable);
    let mut quoted = crate::packet::Packet::new();
    quoted.push(Ipv4::default());
    quoted.push(Icmpv4::default());
    quoted.push(Tcp::default());
    assert!(extract(Probe::OpenSyn, &quoted).is_none());
}
