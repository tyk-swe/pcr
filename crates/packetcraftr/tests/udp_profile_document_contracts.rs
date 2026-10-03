// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::sync::Arc;

use packetcraftr::scan::profile::{self, Error, UdpProfile};
use packetcraftr_core::document::udp_profiles::{self, MAX_PROFILE_BYTES};
use packetcraftr_core::error::Classified;
use serde_json::{Value, json};

const SAMPLE: &str = include_str!("../../../examples/documents/udp-profiles.json");

fn sample() -> Value {
    serde_json::from_str(SAMPLE).unwrap()
}

fn parse_document(document: &[u8]) -> Result<BTreeMap<u16, Arc<UdpProfile>>, Error> {
    profile::compile(udp_profiles::parse(document)?)
}

fn parse(document: &Value) -> Result<(), Error> {
    parse_document(&serde_json::to_vec(document).unwrap()).map(drop)
}

#[test]
fn distinct_profiles_share_one_storage_budget() {
    let profile = sample()["profiles"][0]["profile"].clone();
    let assignments: Vec<Value> = (0..200)
        .map(|index| {
            let mut profile = profile.clone();
            profile["name"] = json!(format!("profile-{index}"));
            let label = format!("x{index:03}{}", "a".repeat(55));
            profile["request"]["name"] = json!(format!("{label}.{label}.{label}.{label}."));
            json!({"ports": [index + 1], "profile": profile})
        })
        .collect();
    let document = json!({"schema": "packetcraftr.udp-profiles/v1", "profiles": assignments});
    let bytes = serde_json::to_vec(&document).unwrap();
    assert!(bytes.len() < MAX_PROFILE_BYTES);
    let error = parse_document(&bytes).expect_err("over budget");
    assert!(matches!(error, Error::Storage), "{error:?}");
    assert_eq!(error.to_string(), "compiled UDP profiles exceed 1 MiB");
}

#[test]
fn an_invalid_profile_keeps_its_own_classification() {
    let mut document = sample();
    document["profiles"][1]["profile"]["response"]["checks"][0]["mask"] = json!("00");
    let error = parse(&document).expect_err("mask length differs from data");
    assert!(matches!(error, Error::Invalid(_)), "{error:?}");
    assert_eq!(error.classification().code, "cli.udp_profile");
}
