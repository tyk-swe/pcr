// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;
use packetcraftr_core::{
    document::{Format, payload, recipe},
    error::{Classified, Kind},
    packet::DEFAULT_MAX_LAYERS,
    packet::Packet,
    protocol::builtin,
};
const RECIPE: &str = "ipv4(src=192.0.2.1,dst=192.0.2.2)/udp(sport=9000,dport=9001)/raw()";

fn recipe(input: &str, declared: Option<Format>) -> Result<Packet, recipe::Error> {
    recipe::parse(input, declared, &builtin::registry(), DEFAULT_MAX_LAYERS)
}

fn target(selector: &str) -> payload::Target {
    selector.parse().expect("valid target")
}

#[test]
fn a_refused_payload_target_never_loads_its_bytes() {
    let occupied = "ipv4()/udp()/raw(hex=\"aa\")";
    for (recipe_text, selector, message) in [
        (
            RECIPE,
            "9.bytes",
            "payload layer index 9 is outside the recipe's 3 layers",
        ),
        (RECIPE, "2.nope", "payload field nope is unknown on layer 2"),
        (RECIPE, "2.a..b", "payload field a..b is unknown on layer 2"),
        (
            RECIPE,
            "1.source_port",
            "payload field source_port on layer 1 is not bytes-typed",
        ),
        (
            occupied,
            "2.bytes",
            "payload field bytes on layer 2 already holds recipe bytes",
        ),
    ] {
        let mut packet = recipe(recipe_text, None).unwrap();
        let error = target(selector)
            .inject(&mut packet, || -> Result<Bytes, payload::Error> {
                panic!("{selector} loaded its bytes")
            })
            .expect_err("refused");
        assert_eq!(error.to_string(), message);
        let classification = error.classification();
        assert_eq!(
            (classification.code, classification.kind),
            ("cli.error", Kind::Usage)
        );
        assert!(error.causes().is_empty());
    }
}
