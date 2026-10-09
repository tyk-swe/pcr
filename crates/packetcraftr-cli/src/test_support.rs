// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{self, Write};
use std::sync::{Arc, Mutex, OnceLock};

use crate::output::{contract::Command, stream::StreamEncoder};
use packetcraftr_core::diagnostic::Diagnostic;
use serde_json::Value;

#[derive(Clone, Default)]
pub struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl SharedBuffer {
    pub fn bytes(&self) -> Vec<u8> {
        self.0.lock().expect("shared buffer lock").clone()
    }

    pub fn records(&self) -> Vec<Value> {
        parse_ndjson(&self.bytes())
    }
}

impl Write for SharedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("shared buffer lock")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn stream(command: Command) -> (StreamEncoder, SharedBuffer) {
    let buffer = SharedBuffer::default();
    (StreamEncoder::new(command, buffer.clone()), buffer)
}

pub fn parse_ndjson(bytes: &[u8]) -> Vec<Value> {
    let text = std::str::from_utf8(bytes).expect("NDJSON output must be UTF-8");
    assert!(
        text.is_empty() || text.ends_with('\n'),
        "nonempty NDJSON output ends every record with a newline"
    );
    text.lines()
        .map(|line| {
            serde_json::from_str(line)
                .expect("each NDJSON line holds exactly one complete JSON value")
        })
        .collect()
}

pub fn assert_contiguous(records: &[Value]) {
    for (expected, record) in records.iter().enumerate() {
        assert_eq!(
            record["sequence"].as_u64(),
            u64::try_from(expected).ok(),
            "record {expected} has the wrong stream sequence"
        );
    }
}

pub fn output_schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../../schemas/packetcraftr.output.v11.schema.json"
        ))
        .expect("published output schema must be JSON")
    })
}

/// Integration tests build their own validator over [`output_schema`], because
/// `jsonschema` is only a dev-dependency.
#[cfg(test)]
pub(crate) fn schema_validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        jsonschema::validator_for(output_schema()).expect("published output schema must compile")
    })
}

#[derive(serde::Serialize)]
#[serde(transparent)]
pub struct TestRecord<T>(pub T);

impl<T: serde::Serialize> crate::output::stream::StreamRecord for TestRecord<T> {
    fn event_name(&self) -> &'static str {
        "frame"
    }
}

/// Sent evidence for one raw byte whose build carried `diagnostics`.
pub fn sent_packet_with(diagnostics: Vec<Diagnostic>) -> Arc<packetcraftr::evidence::SentPacket> {
    use packetcraftr::route::{Materialized, Plan};
    use packetcraftr_core::{build, codec, frame::LinkType, layer::Raw, packet::Packet};
    use packetcraftr_netio::link::{Capability, Mode};
    use packetcraftr_netio::route::{Decision, Scope, SelectionReason};

    let mut packet = Packet::new();
    packet.push(Raw::new(vec![0_u8]));
    let mut built = build::Builder::new(packetcraftr_core::protocol::builtin::registry())
        .build(packet, codec::Context::default(), build::Options::default())
        .expect("sent fixture builds");
    built.diagnostics = diagnostics;
    let route = Materialized {
        plan: Plan {
            decision: Decision {
                interface: packetcraftr_netio::interface::Id {
                    name: "fixture0".to_owned(),
                    index: 1,
                },
                source_mac: None,
                selected_source: None,
                preferred_source: None,
                next_hop: None,
                selection_reason: SelectionReason::InterfaceOnly,
                destination_scope: Scope::Link,
                mtu: u32::MAX,
                capability: Capability::Layer3,
                link_type: LinkType::RAW,
            },
            mode: Mode::Layer3,
            lookup_destination: None,
            final_destination: None,
            visited_destinations: Vec::new(),
            packet_source: None,
            neighbor_source: None,
            neighbor_target: None,
            destination_mac: None,
            source_mac: None,
            neighbor_vlan_tags: Vec::new(),
            synthesized_ethernet: false,
        },
        neighbor_resolution: None,
    };
    let report = packetcraftr_netio::transmit::Submission::start()
        .complete(built.bytes.len(), built.bytes.clone());
    Arc::new(
        packetcraftr::evidence::SentPacket::try_new(built, route, report)
            .expect("trusted sent fixture"),
    )
}
