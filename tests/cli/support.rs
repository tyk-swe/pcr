// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use packetcraftr::{
    capture::{Frame, LinkType, Writer},
    packet::{
        build::{Builder, Context as BuildContext, Options as BuildOptions},
        expression::{Options as ExpressionOptions, parse as parse_packet_expression},
    },
    protocol::builtin::registry as default_registry,
};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(super) fn binary() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_packetcraftr"));
    for variable in ["NO_COLOR", "CLICOLOR", "CLICOLOR_FORCE", "FORCE_COLOR"] {
        command.env_remove(variable);
    }
    command
}

pub(super) fn normalize_cli_text(bytes: &[u8]) -> String {
    let text = String::from_utf8(bytes.to_vec())
        .unwrap()
        .replace("\r\n", "\n");
    text.split('\n')
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n")
}

pub(super) fn temp_path(label: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "packetcraftr-{label}-{}-{suffix}-{sequence}.bin",
        std::process::id()
    ))
}

pub(super) fn write_capture(frames: &[&[u8]], malformed_tail: bool) -> PathBuf {
    let mut writer = Writer::pcap(Vec::new(), LinkType::ETHERNET).unwrap();
    for (index, bytes) in frames.iter().enumerate() {
        let frame = Frame::new(
            UNIX_EPOCH + std::time::Duration::from_secs(index as u64),
            LinkType::ETHERNET,
            bytes.to_vec(),
        )
        .unwrap();
        writer.write_frame(&frame).unwrap();
    }
    let mut bytes = writer.into_inner();
    if malformed_tail {
        bytes.extend_from_slice(&[0_u8; 8]);
    }
    let path = temp_path("typed-output");
    std::fs::write(&path, bytes).unwrap();
    path
}

pub(super) fn write_link_capture(link_type: LinkType, frames: &[&[u8]]) -> PathBuf {
    let mut writer = Writer::pcap(Vec::new(), link_type).unwrap();
    for (index, bytes) in frames.iter().enumerate() {
        writer
            .write_frame(
                &Frame::new(
                    UNIX_EPOCH + std::time::Duration::from_millis(index as u64 * 10),
                    link_type,
                    bytes.to_vec(),
                )
                .unwrap(),
            )
            .unwrap();
    }
    let path = temp_path("link-capture");
    std::fs::write(&path, writer.into_inner()).unwrap();
    path
}

pub(super) fn write_public_raw_capture() -> PathBuf {
    use std::sync::Arc;

    let registry = Arc::new(default_registry().unwrap());
    let packet = parse_packet_expression(
        "ipv4(src=192.0.2.1,dst=8.8.8.8,identification=1)/udp(sport=40000,dport=9)/raw(text=hi)",
        &registry,
        ExpressionOptions::default(),
    )
    .unwrap();
    let built = Builder::new(registry)
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap();
    write_link_capture(LinkType::RAW, &[built.bytes.as_ref()])
}

pub(super) fn decode_output_hex(output: &[u8]) -> Vec<u8> {
    let value = std::str::from_utf8(output).unwrap().trim();
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
