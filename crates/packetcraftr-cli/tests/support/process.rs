// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Shared by several test binaries; each one uses a different subset.
#![allow(dead_code)]

use std::io::Write;
use std::process::{Command, Output, Stdio};

pub(crate) fn run_with_stdin(arguments: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("CLI process must start");
    child
        .stdin
        .take()
        .expect("stdin must be piped")
        .write_all(input)
        .expect("stdin must accept input");
    child.wait_with_output().expect("CLI process must finish")
}

pub(crate) fn decode_hex(value: &str) -> Vec<u8> {
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    assert!(
        remainder.is_empty(),
        "fixture hex must not have an unmatched final nibble"
    );
    pairs
        .iter()
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("fixture hex must be UTF-8");
            u8::from_str_radix(pair, 16).expect("fixture hex must be valid")
        })
        .collect()
}

pub(crate) fn append_truncated_record(file: &mut tempfile::NamedTempFile) {
    file.write_all(&[0; 8])
        .expect("truncated record header must write");
    file.flush().expect("truncated capture must flush");
}
