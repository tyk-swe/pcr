// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

use std::io::{self, Write};
use std::process::{ChildStdin, Command, Output, Stdio};
use std::sync::mpsc;

pub(crate) fn run_with_stdin(arguments: &[&str], input: &[u8]) -> Output {
    run_with_stdin_writer(arguments, input, |mut stdin, input, _| {
        stdin.write_all(input)
    })
}

pub(crate) fn run_with_stdin_writer(
    arguments: &[&str],
    input: &[u8],
    write_input: impl FnOnce(ChildStdin, &[u8], mpsc::Receiver<()>) -> io::Result<()> + Send,
) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("CLI process must start");
    let stdin = child.stdin.take().expect("stdin must be piped");
    let (exited, child_exited) = mpsc::channel();
    std::thread::scope(|scope| {
        // Stream input while wait_with_output drains both output pipes. Writing
        // everything first can block on a child waiting for stdout capacity.
        let writer = scope.spawn(move || write_input(stdin, input, child_exited));
        let output = child.wait_with_output().expect("CLI process must finish");
        // Controlled writers can hold input until the child has refused it.
        let _ = exited.send(());
        writer
            .join()
            .expect("stdin writer must finish")
            .unwrap_or_else(|error| {
                // Input validation may reject a prefix without consuming stdin.
                // Callers must still assert the child's expected failure status.
                if error.kind() == io::ErrorKind::BrokenPipe && !output.status.success() {
                    return;
                }
                panic!("stdin must accept input: {error}; CLI output: {output:?}")
            });
        output
    })
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
