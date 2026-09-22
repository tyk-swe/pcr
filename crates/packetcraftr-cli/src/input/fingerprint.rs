// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_cli::output::forwarding::CaptureSource;
use packetcraftr_cli::output::hex::compact_hex;
use sha2::{Digest as _, Sha256};
use std::cell::RefCell;
use std::io::{self, Read};
use std::rc::Rc;

#[derive(Clone, Default)]
pub(crate) struct Fingerprint(Rc<RefCell<State>>);

#[derive(Default)]
struct State {
    digest: Sha256,
    bytes: u64,
}

impl Fingerprint {
    pub(crate) fn finish(&self) -> CaptureSource {
        let state = self.0.borrow();
        let digest = state.digest.clone().finalize();
        CaptureSource {
            sha256: compact_hex(&digest),
            encoded_bytes: state.bytes,
        }
    }
}

pub(super) struct Hashed<R> {
    source: R,
    fingerprint: Fingerprint,
}

impl<R> Hashed<R> {
    pub(super) fn new(source: R) -> (Self, Fingerprint) {
        let fingerprint = Fingerprint::default();
        (
            Self {
                source,
                fingerprint: fingerprint.clone(),
            },
            fingerprint,
        )
    }
}

impl<R: Read> Read for Hashed<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.source.read(buffer)?;
        let mut state = self.fingerprint.0.borrow_mut();
        state.bytes = state
            .bytes
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::other("capture fingerprint byte count overflow"))?;
        state.digest.update(&buffer[..count]);
        Ok(count)
    }
}
