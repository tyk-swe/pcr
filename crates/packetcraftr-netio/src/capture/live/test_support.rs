// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Fake native capture sources and interrupts the activation and session
//! tests share.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    mpsc::{Receiver, Sender},
};

use super::{CaptureInterrupt, NativeCaptureEvent, NativeCaptureSource, NativeCaptureStats};
use crate::Error;

/// Counts the interrupts a session delivers.
#[derive(Default)]
pub(crate) struct FakeInterrupt {
    pub(crate) calls: AtomicUsize,
}

impl CaptureInterrupt for FakeInterrupt {
    fn interrupt(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

/// A source whose first read reports that it started, then blocks until
/// released, reports that it finished, and closes.
pub(crate) struct BlockingSource {
    pub(crate) started: Option<Sender<()>>,
    pub(crate) release: Receiver<()>,
    pub(crate) finished: Option<Sender<()>>,
}

impl NativeCaptureSource for BlockingSource {
    fn next_event(&mut self) -> Result<NativeCaptureEvent, Error> {
        if let Some(started) = self.started.take() {
            let _ = started.send(());
        }
        self.release.recv().map_err(|_| Error::Capture {
            message: "fake capture release channel closed".to_owned(),
            source: None,
        })?;
        if let Some(finished) = self.finished.take() {
            let _ = finished.send(());
        }
        Ok(NativeCaptureEvent::Closed)
    }

    fn stats(&mut self) -> Result<NativeCaptureStats, Error> {
        Ok(NativeCaptureStats::default())
    }
}
