// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    mpsc::{Receiver, Sender},
};

use super::{CaptureInterrupt, NativeCaptureEvent, NativeCaptureSource, NativeCaptureStats};
use crate::Error;

#[derive(Default)]
pub(crate) struct FakeInterrupt {
    pub(crate) calls: AtomicUsize,
}

impl CaptureInterrupt for FakeInterrupt {
    fn interrupt(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

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
