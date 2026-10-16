// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{
    Arc,
    mpsc::{self, Receiver, RecvTimeoutError},
};

use packetcraftr_core::{
    budget::{Deadline, Interrupted},
    error::Source,
};

use super::{
    ARMING, Limits, Session, admit,
    live::{NativeCaptureParts, NativeCaptureSession, Started},
};
use crate::{
    Error,
    deadline::POLL_INTERVAL,
    workers::{
        Class, Pool,
        reaper::{ReaperClient, ReaperStartError, shared_reaper, wait_until_finished},
    },
};

pub(super) fn open(
    limits: Limits,
    deadline: &Deadline,
    activate: impl FnOnce() -> Result<NativeCaptureParts, Error> + Send + 'static,
) -> Result<Box<dyn Session>, Error> {
    open_with(
        limits,
        deadline,
        activate,
        crate::workers::shared(),
        shared_reaper,
    )
}

fn open_with(
    limits: Limits,
    caller: &Deadline,
    activate: impl FnOnce() -> Result<NativeCaptureParts, Error> + Send + 'static,
    pool: &Arc<Pool>,
    reaper: impl FnOnce() -> Result<ReaperClient, ReaperStartError>,
) -> Result<Box<dyn Session>, Error> {
    // Native activation spends wall time even when the caller's clock is frozen.
    let deadline = caller
        .detach()
        .map_err(|interrupted| Error::interrupted(interrupted, ARMING))?;
    // Both fallible cleanup-service steps happen before any native call.
    let reaper = reaper().map_err(|error| Error::Capture {
        message: "native capture cleanup is unavailable".to_owned(),
        source: Some(Source::new(error)),
    })?;
    let permit = pool.admit(Class::Native).map_err(|error| Error::Capture {
        message: format!(
            "native capture activation capacity {} is exhausted",
            error.capacity
        ),
        source: Some(Source::new(error)),
    })?;
    // A rendezvous: the reader starts only once an owner holds its stop flag.
    let (handoff, claim) = mpsc::sync_channel::<Result<Started, Error>>(0);
    let worker_deadline = deadline.clone();
    let task = permit
        .spawn_with_control(&deadline, move || {
            let activated = (|| {
                admit(&worker_deadline, ARMING)?;
                let parts = activate();
                // A late native error must not mask interruption.
                admit(&worker_deadline, ARMING)?;
                parts
            })();
            match activated {
                Err(error) => {
                    let _ = handoff.send(Err(error));
                }
                Ok(parts) => {
                    let (started, reader) = NativeCaptureSession::prepare(parts, limits);
                    if handoff.send(Ok(started)).is_ok() {
                        reader.run();
                    }
                }
            }
        })
        .map_err(|error| match deadline.enforce() {
            Err(interrupted) => Error::interrupted(interrupted, ARMING),
            Ok(()) => Error::Capture {
                message: "could not start the native capture activation worker".to_owned(),
                source: Some(Source::new(error)),
            },
        })?;

    match await_handoff(&claim, &deadline) {
        Err(interrupted) => {
            drop(claim);
            permit.retention_marker().mark_retained();
            reaper.transfer(Box::new(move || {
                let _permit = permit;
                wait_until_finished(task, POLL_INTERVAL, || {});
            }));
            Err(Error::interrupted(interrupted, ARMING))
        }
        Ok(Ok(started)) => {
            let retention = permit.retention_marker();
            let session = NativeCaptureSession::attach(started, task, permit, reaper.clone());
            if let Err(interrupted) = deadline.live_remaining() {
                retention.mark_retained();
                reaper.transfer(Box::new(move || drop(session)));
                return Err(Error::interrupted(interrupted, ARMING));
            }
            Ok(Box::new(session))
        }
        // Interruption still wins over a failure that arrived at the same moment.
        Ok(Err(error)) => {
            admit(&deadline, ARMING)?;
            Err(error)
        }
    }
}

fn await_handoff(
    claim: &Receiver<Result<Started, Error>>,
    deadline: &Deadline,
) -> Result<Result<Started, Error>, Interrupted> {
    // The channel signals the handoff, not cancellation, so the wait is sliced.
    loop {
        let remaining = deadline.live_remaining()?;
        match claim.recv_timeout(remaining.min(POLL_INTERVAL)) {
            Ok(outcome) => return Ok(outcome),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                return Ok(Err(Error::Capture {
                    message: "native capture activation worker panicked".to_owned(),
                    source: None,
                }));
            }
        }
    }
}
