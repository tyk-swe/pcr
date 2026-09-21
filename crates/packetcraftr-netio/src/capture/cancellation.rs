// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Cooperative cancellation around an owned capture session.

use std::time::{Duration, Instant};

use packetcraftr_core::budget::Cancellation;

use super::{Captured, Error, MAX_TIMEOUT, Metadata, Session, Statistics};

/// Capture adapter that polls cooperatively for user cancellation. Provider
/// readiness and shutdown retain their original bounded lifecycle contracts.
/// A provider must honor each requested wait; arbitrary blocked provider code
/// cannot be preempted by this adapter.
pub struct Cancellable<C> {
    inner: C,
    cancellation: Option<packetcraftr_core::budget::Cancellation>,
}

impl<C: Session> Cancellable<C> {
    pub fn new(inner: C, cancellation: Option<packetcraftr_core::budget::Cancellation>) -> Self {
        Self {
            inner,
            cancellation,
        }
    }

    fn check(&self) -> Result<(), Error> {
        if let Some(signal) = &self.cancellation {
            signal.check()?;
        }
        Ok(())
    }
}

impl<C: Session> Session for Cancellable<C> {
    fn metadata(&self) -> &Metadata {
        self.inner.metadata()
    }
    fn wait_ready(&mut self, timeout: Duration) -> Result<(), Error> {
        self.check()?;
        self.inner.wait_ready(timeout)?;
        self.check()
    }
    fn next_captured_frame(&mut self, timeout: Duration) -> Result<Option<Captured>, Error> {
        let start = Instant::now();
        // Validate the original request before slicing it into polls: otherwise
        // cancellation would accidentally admit waits beyond the provider contract.
        if timeout > MAX_TIMEOUT || start.checked_add(timeout).is_none() {
            return Err(Error::InvalidCaptureTimeout {
                timeout,
                maximum: MAX_TIMEOUT,
            });
        }
        if self.cancellation.is_none() {
            return self.inner.next_captured_frame(timeout);
        }
        loop {
            self.check()?;
            let poll_started = Instant::now();
            let remaining = timeout.saturating_sub(poll_started.duration_since(start));
            let poll_timeout = remaining.min(Cancellation::POLL_INTERVAL);
            let frame = self.inner.next_captured_frame(poll_timeout)?;
            self.check()?;
            if frame.is_none() {
                // Empty polls may return early, including after a backend stops.
                std::thread::sleep(poll_timeout.saturating_sub(poll_started.elapsed()));
                self.check()?;
            }
            if frame.is_some() || start.elapsed() >= timeout {
                return Ok(frame);
            }
        }
    }
    fn shutdown(&mut self) -> Result<(), Error> {
        self.inner.shutdown()
    }
    fn statistics(&self) -> Statistics {
        self.inner.statistics()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::Id as InterfaceId;
    use packetcraftr_core::budget::Cancellation;
    use packetcraftr_core::frame::LinkType;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    struct Capture {
        metadata: Metadata,
        signal: Cancellation,
        stopped: Arc<AtomicBool>,
    }
    impl Session for Capture {
        fn metadata(&self) -> &Metadata {
            &self.metadata
        }
        fn wait_ready(&mut self, _: Duration) -> Result<(), Error> {
            Ok(())
        }
        fn next_captured_frame(&mut self, timeout: Duration) -> Result<Option<Captured>, Error> {
            assert!(timeout <= Duration::from_millis(25));
            self.signal.cancel();
            Ok(None)
        }
        fn shutdown(&mut self) -> Result<(), Error> {
            self.stopped.store(true, Ordering::Release);
            Ok(())
        }
        fn statistics(&self) -> Statistics {
            Statistics::default()
        }
    }
    #[test]
    fn cancellation_during_capture_wait_still_allows_explicit_shutdown() {
        let signal = Cancellation::default();
        let stopped = Arc::new(AtomicBool::new(false));
        let capture = Capture {
            metadata: Metadata {
                interface: InterfaceId {
                    name: "fixture".to_owned(),
                    index: 1,
                },
                link_type: LinkType::IPV4,
                snap_length: 128,
                native: Default::default(),
            },
            signal: signal.clone(),
            stopped: stopped.clone(),
        };
        let mut capture = Cancellable::new(capture, Some(signal));
        capture.wait_ready(Duration::from_secs(1)).unwrap();
        assert!(matches!(
            capture.next_captured_frame(Duration::MAX),
            Err(Error::InvalidCaptureTimeout { .. })
        ));
        assert!(matches!(
            capture.next_captured_frame(Duration::from_secs(60)),
            Err(Error::Cancelled(_))
        ));
        capture.shutdown().unwrap();
        assert!(stopped.load(Ordering::Acquire));
    }
}
