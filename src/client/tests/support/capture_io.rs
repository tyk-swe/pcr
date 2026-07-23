// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::*;

#[derive(Clone)]
pub(crate) struct ScriptedExchangeIo {
    pub(crate) events: Arc<Mutex<Vec<&'static str>>>,
    pub(crate) response: Arc<Mutex<Option<Frame>>>,
    pub(crate) deliver_before_send: bool,
    pub(crate) limits: Arc<Mutex<Vec<CaptureQueueLimits>>>,
    pub(crate) capture_statistics: CaptureStatistics,
}

impl PacketIo for ScriptedExchangeIo {
    fn send(&self, frame: TransmissionFrame<'_>) -> Result<IoSendReport, LiveIoError> {
        self.events.lock().unwrap().push("send");
        Ok(IoSendReport {
            bytes_sent: frame.bytes().len(),
            wire_bytes: Some(frame.bytes().clone()),
        })
    }
}

#[derive(Clone, Default)]
pub(crate) struct RecordingIo(pub(crate) Arc<Mutex<Vec<Bytes>>>);

impl PacketIo for RecordingIo {
    fn send(&self, frame: TransmissionFrame<'_>) -> Result<IoSendReport, LiveIoError> {
        self.0.lock().unwrap().push(frame.bytes().clone());
        Ok(IoSendReport {
            bytes_sent: frame.bytes().len(),
            wire_bytes: Some(frame.bytes().clone()),
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct PartialIo;

impl PacketIo for PartialIo {
    fn send(&self, frame: TransmissionFrame<'_>) -> Result<IoSendReport, LiveIoError> {
        Ok(IoSendReport {
            bytes_sent: frame.bytes().len().saturating_sub(1),
            wire_bytes: None,
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ChangedWireIo;

impl PacketIo for ChangedWireIo {
    fn send(&self, frame: TransmissionFrame<'_>) -> Result<IoSendReport, LiveIoError> {
        let mut changed = frame.bytes().to_vec();
        changed[0] ^= 1;
        Ok(IoSendReport {
            bytes_sent: changed.len(),
            wire_bytes: Some(Bytes::from(changed)),
        })
    }
}

pub(crate) struct ScriptedExchangeCapture {
    pub(crate) events: Arc<Mutex<Vec<&'static str>>>,
    pub(crate) response: Arc<Mutex<Option<Frame>>>,
    pub(crate) deliver_before_send: bool,
    pub(crate) statistics: CaptureStatistics,
}

impl CaptureSession for ScriptedExchangeCapture {
    fn supports_monotonic_ingress_time(&self) -> bool {
        true
    }

    fn wait_ready(&mut self, _timeout: Duration) -> Result<(), LiveIoError> {
        self.events.lock().unwrap().push("ready");
        Ok(())
    }

    fn next_frame(&mut self, _timeout: Duration) -> Result<Option<Frame>, LiveIoError> {
        let sent = self.events.lock().unwrap().contains(&"send");
        if sent || self.deliver_before_send {
            let mut response = self.response.lock().unwrap().take();
            if let Some(frame) = &mut response {
                self.statistics.received_frames = self
                    .statistics
                    .received_frames
                    .checked_add(1)
                    .expect("test capture frame counter");
                self.statistics.received_bytes = self
                    .statistics
                    .received_bytes
                    .checked_add(frame.bytes().len() as u64)
                    .expect("test capture byte counter");
            }
            Ok(response)
        } else {
            Ok(None)
        }
    }

    fn next_captured_frame(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<CapturedFrame>, LiveIoError> {
        self.next_frame(timeout)
            .map(|frame| frame.map(|frame| CapturedFrame::new(frame, Instant::now())))
    }

    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        self.events.lock().unwrap().push("shutdown");
        Ok(())
    }

    fn statistics(&self) -> CaptureStatistics {
        self.statistics
    }
}

impl CaptureProvider for ScriptedExchangeIo {
    type Capture = ScriptedExchangeCapture;

    fn arm_capture(
        &self,
        _route: &PlannedRoute,
        limits: CaptureQueueLimits,
    ) -> Result<Self::Capture, LiveIoError> {
        self.events.lock().unwrap().push("arm");
        self.limits.lock().unwrap().push(limits);
        Ok(ScriptedExchangeCapture {
            events: Arc::clone(&self.events),
            response: Arc::clone(&self.response),
            deliver_before_send: self.deliver_before_send,
            statistics: self.capture_statistics,
        })
    }
}

#[derive(Clone)]
pub(crate) struct DeadlineConsumingExchangeIo {
    pub(crate) events: Arc<Mutex<Vec<&'static str>>>,
    pub(crate) response: Arc<Mutex<Option<Frame>>>,
}

impl PacketIo for DeadlineConsumingExchangeIo {
    fn send(&self, frame: TransmissionFrame<'_>) -> Result<IoSendReport, LiveIoError> {
        self.events.lock().unwrap().push("send");
        Ok(IoSendReport {
            bytes_sent: frame.bytes().len(),
            wire_bytes: Some(frame.bytes().clone()),
        })
    }
}

pub(crate) struct DeadlineConsumingCapture {
    pub(crate) events: Arc<Mutex<Vec<&'static str>>>,
    pub(crate) response: Arc<Mutex<Option<Frame>>>,
    pub(crate) statistics: CaptureStatistics,
}

impl CaptureSession for DeadlineConsumingCapture {
    fn supports_monotonic_ingress_time(&self) -> bool {
        true
    }

    fn wait_ready(&mut self, _timeout: Duration) -> Result<(), LiveIoError> {
        self.events.lock().unwrap().push("ready");
        Ok(())
    }

    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>, LiveIoError> {
        if self.events.lock().unwrap().contains(&"send") {
            let response = self.response.lock().unwrap().take();
            if let Some(frame) = &response {
                self.statistics.received_frames += 1;
                self.statistics.received_bytes += frame.bytes().len() as u64;
                return Ok(response);
            }
        }
        if !timeout.is_zero() {
            self.events.lock().unwrap().push("capture_wait");
            std::thread::sleep(timeout);
        }
        Ok(None)
    }

    fn next_captured_frame(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<CapturedFrame>, LiveIoError> {
        self.next_frame(timeout)
            .map(|frame| frame.map(|frame| CapturedFrame::new(frame, Instant::now())))
    }

    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        self.events.lock().unwrap().push("shutdown");
        Ok(())
    }

    fn statistics(&self) -> CaptureStatistics {
        self.statistics
    }
}

impl CaptureProvider for DeadlineConsumingExchangeIo {
    type Capture = DeadlineConsumingCapture;

    fn arm_capture(
        &self,
        _route: &PlannedRoute,
        _limits: CaptureQueueLimits,
    ) -> Result<Self::Capture, LiveIoError> {
        self.events.lock().unwrap().push("arm");
        Ok(DeadlineConsumingCapture {
            events: Arc::clone(&self.events),
            response: Arc::clone(&self.response),
            statistics: CaptureStatistics::default(),
        })
    }
}

#[derive(Clone)]
pub(crate) struct UnmarkedExchangeIo(pub(crate) ScriptedExchangeIo);

impl PacketIo for UnmarkedExchangeIo {
    fn send(&self, frame: TransmissionFrame<'_>) -> Result<IoSendReport, LiveIoError> {
        self.0.send(frame)
    }
}

pub(crate) struct UnmarkedExchangeCapture(pub(crate) ScriptedExchangeCapture);

impl CaptureSession for UnmarkedExchangeCapture {
    fn supports_monotonic_ingress_time(&self) -> bool {
        true
    }

    fn wait_ready(&mut self, timeout: Duration) -> Result<(), LiveIoError> {
        self.0.wait_ready(timeout)
    }

    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>, LiveIoError> {
        self.0.next_frame(timeout)
    }

    fn next_captured_frame(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<CapturedFrame>, LiveIoError> {
        self.0
            .next_frame(timeout)
            .map(|frame| frame.map(CapturedFrame::without_ingress_time))
    }

    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        self.0.shutdown()
    }

    fn statistics(&self) -> CaptureStatistics {
        self.0.statistics()
    }
}

impl CaptureProvider for UnmarkedExchangeIo {
    type Capture = UnmarkedExchangeCapture;

    fn arm_capture(
        &self,
        _route: &PlannedRoute,
        limits: CaptureQueueLimits,
    ) -> Result<Self::Capture, LiveIoError> {
        self.0.events.lock().unwrap().push("arm");
        self.0.limits.lock().unwrap().push(limits);
        Ok(UnmarkedExchangeCapture(ScriptedExchangeCapture {
            events: Arc::clone(&self.0.events),
            response: Arc::clone(&self.0.response),
            deliver_before_send: self.0.deliver_before_send,
            statistics: self.0.capture_statistics,
        }))
    }
}

#[derive(Clone)]
pub(crate) struct EndlessCaptureIo {
    pub(crate) frame: Frame,
    pub(crate) sends: Arc<AtomicUsize>,
}

impl PacketIo for EndlessCaptureIo {
    fn send(&self, frame: TransmissionFrame<'_>) -> Result<IoSendReport, LiveIoError> {
        self.sends.fetch_add(1, Ordering::SeqCst);
        Ok(IoSendReport {
            bytes_sent: frame.bytes().len(),
            wire_bytes: Some(frame.bytes().clone()),
        })
    }
}

pub(crate) struct EndlessCapture(pub(crate) Frame);

impl CaptureSession for EndlessCapture {
    fn supports_monotonic_ingress_time(&self) -> bool {
        true
    }

    fn wait_ready(&mut self, _timeout: Duration) -> Result<(), LiveIoError> {
        Ok(())
    }

    fn next_frame(&mut self, _timeout: Duration) -> Result<Option<Frame>, LiveIoError> {
        Ok(Some(self.0.clone()))
    }

    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        Ok(())
    }

    fn statistics(&self) -> CaptureStatistics {
        CaptureStatistics::default()
    }
}

impl CaptureProvider for EndlessCaptureIo {
    type Capture = EndlessCapture;

    fn arm_capture(
        &self,
        _route: &PlannedRoute,
        limits: CaptureQueueLimits,
    ) -> Result<Self::Capture, LiveIoError> {
        limits.validate()?;
        Ok(EndlessCapture(self.frame.clone()))
    }
}

#[derive(Clone)]
pub(crate) struct SlowSendIo {
    pub(crate) delay: Duration,
    pub(crate) sends: Arc<AtomicUsize>,
}

impl PacketIo for SlowSendIo {
    fn send(&self, frame: TransmissionFrame<'_>) -> Result<IoSendReport, LiveIoError> {
        self.sends.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(self.delay);
        Ok(IoSendReport {
            bytes_sent: frame.bytes().len(),
            wire_bytes: Some(frame.bytes().clone()),
        })
    }
}

pub(crate) struct EmptyCapture;

impl CaptureSession for EmptyCapture {
    fn supports_monotonic_ingress_time(&self) -> bool {
        true
    }

    fn wait_ready(&mut self, _timeout: Duration) -> Result<(), LiveIoError> {
        Ok(())
    }

    fn next_frame(&mut self, _timeout: Duration) -> Result<Option<Frame>, LiveIoError> {
        Ok(None)
    }

    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        Ok(())
    }

    fn statistics(&self) -> CaptureStatistics {
        CaptureStatistics::default()
    }
}

impl CaptureProvider for SlowSendIo {
    type Capture = EmptyCapture;

    fn arm_capture(
        &self,
        _route: &PlannedRoute,
        limits: CaptureQueueLimits,
    ) -> Result<Self::Capture, LiveIoError> {
        limits.validate()?;
        Ok(EmptyCapture)
    }
}

#[derive(Clone)]
pub(crate) struct ReadinessAndShutdownFailIo(pub(crate) Arc<Mutex<Vec<&'static str>>>);

impl PacketIo for ReadinessAndShutdownFailIo {
    fn send(&self, _frame: TransmissionFrame<'_>) -> Result<IoSendReport, LiveIoError> {
        panic!("readiness failure must prevent transmission")
    }
}

pub(crate) struct ReadinessAndShutdownFailCapture(pub(crate) Arc<Mutex<Vec<&'static str>>>);

impl CaptureSession for ReadinessAndShutdownFailCapture {
    fn supports_monotonic_ingress_time(&self) -> bool {
        true
    }

    fn wait_ready(&mut self, _timeout: Duration) -> Result<(), LiveIoError> {
        self.0.lock().unwrap().push("ready");
        Err(LiveIoError::CaptureReadiness {
            message: "not ready".to_owned(),
        })
    }

    fn next_frame(&mut self, _timeout: Duration) -> Result<Option<Frame>, LiveIoError> {
        unreachable!("readiness failure prevents receive")
    }

    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        self.0.lock().unwrap().push("shutdown");
        Err(LiveIoError::Capture {
            message: "join failed".to_owned(),
        })
    }

    fn statistics(&self) -> CaptureStatistics {
        CaptureStatistics::default()
    }
}

impl CaptureProvider for ReadinessAndShutdownFailIo {
    type Capture = ReadinessAndShutdownFailCapture;

    fn arm_capture(
        &self,
        _route: &PlannedRoute,
        _limits: CaptureQueueLimits,
    ) -> Result<Self::Capture, LiveIoError> {
        self.0.lock().unwrap().push("arm");
        Ok(ReadinessAndShutdownFailCapture(Arc::clone(&self.0)))
    }
}

pub(crate) struct DropObservedCapture(pub(crate) Arc<AtomicUsize>);

impl CaptureSession for DropObservedCapture {
    fn supports_monotonic_ingress_time(&self) -> bool {
        true
    }

    fn wait_ready(&mut self, _timeout: Duration) -> Result<(), LiveIoError> {
        Ok(())
    }

    fn next_frame(&mut self, _timeout: Duration) -> Result<Option<Frame>, LiveIoError> {
        Ok(None)
    }

    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn statistics(&self) -> CaptureStatistics {
        CaptureStatistics::default()
    }
}

pub(crate) struct PanicShutdownCapture(pub(crate) Arc<AtomicUsize>);

impl CaptureSession for PanicShutdownCapture {
    fn supports_monotonic_ingress_time(&self) -> bool {
        true
    }

    fn wait_ready(&mut self, _timeout: Duration) -> Result<(), LiveIoError> {
        Ok(())
    }

    fn next_frame(&mut self, _timeout: Duration) -> Result<Option<Frame>, LiveIoError> {
        Ok(None)
    }

    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        panic!("scripted shutdown panic")
    }

    fn statistics(&self) -> CaptureStatistics {
        CaptureStatistics::default()
    }
}

#[derive(Clone)]
pub(crate) struct MissingMonotonicIo(pub(crate) Arc<Mutex<Vec<&'static str>>>);

impl PacketIo for MissingMonotonicIo {
    fn send(&self, _frame: TransmissionFrame<'_>) -> Result<IoSendReport, LiveIoError> {
        self.0.lock().unwrap().push("send");
        unreachable!("missing monotonic ingress capability must prevent transmission")
    }
}

pub(crate) struct MissingMonotonicCapture(pub(crate) Arc<Mutex<Vec<&'static str>>>);

impl CaptureSession for MissingMonotonicCapture {
    fn wait_ready(&mut self, _timeout: Duration) -> Result<(), LiveIoError> {
        self.0.lock().unwrap().push("ready");
        Ok(())
    }

    fn next_frame(&mut self, _timeout: Duration) -> Result<Option<Frame>, LiveIoError> {
        Ok(None)
    }

    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        self.0.lock().unwrap().push("shutdown");
        Ok(())
    }

    fn statistics(&self) -> CaptureStatistics {
        CaptureStatistics::default()
    }
}

impl CaptureProvider for MissingMonotonicIo {
    type Capture = MissingMonotonicCapture;

    fn arm_capture(
        &self,
        _route: &PlannedRoute,
        _limits: CaptureQueueLimits,
    ) -> Result<Self::Capture, LiveIoError> {
        self.0.lock().unwrap().push("arm");
        Ok(MissingMonotonicCapture(Arc::clone(&self.0)))
    }
}
