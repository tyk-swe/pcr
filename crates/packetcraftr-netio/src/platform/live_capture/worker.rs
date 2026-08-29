// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native source event loop.

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::{Error, capture::Captured};
use packetcraftr_core::frame::{Frame, LinkType};

use super::{NativeCaptureEvent, NativeCaptureSource, queue::SharedCapture};
use crate::platform::worker_reaper::{ReapTask, ReaperClient, ReaperPermit, TransferOutcome};

const STATISTICS_INTERVAL: Duration = Duration::from_millis(250);
const REAPER_POLL_INTERVAL: Duration = Duration::from_millis(10);

pub(super) fn transfer_capture_worker(
    worker: JoinHandle<()>,
    stop: Arc<AtomicBool>,
    interrupt: Option<Arc<dyn super::CaptureInterrupt>>,
    permit: ReaperPermit,
    reaper: &ReaperClient,
) -> TransferOutcome {
    reaper.transfer(ReapTask::new(move || {
        // The permit and interrupt are intentionally captured by this task so
        // neither can be released before the worker has actually stopped.
        let _permit = permit;
        stop.store(true, Ordering::Release);
        while !worker.is_finished() {
            if let Some(interrupt) = &interrupt {
                // CaptureInterrupt is an internal native boundary, but keeping
                // its panic contained prevents a defective implementation from
                // abandoning the complete ownership bundle.
                let _ = catch_unwind(AssertUnwindSafe(|| interrupt.interrupt()));
            }
            thread::park_timeout(REAPER_POLL_INTERVAL);
        }
        let _ = worker.join();
        drop(interrupt);
    }))
}

pub(super) fn capture_worker(
    source: &mut dyn NativeCaptureSource,
    shared: Arc<SharedCapture>,
    stop: Arc<AtomicBool>,
    interface_index: u32,
    link_type: LinkType,
) {
    let mut native_statistics = match source.statistics() {
        Ok(statistics) => statistics,
        Err(error) => {
            shared.set_error(error);
            return;
        }
    };
    let mut statistics_checked_at = Instant::now();
    shared.set_ready();

    while !stop.load(Ordering::Acquire) {
        match source.next_event() {
            Ok(NativeCaptureEvent::Packet(packet)) => {
                let mut frame = match Frame::try_with_lengths(
                    packet.timestamp,
                    link_type,
                    packet.captured_length,
                    packet.original_length,
                    packet.bytes,
                ) {
                    Ok(frame) => frame,
                    Err(error) => {
                        shared.set_error(Error::Capture {
                            message: format!("native capture returned an invalid frame: {error}"),
                        });
                        return;
                    }
                };
                frame.interface = Some(interface_index);
                if let Err(error) =
                    shared.enqueue(Captured::with_ingress_time(frame, packet.received_at))
                {
                    shared.set_error(error);
                    return;
                }
            }
            Ok(NativeCaptureEvent::Timeout) => {}
            Ok(NativeCaptureEvent::Closed) if stop.load(Ordering::Acquire) => break,
            Ok(NativeCaptureEvent::Closed) => {
                shared.set_error(Error::Capture {
                    message: "native capture source closed unexpectedly".to_owned(),
                });
                return;
            }
            Err(error) => {
                shared.set_error(error);
                return;
            }
        }

        if statistics_checked_at.elapsed() >= STATISTICS_INTERVAL {
            let current = match source.statistics() {
                Ok(statistics) => statistics,
                Err(error) => {
                    shared.set_error(error);
                    return;
                }
            };
            if let Err(error) = shared.add_native_drop_deltas(native_statistics, current) {
                shared.set_error(error);
                return;
            }
            native_statistics = current;
            statistics_checked_at = Instant::now();
        }
    }

    match source.statistics() {
        Ok(current) => {
            if let Err(error) = shared.add_native_drop_deltas(native_statistics, current) {
                shared.set_error(error);
                return;
            }
        }
        Err(error) => {
            shared.set_error(error);
            return;
        }
    }
    shared.close();
}
