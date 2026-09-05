// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native source event loop.

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use crate::{Error, capture::Captured};
use packetcraftr_core::frame::{Frame, LinkType};

use super::{NativeCaptureEvent, NativeCaptureSource, queue::CaptureQueue};
use crate::platform::worker_reaper::{
    ReaperClient, ReaperPermit, TransferOutcome, wait_until_finished,
};

const STATISTICS_INTERVAL: Duration = Duration::from_millis(250);
const REAPER_POLL_INTERVAL: Duration = Duration::from_millis(10);

pub(super) fn transfer_capture_worker(
    worker: JoinHandle<()>,
    stop: Arc<AtomicBool>,
    interrupt: Arc<dyn super::CaptureInterrupt>,
    permit: ReaperPermit,
    reaper: &ReaperClient,
) -> TransferOutcome {
    reaper.transfer(Box::new(move || {
        // The permit and interrupt are intentionally captured by this task so
        // neither can be released before the worker has actually stopped.
        let _permit = permit;
        stop.store(true, Ordering::Release);
        wait_until_finished(worker, REAPER_POLL_INTERVAL, || {
            // A panicking interrupt must not abandon the ownership bundle.
            let _ = catch_unwind(AssertUnwindSafe(|| interrupt.interrupt()));
        });
        drop(interrupt);
    }))
}

pub(super) fn capture_worker(
    source: &mut dyn NativeCaptureSource,
    shared: Arc<CaptureQueue>,
    stop: Arc<AtomicBool>,
    interface_index: u32,
    link_type: LinkType,
) -> Result<(), Error> {
    let mut native_statistics = source.statistics()?;
    let mut statistics_checked_at = Instant::now();
    shared.set_ready();

    while !stop.load(Ordering::Acquire) {
        match source.next_event()? {
            NativeCaptureEvent::Packet(packet) => {
                let mut frame = Frame::try_with_lengths(
                    packet.timestamp,
                    link_type,
                    packet.captured_length,
                    packet.original_length,
                    packet.bytes,
                )
                .map_err(|error| Error::Capture {
                    message: "native capture returned an invalid frame".to_owned(),
                    source: Some(Arc::new(error)),
                })?;
                frame.interface = Some(interface_index);
                shared.enqueue(Captured::with_ingress_time(frame, packet.received_at))?;
            }
            NativeCaptureEvent::Timeout => {}
            NativeCaptureEvent::Closed if stop.load(Ordering::Acquire) => break,
            NativeCaptureEvent::Closed => {
                return Err(Error::Capture {
                    message: "native capture source closed unexpectedly".to_owned(),
                    source: None,
                });
            }
        }

        if statistics_checked_at.elapsed() >= STATISTICS_INTERVAL {
            let current = source.statistics()?;
            shared.add_native_drop_deltas(native_statistics, current)?;
            native_statistics = current;
            statistics_checked_at = Instant::now();
        }
    }

    shared.add_native_drop_deltas(native_statistics, source.statistics()?)?;
    shared.close();
    Ok(())
}
