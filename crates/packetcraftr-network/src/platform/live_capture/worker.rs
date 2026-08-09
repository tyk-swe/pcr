// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native source event loop.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::{Error as LiveIoError, capture::CapturedFrame};
use packetcraftr_packet::frame::{Frame, LinkType};

use super::{NativeCaptureEvent, NativeCaptureSource, queue::SharedCapture};

const STATISTICS_INTERVAL: Duration = Duration::from_millis(250);
const REAPER_POLL_INTERVAL: Duration = Duration::from_millis(10);

pub(super) fn transfer_capture_worker(
    worker: JoinHandle<()>,
    stop: Arc<AtomicBool>,
    interrupt: Option<Arc<dyn super::CaptureInterrupt>>,
) {
    transfer_capture_worker_with_callback(worker, stop, interrupt, || {});
}

fn transfer_capture_worker_with_callback<F>(
    worker: JoinHandle<()>,
    stop: Arc<AtomicBool>,
    interrupt: Option<Arc<dyn super::CaptureInterrupt>>,
    after_join: F,
) where
    F: FnOnce() + Send + 'static,
{
    let _ = thread::Builder::new()
        .name("packetcraftr-capture-reaper".to_owned())
        .spawn(move || {
            stop.store(true, Ordering::Release);
            while !worker.is_finished() {
                if let Some(interrupt) = &interrupt {
                    interrupt.interrupt();
                }
                thread::park_timeout(REAPER_POLL_INTERVAL);
            }
            let _ = worker.join();
            after_join();
        })
        .expect("could not start the native capture worker reaper");
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
                        shared.set_error(LiveIoError::Capture {
                            message: format!("native capture returned an invalid frame: {error}"),
                        });
                        return;
                    }
                };
                frame.interface = Some(interface_index);
                if let Err(error) =
                    shared.enqueue(CapturedFrame::with_ingress_time(frame, packet.received_at))
                {
                    shared.set_error(error);
                    return;
                }
            }
            Ok(NativeCaptureEvent::Timeout) => {}
            Ok(NativeCaptureEvent::Closed) if stop.load(Ordering::Acquire) => break,
            Ok(NativeCaptureEvent::Closed) => {
                shared.set_error(LiveIoError::Capture {
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
