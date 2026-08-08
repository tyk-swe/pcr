// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native source event loop.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use crate::{Error as LiveIoError, capture::CapturedFrame};
use packetcraftr_packet::frame::{Frame, LinkType};

use super::{NativeCaptureEvent, NativeCaptureSource, queue::SharedCapture};

const STATISTICS_INTERVAL: Duration = Duration::from_millis(250);

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
