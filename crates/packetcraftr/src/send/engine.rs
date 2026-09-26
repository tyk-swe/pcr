// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_netio::capture::{self, MAX_TIMEOUT};

use crate::clock::Clock;
use crate::providers::Providers;
use crate::{Client, Sink, Stats};
use packetcraftr_core::error::BoundaryError;

use super::{Error, Event, Report, Request, SentFrame};

impl<P: Providers, K: Clock> Client<P, K> {
    /// Sends every packet the request's template expands to, `repeat` passes
    /// in expansion order, under one packet and byte budget shared by the
    /// whole operation.
    ///
    /// The count-only budget is authorized before any provider is consulted,
    /// and each packet then passes staged preparation just before it is
    /// transmitted. Each confirmed frame is published to `sink` on a worker
    /// admitted by the client's runtime, and the send waits for the sink's
    /// answer before it transmits the next frame, so evidence published
    /// before a failure is preserved. Pacing delays run on the client's clock.
    ///
    /// # Errors
    ///
    /// Returns the invalid request, the preparation or provider failure, the
    /// sink's failure, or the clock's failure.
    pub fn send<S>(&self, request: Request, sink: S) -> Result<Report, Error>
    where
        S: Sink<Event, Ack = ()>,
    {
        let total = request.packet_count()?;
        let delay = request.delay()?;
        let started = self.now();
        let mut stream = self.streaming(&request.send, total)?;
        let mut publish = crate::execution::publisher(
            &self.runtime,
            sink,
            |deadline| Error::Output {
                source: BoundaryError::from_error(deadline),
            },
            |source| Error::Output { source },
        )?;

        let mut completed = 0_u64;
        let mut bytes = 0_u64;
        for pass in 1..=request.repeat {
            let expansion = request
                .template
                .expand(request.max_template_packets)
                .map_err(template_error)?;
            for (offset, expanded) in expansion.into_iter().enumerate() {
                stream.check()?;
                let prepared = stream.prepare(expanded.map_err(template_error)?)?;
                if completed > 0 {
                    stream.check()?;
                    self.clock
                        .sleep(delay, &self.deadline(MAX_TIMEOUT))
                        .map_err(|source| Error::Clock {
                            source: Box::new(source),
                        })?;
                }
                let packet = stream.transmit(prepared)?;
                completed += 1;
                bytes =
                    bytes.saturating_add(u64::try_from(packet.bytes_sent()).unwrap_or(u64::MAX));
                // Each event gets the longest wait a workflow has, carrying
                // the client's cancellation.
                publish(
                    Event::Sent(SentFrame {
                        pass,
                        index: offset as u64,
                        packet,
                    }),
                    &self.deadline(MAX_TIMEOUT),
                )?;
            }
        }
        Ok(Report {
            passes_completed: request.repeat,
            stats: Stats {
                packets_attempted: completed,
                packets_completed: completed,
                bytes,
                elapsed: self.now().saturating_duration_since(started),
                capture: capture::Stats::default(),
            },
        })
    }
}

fn template_error(source: packetcraftr_core::template::Error) -> crate::Error {
    crate::Error::Template {
        message: source.to_string(),
        source: Some(source),
    }
}
