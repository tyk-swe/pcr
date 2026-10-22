// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_netio::{capture, deadline::MAX_WAIT};

use crate::clock::Clock;
use crate::providers::{PacketProviders, TransmitProviders};
use crate::{Client, Sink, Stats};
use packetcraftr_core::error::BoundaryError;

use super::{Error, Event, Report, Request, SentFrame};

impl<P: PacketProviders, K: Clock> Client<P, K> {
    /// Sends every packet the request's template expands to, `repeat` passes
    /// in expansion order, under one packet and byte budget shared by the
    /// whole operation.
    pub fn send<S>(&self, request: Request, sink: S) -> Result<Report, Error>
    where
        S: Sink<Event, Ack = ()>,
    {
        let operation = crate::engine::execution::Operation::new(self, std::time::Duration::MAX);
        self.send_in(request, sink, &operation)
    }

    pub(crate) fn send_in<S>(
        &self,
        request: Request,
        sink: S,
        operation: &crate::engine::execution::Operation,
    ) -> Result<Report, Error>
    where
        S: Sink<Event, Ack = ()>,
    {
        self.send_prepared_in(request, sink, operation, |stream, packet| {
            stream.prepare(packet)
        })
    }
}

impl<P: TransmitProviders, K: Clock> Client<P, K> {
    /// Sends numeric IP packets in explicit Layer 3 mode, requiring no capture
    /// provider. All route, MTU, policy, final-wire and cumulative budget checks
    /// are shared with `send`; this operation cannot perform neighbor discovery.
    pub fn send_layer3<S>(&self, mut request: Request, sink: S) -> Result<Report, Error>
    where
        S: Sink<Event, Ack = ()>,
    {
        if request.send.plan.link_mode == packetcraftr_netio::link::Mode::Layer2 {
            return Err(super::request::invalid(
                "link_mode",
                "send_layer3 requires Layer 3 mode",
            ));
        }
        request.send.plan.link_mode = packetcraftr_netio::link::Mode::Layer3;
        let operation = crate::engine::execution::Operation::new(self, std::time::Duration::MAX);
        self.send_prepared_in(request, sink, &operation, |stream, packet| {
            stream.prepare_layer3(packet)
        })
    }

    fn send_prepared_in<S>(
        &self,
        request: Request,
        sink: S,
        operation: &crate::engine::execution::Operation,
        mut prepare: impl FnMut(
            &mut crate::engine::preparation::Streaming<'_, P, K>,
            packetcraftr_core::packet::Packet,
        )
            -> Result<crate::engine::preparation::PreparedPacket, crate::Error>,
    ) -> Result<Report, Error>
    where
        S: Sink<Event, Ack = ()>,
    {
        let plan = super::plan::Plan::try_from(&request)?;
        let started = self.now();
        let mut stream = self.streaming_in(&request.send, plan.packet_count, operation)?;
        let mut publish = crate::engine::execution::publisher(
            &operation.runtime,
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
                .map_err(crate::Error::from)?;
            for (offset, expanded) in expansion.into_iter().enumerate() {
                stream.check()?;
                let packet = expanded.map_err(crate::Error::from)?;
                if completed > 0 {
                    stream.check()?;
                    self.clock
                        .sleep(plan.delay, &operation.deadline(self, MAX_WAIT))
                        .map_err(|source| Error::Clock {
                            source: Box::new(source),
                        })?;
                    stream.check()?;
                }
                // Route, MTU and wire authorization follow the cooperative
                // pacing wait; a prepared packet must not cross that gap.
                let prepared = prepare(&mut stream, packet)?;
                let packet = stream.transmit(prepared)?;
                completed += 1;
                bytes =
                    bytes.saturating_add(u64::try_from(packet.bytes_sent()).unwrap_or(u64::MAX));
                publish(
                    Event::Sent(SentFrame {
                        pass,
                        index: offset as u64,
                        packet,
                    }),
                    &operation.deadline(self, MAX_WAIT),
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
