// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Instant;

use packetcraftr_core::{packet::Packet, template::Template};
use packetcraftr_netio::{capture::Statistics, transmit::Sender as PacketIo};

use crate::Client;
use crate::Error;
use crate::Stats;
use crate::clock::{CancellableClock, Clock, SystemClock};
use crate::send::{Options, Report, SentFrame, SetOptions, SetReport};

impl<R, N, I> Client<R, N, I>
where
    R: packetcraftr_netio::route::Provider,
    N: crate::neighbor::Resolver,
    I: PacketIo,
{
    pub fn send(&self, packet: Packet, options: Options) -> Result<Report, Error> {
        let started = Instant::now();
        let mut stream = self.streaming(&options, 1, None)?;
        let prepared = stream.prepare(packet)?;
        let sent = stream.transmit(prepared)?;
        let bytes_sent = sent.bytes_sent();
        Ok(Report {
            sent,
            stats: Stats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes: u64::try_from(bytes_sent).unwrap_or(u64::MAX),
                elapsed: started.elapsed(),
                capture: Statistics::default(),
            },
        })
    }

    /// Sends every packet a template expands to, `options.repeat` passes in
    /// expansion order, under one packet/byte budget shared by the whole
    /// operation. Each frame is handed to `emit` as soon as the provider
    /// confirms it, so evidence published before a failure is preserved.
    pub fn send_set_with_events<F>(
        &self,
        template: &Template,
        options: SetOptions,
        emit: F,
    ) -> Result<SetReport, Error>
    where
        F: FnMut(&SentFrame) -> Result<(), Error>,
    {
        // A cancellation-aware clock keeps long pacing delays interruptible;
        // without a signal the plain clock is equivalent.
        match &self.cancellation {
            Some(signal) => {
                self.send_set_driven(template, &options, CancellableClock(signal.clone()), emit)
            }
            None => self.send_set_driven(template, &options, SystemClock, emit),
        }
    }

    /// [`send_set_with_events`](Self::send_set_with_events) without an event
    /// sink; the returned report retains every confirmed frame.
    pub fn send_set(&self, template: &Template, options: SetOptions) -> Result<SetReport, Error> {
        self.send_set_with_events(template, options, |_| Ok(()))
    }

    /// [`send_set_with_events`](Self::send_set_with_events) with an injectable
    /// pacing clock so tests and simulations drive deterministic delays.
    pub fn send_set_driven<C, F>(
        &self,
        template: &Template,
        options: &SetOptions,
        mut clock: C,
        mut emit: F,
    ) -> Result<SetReport, Error>
    where
        C: Clock,
        C::Error: Into<Error>,
        F: FnMut(&SentFrame) -> Result<(), Error>,
    {
        let total = options.validate_for(template)?;
        let started = Instant::now();
        // Packet admission precedes provider work. Exact bytes remain a
        // cumulative per-frame budget, including link materialization.
        let mut stream = self.streaming(&options.send, total, clock.cancellation())?;
        let delay = crate::clock::rate_delay(1, options.rate)
            .expect("validate_for checked the pacing rate");

        let mut sent = Vec::new();
        for pass in 1..=options.repeat {
            let expansion = template
                .expand(options.max_template_packets)
                .map_err(|source| Error::Template {
                    message: source.to_string(),
                    source: Some(source),
                })?;
            for (offset, expanded) in expansion.into_iter().enumerate() {
                stream.check()?;
                let packet = expanded.map_err(|source| Error::Template {
                    message: source.to_string(),
                    source: Some(source),
                })?;
                let prepared = stream.prepare(packet)?;
                if !sent.is_empty() {
                    stream.check()?;
                    clock.sleep(delay).map_err(Into::into)?;
                }
                sent.push(SentFrame {
                    pass,
                    index: offset as u64,
                    packet: stream.transmit(prepared)?,
                });
                emit(sent.last().expect("frame was just recorded"))?;
            }
        }
        let bytes = crate::evidence::total_bytes_sent(sent.iter().map(|frame| &frame.packet))
            .unwrap_or(u64::MAX);
        let packets = u64::try_from(sent.len()).unwrap_or(u64::MAX);
        Ok(SetReport {
            stats: Stats {
                packets_attempted: packets,
                packets_completed: packets,
                bytes,
                elapsed: started.elapsed(),
                capture: Statistics::default(),
            },
            passes_completed: options.repeat,
            sent,
        })
    }
}
