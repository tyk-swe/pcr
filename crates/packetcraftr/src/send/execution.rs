// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::Instant;

use packetcraftr_core::{budget::Deadline, build::Builder, packet::Packet, template::Template};
use packetcraftr_netio::{
    capture::Statistics,
    transmit::{Frame as TransmissionFrame, Sender as PacketIo},
};

use crate::Client;
use crate::Error;
use crate::Stats;
use crate::clock::{CancellableClock, Clock, SystemClock};
use crate::probe::live_step::Pacer;
use crate::send::{Options, Report, SentFrame, SetOptions, SetReport};

impl<R, N, I> Client<R, N, I>
where
    R: packetcraftr_netio::route::Provider,
    N: packetcraftr_netio::neighbor::Resolver,
    I: PacketIo,
{
    pub fn send(&self, packet: Packet, options: Options) -> Result<Report, Error> {
        self.check_cancelled()?;
        let started = Instant::now();
        self.policy.authorize(crate::policy::Operation::Budgeted(
            crate::policy::WireBudget::new(1, 0),
        ))?;
        let plan = self.plan(&packet, options.destination, &options.plan)?;
        let builder = Builder::new(Arc::clone(&self.registry));
        // Validate and authorize every packet field before neighbor discovery
        // emits traffic.
        let planned = self.plan_and_authorize(packet, plan, &builder, &options, None)?;
        self.policy.authorize(crate::policy::Operation::Budgeted(
            crate::policy::WireBudget::new(
                1,
                u64::try_from(planned.preliminary_build.bytes.len()).unwrap_or(u64::MAX),
            ),
        ))?;
        let prepared = self.materialize_and_authorize(planned, &builder, &options, None)?;
        // Link-layer synthesis is already included in the exact build. The
        // typed frame selects the matching native provider boundary.
        self.check_cancelled()?;
        let io_report = self.io.send(TransmissionFrame::try_new(
            &prepared.built.bytes,
            &prepared.route,
        )?)?;
        let sent = crate::SentPacket::try_new(prepared.built, prepared.route, io_report)?;
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
        let cancellation = clock.cancellation();
        let check_cancelled = || -> Result<(), Error> {
            self.check_cancelled()?;
            if let Some(signal) = &cancellation {
                signal.check()?;
            }
            Ok(())
        };
        check_cancelled()?;
        let started = Instant::now();
        // Packet admission precedes provider work. Exact bytes remain a
        // cumulative per-frame budget, including link materialization.
        self.policy.authorize(crate::policy::Operation::Budgeted(
            crate::policy::WireBudget::new(total, 0),
        ))?;
        let delay = Pacer::delay(1, options.rate).expect("validate_for checked the pacing rate");
        // Send sets have no duration ceiling; the pacer still enforces the
        // operation's cancellation across each delay without changing the
        // send loop or its wall-clock report.
        let mut pacing_deadline = Deadline::new(std::time::Duration::MAX)
            .with_cancellation(self.cancellation.clone().or(cancellation.clone()));

        let builder = Builder::new(Arc::clone(&self.registry));
        let mut sent = Vec::new();
        let mut total_bytes = 0_u64;
        for pass in 1..=options.repeat {
            let expansion = template
                .expand(options.max_template_packets)
                .map_err(|source| Error::Template {
                    message: source.to_string(),
                    source: Some(source),
                })?;
            for (offset, expanded) in expansion.into_iter().enumerate() {
                check_cancelled()?;
                let packet = expanded.map_err(|source| Error::Template {
                    message: source.to_string(),
                    source: Some(source),
                })?;
                let plan = self.plan(&packet, options.send.destination, &options.send.plan)?;
                let planned =
                    self.plan_and_authorize(packet, plan, &builder, &options.send, None)?;
                // The cumulative packet and exact wire-byte totals are
                // re-authorized before every transmission.
                total_bytes = total_bytes
                    .checked_add(
                        u64::try_from(planned.preliminary_build.bytes.len()).unwrap_or(u64::MAX),
                    )
                    .ok_or(crate::policy::Error::ByteLimit {
                        actual: u64::MAX,
                        limit: self.policy.max_bytes_per_operation,
                    })?;
                self.policy.authorize(crate::policy::Operation::Budgeted(
                    crate::policy::WireBudget::new(
                        u64::try_from(sent.len()).unwrap_or(u64::MAX) + 1,
                        total_bytes,
                    ),
                ))?;
                check_cancelled()?;
                let prepared =
                    self.materialize_and_authorize(planned, &builder, &options.send, None)?;
                check_cancelled()?;
                if !sent.is_empty() {
                    Pacer::wait(
                        &mut pacing_deadline,
                        &mut clock,
                        delay,
                        pacing_interrupted,
                        pacing_duration,
                        Into::into,
                    )?;
                    check_cancelled()?;
                }
                let io_report = self.io.send(TransmissionFrame::try_new(
                    &prepared.built.bytes,
                    &prepared.route,
                )?)?;
                sent.push(SentFrame {
                    pass,
                    index: offset as u64,
                    packet: crate::SentPacket::try_new(prepared.built, prepared.route, io_report)?,
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

fn pacing_interrupted(source: packetcraftr_core::budget::Interrupted) -> Error {
    match source {
        packetcraftr_core::budget::Interrupted::Cancelled(source) => source.into(),
        packetcraftr_core::budget::Interrupted::Exceeded(source) => pacing_duration(source),
        _ => Error::InvalidSendOption {
            field: "rate",
            message: "pacing was interrupted".to_owned(),
        },
    }
}

fn pacing_duration(source: packetcraftr_core::budget::DeadlineExceeded) -> Error {
    Error::InvalidSendOption {
        field: "rate",
        message: format!("pacing exceeded its operation budget: {source}"),
    }
}
