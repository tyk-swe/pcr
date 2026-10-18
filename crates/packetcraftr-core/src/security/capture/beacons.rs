// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Connection-attempt deduplication and periodicity evaluation.

use super::{BeaconOptions, Collector, Finding, Severity, sample};
use crate::{
    analysis::{self, FrameRecord},
    budget::Deadline,
    error::BoundaryError,
    protocol::transport::Tcp,
};
use serde_json::json;
use std::time::UNIX_EPOCH;

impl Collector {
    pub(super) fn beacon(&mut self, r: &FrameRecord<'_>) -> Result<(), BoundaryError> {
        let Some(tcp) = r.tcp else { return Ok(()) };
        let Some(c) = tcp.conversation else {
            return Ok(());
        };
        if tcp.header.flags & (Tcp::RST | Tcp::FIN) != 0 {
            self.syns.remove(c.flow);
            self.syns.remove(&c.flow.reverse());
        }
        if tcp.header.flags & (Tcp::SYN | Tcp::ACK) != Tcp::SYN {
            return Ok(());
        }
        if self
            .syns
            .get(c.flow)
            .is_some_and(|seen| seen.contains(&tcp.header.sequence))
        {
            return Ok(());
        }
        self.charge()?;
        self.syns
            .entry(c.flow.clone())
            .or_default()
            .insert(tcp.header.sequence);
        let Ok(time) = r.timestamp.duration_since(UNIX_EPOCH) else {
            self.report
                .completeness
                .note("beacon timestamp unavailable");
            return Ok(());
        };
        let key = (
            c.flow.scope.get(),
            c.flow.flow.source,
            c.flow.flow.destination,
            c.flow.flow.destination_port,
        );
        if !self.beacons.contains_key(&key) {
            self.group()?;
        }
        let g = self.beacons.entry(key).or_default();
        g.times.push(time.as_secs_f64());
        sample(
            &mut g.frames,
            &r.tcp_sources()
                .map_or_else(|| vec![r.number], |s| s.iter().map(|f| f.number).collect()),
        );
        Ok(())
    }
    pub(super) fn finish_beacons(
        &mut self,
        o: BeaconOptions,
        run: &analysis::Summary,
        deadline: &Deadline,
    ) -> Result<(), BoundaryError> {
        self.report.measurements.insert("thresholds".into(), json!({"min_attempts":o.min_attempts,"min_interval_seconds":o.min_interval_seconds,"max_cv":o.max_cv}));
        for ((scope, src, dst, port), g) in std::mem::take(&mut self.beacons) {
            deadline.enforce().map_err(BoundaryError::from_error)?;
            if run.clock.regressions > 0 || g.times.len() < o.min_attempts {
                continue;
            }
            let intervals: Vec<_> = g.times.windows(2).map(|w| w[1] - w[0]).collect();
            let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
            if mean < o.min_interval_seconds || intervals.iter().any(|x| *x <= 0.0) {
                continue;
            }
            let sd = (intervals.iter().map(|i| (i - mean).powi(2)).sum::<f64>()
                / intervals.len() as f64)
                .sqrt();
            let cv = sd / mean;
            if cv <= o.max_cv {
                let mut f = Finding::new(
                    "traffic.periodic_connections",
                    Severity::Medium,
                    format!("{src} → {dst}:{port}"),
                    "Regularly spaced TCP connection attempts",
                    json!({"scope":scope,"source":src,"destination":dst,"destination_port":port,"attempts":g.times.len(),"mean_interval_seconds":mean,"standard_deviation_seconds":sd,"coefficient_of_variation":cv,"min_interval_seconds":intervals.iter().copied().fold(f64::INFINITY, f64::min),"max_interval_seconds":intervals.iter().copied().fold(0.0, f64::max),"frames_sampled":true}),
                    "Correlate periodic traffic with the originating process and expected scheduled activity.",
                );
                f.frames = g.frames;
                self.add(f)?;
            }
        }
        Ok(())
    }
}
