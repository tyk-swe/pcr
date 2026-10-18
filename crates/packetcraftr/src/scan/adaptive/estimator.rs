// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

const RTO_GRANULARITY: Duration = Duration::from_millis(1);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Estimator {
    srtt_ns: Option<u64>,
    rttvar_ns: u64,
}

impl Estimator {
    pub(super) fn sample(&mut self, rtt: Duration) {
        let sample = u64::try_from(rtt.as_nanos()).unwrap_or(u64::MAX);
        match self.srtt_ns {
            None => {
                self.srtt_ns = Some(sample);
                self.rttvar_ns = sample / 2;
            }
            Some(srtt) => {
                let deviation = srtt.abs_diff(sample);
                self.rttvar_ns = self.rttvar_ns.saturating_mul(3).saturating_add(deviation) / 4;
                self.srtt_ns = Some(srtt.saturating_mul(7).saturating_add(sample) / 8);
            }
        }
    }

    pub(super) fn rto(&self, min: Duration, max: Duration) -> Option<Duration> {
        let srtt = self.srtt_ns?;
        let jitter = self
            .rttvar_ns
            .saturating_mul(4)
            .max(u64::try_from(RTO_GRANULARITY.as_nanos()).unwrap_or(u64::MAX));
        Some(Duration::from_nanos(srtt.saturating_add(jitter)).clamp(min, max))
    }
}
