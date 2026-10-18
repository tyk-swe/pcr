// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod charge;
mod controller;
mod estimator;
mod work;

pub(super) use charge::{scoped_bytes, state_charge};
pub(super) use controller::{Controller, Outcome};
pub(super) use work::{Selection, Work};

use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use packetcraftr_netio::deadline::MAX_WAIT;

use crate::execution::limits::duration_violation;
use crate::target::ResolvedZone;

use super::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Adaptive {
    pub min_timeout: Duration,
    pub max_timeout: Duration,
    pub min_window: usize,
    pub initial_window: usize,
    pub host_timeout: Duration,
    pub retry_backoff: Duration,
    pub max_backoff: Duration,
}

impl Adaptive {
    pub(crate) fn validate(&self, request: &super::Request) -> Result<(), Error> {
        for value in [
            self.min_timeout,
            self.max_timeout,
            self.host_timeout,
            self.retry_backoff,
            self.max_backoff,
        ] {
            if duration_violation(value, MAX_WAIT) {
                return Err(Error::InvalidDuration {
                    value,
                    maximum: MAX_WAIT,
                });
            }
        }
        if !(self.min_timeout <= request.timeout && request.timeout <= self.max_timeout) {
            return Err(Error::InvalidTimeout {
                value: request.timeout,
                maximum: self.max_timeout.max(self.min_timeout),
            });
        }
        let invalid = |field: &'static str, value: usize, reason: String| {
            Err(Error::InvalidLimit {
                field,
                value: value as u64,
                reason,
            })
        };
        if self.min_window == 0 || self.initial_window < self.min_window {
            return invalid(
                "min_window",
                self.min_window,
                format!(
                    "must satisfy 1 <= min_window <= initial_window={}",
                    self.initial_window
                ),
            );
        }
        if self.initial_window > request.max_in_flight {
            return invalid(
                "initial_window",
                self.initial_window,
                format!("must not exceed max_in_flight={}", request.max_in_flight),
            );
        }
        if self.host_timeout > request.limits.max_duration {
            return Err(Error::InvalidDuration {
                value: self.host_timeout,
                maximum: request.limits.max_duration,
            });
        }
        if self.retry_backoff > self.max_backoff {
            return Err(Error::InvalidDuration {
                value: self.retry_backoff,
                maximum: self.max_backoff,
            });
        }
        Ok(())
    }

    pub(crate) fn retry_delay(&self, next_attempt: u32) -> Duration {
        let shift = next_attempt.saturating_sub(2).min(31);
        self.retry_backoff
            .saturating_mul(1u32 << shift)
            .min(self.max_backoff)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SchedulingMode {
    #[default]
    Fixed,
    Adaptive,
}

impl SchedulingMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixed => "fixed",
            Self::Adaptive => "adaptive",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostIdentity {
    pub address: IpAddr,
    pub scope: Option<ResolvedZone>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConditionKind {
    SuspectedResponseRateLimit,
}

impl ConditionKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SuspectedResponseRateLimit => "suspected_response_rate_limit",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Condition {
    pub kind: ConditionKind,
    pub host: HostIdentity,
    pub control_responder: IpAddr,
    pub completed: u64,
    pub replies: u64,
    pub losses: u64,
    pub control_sequences: Vec<u64>,
    pub loss_sequences: Vec<u64>,
    pub caveat: &'static str,
}

#[derive(Clone, Debug, Default)]
pub struct Scheduling {
    pub mode: SchedulingMode,
    pub adaptive: Option<Adaptive>,
    pub observed_peak_window: usize,
    pub retries_started: u64,
    pub conditions: Vec<Condition>,
    pub incomplete: Vec<HostIdentity>,
    pub operation_ceiling: Option<usize>,
    pub process_ceiling: Option<usize>,
}

#[derive(Clone, Copy, Debug, Default)]
pub(in crate::scan) struct Ceilings {
    pub(in crate::scan) operation: Option<usize>,
    pub(in crate::scan) process: Option<usize>,
}

pub(super) fn fixed_scheduling(
    ceilings: Ceilings,
    peak: usize,
    retries_started: usize,
) -> Scheduling {
    Scheduling {
        mode: SchedulingMode::Fixed,
        adaptive: None,
        observed_peak_window: peak,
        retries_started: retries_started as u64,
        conditions: Vec::new(),
        incomplete: Vec::new(),
        operation_ceiling: ceilings.operation,
        process_ceiling: ceilings.process,
    }
}

#[cfg(test)]
#[path = "adaptive/tests.rs"]
mod tests;
