// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

pub(crate) mod dns;
#[cfg(feature = "fuzz")]
pub(crate) mod fuzz;
#[cfg(any(feature = "scan", feature = "traceroute"))]
pub(crate) mod probe;
#[cfg(feature = "scan")]
pub(crate) mod scan;
#[cfg(feature = "traceroute")]
pub(crate) mod traceroute;

#[cfg(feature = "scan")]
use std::time::Duration;

#[cfg(feature = "scan")]
use crate::domain::policy::TrafficPolicy;

#[cfg(feature = "scan")]
#[derive(Debug, Clone, Copy)]
pub(crate) struct TrafficRuntimeConfig {
    pub batch_size: usize,
    pub send_delay: Option<Duration>,
}

#[cfg(feature = "scan")]
impl TrafficRuntimeConfig {
    pub(crate) fn from_policy(policy: &TrafficPolicy) -> Self {
        Self {
            batch_size: policy.budget.max_batch_size,
            send_delay: policy.rate_delay(),
        }
    }
}
