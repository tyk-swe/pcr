// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

pub mod dns;
#[cfg(feature = "fuzz")]
pub mod fuzz;
#[cfg(any(feature = "scan", feature = "traceroute"))]
pub(crate) mod probe;
#[cfg(feature = "scan")]
pub mod scan;
#[cfg(feature = "traceroute")]
pub mod traceroute;

use std::time::Duration;

use crate::domain::policy::TrafficPolicy;

#[derive(Debug, Clone, Copy)]
pub struct TrafficRuntimeConfig {
    pub batch_size: usize,
    pub send_delay: Option<Duration>,
}

impl TrafficRuntimeConfig {
    pub fn from_policy(policy: &TrafficPolicy) -> Self {
        Self {
            batch_size: policy.budget.max_batch_size,
            send_delay: policy.rate_delay(),
        }
    }
}
