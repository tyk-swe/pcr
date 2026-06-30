// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use crate::domain::command::FuzzRequest;
pub(crate) use crate::domain::command::{FuzzProtocol, FuzzStrategy};
use crate::domain::policy::TrafficPolicy;

#[derive(Debug, Clone)]
pub(crate) struct FuzzConfig {
    pub target_ip: String,
    pub target_port: Option<u16>,
    pub protocol: FuzzProtocol,
    pub strategy: FuzzStrategy,
    pub count: u64,
    pub delay_ms: u64,
    pub batch_size: usize,
    pub rate_per_sec: u64,
}

impl FuzzConfig {
    pub(crate) fn apply_traffic_policy(&mut self, policy: &TrafficPolicy) {
        self.batch_size = policy.budget.max_batch_size;
        self.rate_per_sec = policy.budget.max_rate_per_sec;
    }
}

impl TryFrom<&FuzzRequest> for FuzzConfig {
    type Error = anyhow::Error;

    fn try_from(opts: &FuzzRequest) -> Result<Self, Self::Error> {
        if opts.port.is_none()
            && (matches!(opts.protocol, FuzzProtocol::Tcp)
                || matches!(opts.protocol, FuzzProtocol::Udp))
        {
            anyhow::bail!(
                "Target port is required for TCP and UDP fuzzing. Please provide --port."
            );
        }
        Ok(Self {
            target_ip: opts.target.clone(),
            target_port: opts.port,
            protocol: opts.protocol,
            strategy: opts.strategy,
            count: opts.count,
            delay_ms: opts.delay,
            batch_size: crate::domain::policy::DEFAULT_MAX_BATCH_SIZE,
            rate_per_sec: crate::domain::policy::DEFAULT_MAX_RATE_PER_SEC,
        })
    }
}
