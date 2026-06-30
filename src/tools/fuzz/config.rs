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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::policy::TrafficBudget;

    fn request(protocol: FuzzProtocol, port: Option<u16>) -> FuzzRequest {
        FuzzRequest {
            target: "192.0.2.1".to_string(),
            port,
            protocol,
            strategy: FuzzStrategy::Boundary,
            count: 10,
            delay: 20,
        }
    }

    #[test]
    fn fuzz_config_requires_port_for_tcp_and_udp() {
        assert!(FuzzConfig::try_from(&request(FuzzProtocol::Tcp, None))
            .unwrap_err()
            .to_string()
            .contains("Target port is required"));
        assert!(FuzzConfig::try_from(&request(FuzzProtocol::Udp, None)).is_err());
        assert!(FuzzConfig::try_from(&request(FuzzProtocol::Icmp, None)).is_ok());
    }

    #[test]
    fn fuzz_config_maps_request_fields_and_defaults() {
        let config = FuzzConfig::try_from(&request(FuzzProtocol::Udp, Some(53))).unwrap();

        assert_eq!(config.target_ip, "192.0.2.1");
        assert_eq!(config.target_port, Some(53));
        assert_eq!(config.protocol, FuzzProtocol::Udp);
        assert_eq!(config.strategy, FuzzStrategy::Boundary);
        assert_eq!(config.count, 10);
        assert_eq!(config.delay_ms, 20);
        assert_eq!(
            config.batch_size,
            crate::domain::policy::DEFAULT_MAX_BATCH_SIZE
        );
        assert_eq!(
            config.rate_per_sec,
            crate::domain::policy::DEFAULT_MAX_RATE_PER_SEC
        );
    }

    #[test]
    fn apply_traffic_policy_overrides_runtime_limits() {
        let mut config = FuzzConfig::try_from(&request(FuzzProtocol::Udp, Some(53))).unwrap();
        let policy = TrafficPolicy {
            budget: TrafficBudget {
                max_batch_size: 7,
                max_rate_per_sec: 8,
                ..Default::default()
            },
            ..Default::default()
        };

        config.apply_traffic_policy(&policy);

        assert_eq!(config.batch_size, 7);
        assert_eq!(config.rate_per_sec, 8);
    }
}
