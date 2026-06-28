// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use crate::engine::command::FuzzRequest;
pub use crate::engine::command::{FuzzProtocol, FuzzStrategy};
use crate::engine::policy::TrafficPolicy;

#[derive(Debug, Clone)]
pub struct FuzzConfig {
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
    pub fn apply_traffic_policy(&mut self, policy: &TrafficPolicy) {
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
            batch_size: crate::engine::policy::DEFAULT_MAX_BATCH_SIZE,
            rate_per_sec: crate::engine::policy::DEFAULT_MAX_RATE_PER_SEC,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::command::FuzzRequest;

    #[test]
    fn test_try_from_valid_tcp() {
        let opts = FuzzRequest {
            target: "127.0.0.1".to_string(),
            port: Some(80),
            protocol: FuzzProtocol::Tcp,
            strategy: FuzzStrategy::RandomPayload,
            count: 1,
            delay: 0,
        };
        let config = FuzzConfig::try_from(&opts);
        assert!(config.is_ok());
    }

    #[test]
    fn test_try_from_valid_udp() {
        let opts = FuzzRequest {
            target: "127.0.0.1".to_string(),
            port: Some(53),
            protocol: FuzzProtocol::Udp,
            strategy: FuzzStrategy::RandomPayload,
            count: 1,
            delay: 0,
        };
        let config = FuzzConfig::try_from(&opts);
        assert!(config.is_ok());
    }

    #[test]
    fn test_try_from_valid_icmp_no_port() {
        let opts = FuzzRequest {
            target: "127.0.0.1".to_string(),
            port: None,
            protocol: FuzzProtocol::Icmp,
            strategy: FuzzStrategy::RandomPayload,
            count: 1,
            delay: 0,
        };
        let config = FuzzConfig::try_from(&opts);
        assert!(config.is_ok());
    }

    #[test]
    fn test_try_from_invalid_tcp_no_port() {
        let opts = FuzzRequest {
            target: "127.0.0.1".to_string(),
            port: None,
            protocol: FuzzProtocol::Tcp,
            strategy: FuzzStrategy::RandomPayload,
            count: 1,
            delay: 0,
        };
        let config = FuzzConfig::try_from(&opts);
        assert!(config.is_err());
        assert_eq!(
            config.unwrap_err().to_string(),
            "Target port is required for TCP and UDP fuzzing. Please provide --port."
        );
    }

    #[test]
    fn test_try_from_invalid_udp_no_port() {
        let opts = FuzzRequest {
            target: "127.0.0.1".to_string(),
            port: None,
            protocol: FuzzProtocol::Udp,
            strategy: FuzzStrategy::RandomPayload,
            count: 1,
            delay: 0,
        };
        let config = FuzzConfig::try_from(&opts);
        assert!(config.is_err());
    }
}
