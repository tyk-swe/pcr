// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

pub(crate) mod config;
pub(crate) mod engine;

use anyhow::Result;

use crate::domain::policy::{classify_ip, TrafficMode, TrafficPlan, TrafficPrivilege};

pub(crate) use config::FuzzConfig;
pub(crate) use engine::run_fuzz;

pub(crate) fn traffic_plan(config: &FuzzConfig) -> Result<TrafficPlan> {
    let target_ip: std::net::IpAddr = config.target_ip.parse()?;
    let mut plan = TrafficPlan::new(TrafficMode::Fuzz, classify_ip(target_ip));
    plan.target_count = 1;
    plan.port_count = usize::from(config.target_port.is_some()).max(1);
    plan.estimated_packets = Some(config.count);
    plan.malformed = true;
    plan.batch_size = config.batch_size.max(1);
    plan.rate_per_sec = Some(config.rate_per_sec);
    plan.required_privileges = vec![TrafficPrivilege::RawSocket];
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::command::{FuzzProtocol, FuzzStrategy};
    use crate::domain::policy::{TargetScope, TrafficPrivilege};

    fn config(target_ip: &str, target_port: Option<u16>) -> FuzzConfig {
        FuzzConfig {
            target_ip: target_ip.to_string(),
            target_port,
            protocol: FuzzProtocol::Udp,
            strategy: FuzzStrategy::RandomPayload,
            count: 25,
            delay_ms: 10,
            batch_size: 4,
            rate_per_sec: 5,
        }
    }

    #[test]
    fn traffic_plan_marks_fuzzing_as_malformed_raw_socket_traffic() {
        let plan = traffic_plan(&config("127.0.0.1", Some(53))).unwrap();

        assert_eq!(plan.mode, TrafficMode::Fuzz);
        assert_eq!(plan.target_scope, TargetScope::Local);
        assert_eq!(plan.target_count, 1);
        assert_eq!(plan.port_count, 1);
        assert_eq!(plan.estimated_packets, Some(25));
        assert!(plan.malformed);
        assert_eq!(plan.batch_size, 4);
        assert_eq!(plan.rate_per_sec, Some(5));
        assert_eq!(plan.required_privileges, vec![TrafficPrivilege::RawSocket]);
    }

    #[test]
    fn traffic_plan_treats_protocols_without_ports_as_one_port_slot() {
        let plan = traffic_plan(&config("127.0.0.1", None)).unwrap();

        assert_eq!(plan.port_count, 1);
    }

    #[test]
    fn traffic_plan_rejects_invalid_target_ip() {
        let err = traffic_plan(&config("not-an-ip", Some(53))).unwrap_err();

        assert!(err.to_string().contains("invalid IP address syntax"));
    }
}
