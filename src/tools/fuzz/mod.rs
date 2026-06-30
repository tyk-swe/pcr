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
