// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

pub const RULE_EXECUTOR_WORKERS: usize = 4;
pub const RULE_EXECUTOR_QUEUE_CAPACITY: usize = 64;
pub const RULE_COMMAND_TIMEOUT_SECONDS: u64 = 5;
pub const RULE_COMMAND_TIMEOUT_MIN_SECONDS: u64 = 1;
pub const RULE_COMMAND_TIMEOUT_MAX_SECONDS: u64 = 300;
pub const RULE_COMMAND_MAX_ARGS: usize = 64;
pub const RULE_COMMAND_MAX_ARG_LENGTH: usize = 1024;
pub const RULE_COMMAND_MAX_PROGRAM_LENGTH: usize = 512;

pub const RULE_SEND_EXECUTOR_WORKERS: usize = 4;
pub const RULE_SEND_EXECUTOR_QUEUE_CAPACITY: usize = 64;

#[derive(Debug, Clone)]
pub struct RuleExecutorConfig {
    pub workers: usize,
    pub queue_capacity: usize,
    pub traffic_policy: crate::engine::policy::TrafficPolicy,
    pub dry_run: bool,
}

impl Default for RuleExecutorConfig {
    fn default() -> Self {
        Self {
            workers: RULE_EXECUTOR_WORKERS,
            queue_capacity: RULE_EXECUTOR_QUEUE_CAPACITY,
            traffic_policy: crate::engine::policy::TrafficPolicy::default(),
            dry_run: false,
        }
    }
}

impl RuleExecutorConfig {
    pub fn from_options(
        workers: Option<usize>,
        queue_capacity: Option<usize>,
        traffic_policy: Option<crate::engine::policy::TrafficPolicy>,
        dry_run: Option<bool>,
    ) -> Self {
        let default = Self::default();
        let dry_run = dry_run.unwrap_or(default.dry_run);
        let traffic_policy = traffic_policy
            .unwrap_or(default.traffic_policy)
            .with_dry_run(dry_run);
        Self {
            workers: workers.unwrap_or(default.workers),
            queue_capacity: queue_capacity.unwrap_or(default.queue_capacity),
            traffic_policy,
            dry_run,
        }
    }
}
