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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_options_uses_defaults_when_none_provided() {
        let config = RuleExecutorConfig::from_options(None, None, None, None);
        let default = RuleExecutorConfig::default();
        assert_eq!(config.workers, default.workers);
        assert_eq!(config.queue_capacity, default.queue_capacity);
        assert_eq!(config.traffic_policy, default.traffic_policy);
        assert_eq!(config.dry_run, default.dry_run);
    }

    #[test]
    fn from_options_uses_provided_values() {
        let policy = crate::engine::policy::TrafficPolicy {
            allow_unbounded_sends: true,
            ..Default::default()
        };
        let config = RuleExecutorConfig::from_options(Some(10), Some(20), Some(policy), Some(true));
        assert_eq!(config.workers, 10);
        assert_eq!(config.queue_capacity, 20);
        assert!(config.traffic_policy.allow_unbounded_sends);
        assert!(config.dry_run);
        assert!(config.traffic_policy.dry_run);
    }

    #[test]
    fn from_options_mixes_provided_and_defaults() {
        let default = RuleExecutorConfig::default();
        let config_workers = RuleExecutorConfig::from_options(Some(10), None, None, None);
        assert_eq!(config_workers.workers, 10);
        assert_eq!(config_workers.queue_capacity, default.queue_capacity);
        assert_eq!(config_workers.traffic_policy, default.traffic_policy);

        let config_queue = RuleExecutorConfig::from_options(None, Some(50), None, None);
        assert_eq!(config_queue.workers, default.workers);
        assert_eq!(config_queue.queue_capacity, 50);

        let policy = crate::engine::policy::TrafficPolicy {
            allow_unbounded_sends: true,
            ..Default::default()
        };
        let config_unbounded = RuleExecutorConfig::from_options(None, None, Some(policy), None);
        assert!(config_unbounded.traffic_policy.allow_unbounded_sends);

        let config_dry_run = RuleExecutorConfig::from_options(None, None, None, Some(true));
        assert!(config_dry_run.dry_run);
        assert!(config_dry_run.traffic_policy.dry_run);
    }
}
