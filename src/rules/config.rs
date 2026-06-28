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

#[derive(Debug, Clone, Copy)]
pub struct RuleExecutorConfig {
    pub workers: usize,
    pub queue_capacity: usize,
    pub allow_unbounded_sends: bool,
    pub dry_run: bool,
}

impl Default for RuleExecutorConfig {
    fn default() -> Self {
        Self {
            workers: RULE_EXECUTOR_WORKERS,
            queue_capacity: RULE_EXECUTOR_QUEUE_CAPACITY,
            allow_unbounded_sends: false,
            dry_run: false,
        }
    }
}

impl RuleExecutorConfig {
    pub fn from_options(
        workers: Option<usize>,
        queue_capacity: Option<usize>,
        allow_unbounded_sends: Option<bool>,
        dry_run: Option<bool>,
    ) -> Self {
        let default = Self::default();
        Self {
            workers: workers.unwrap_or(default.workers),
            queue_capacity: queue_capacity.unwrap_or(default.queue_capacity),
            allow_unbounded_sends: allow_unbounded_sends.unwrap_or(default.allow_unbounded_sends),
            dry_run: dry_run.unwrap_or(default.dry_run),
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
        assert_eq!(config.allow_unbounded_sends, default.allow_unbounded_sends);
        assert_eq!(config.dry_run, default.dry_run);
    }

    #[test]
    fn from_options_uses_provided_values() {
        let config = RuleExecutorConfig::from_options(Some(10), Some(20), Some(true), Some(true));
        assert_eq!(config.workers, 10);
        assert_eq!(config.queue_capacity, 20);
        assert!(config.allow_unbounded_sends);
        assert!(config.dry_run);
    }

    #[test]
    fn from_options_mixes_provided_and_defaults() {
        let default = RuleExecutorConfig::default();
        let config_workers = RuleExecutorConfig::from_options(Some(10), None, None, None);
        assert_eq!(config_workers.workers, 10);
        assert_eq!(config_workers.queue_capacity, default.queue_capacity);
        assert_eq!(
            config_workers.allow_unbounded_sends,
            default.allow_unbounded_sends
        );

        let config_queue = RuleExecutorConfig::from_options(None, Some(50), None, None);
        assert_eq!(config_queue.workers, default.workers);
        assert_eq!(config_queue.queue_capacity, 50);

        let config_unbounded = RuleExecutorConfig::from_options(None, None, Some(true), None);
        assert!(config_unbounded.allow_unbounded_sends);

        let config_dry_run = RuleExecutorConfig::from_options(None, None, None, Some(true));
        assert!(config_dry_run.dry_run);
    }
}
