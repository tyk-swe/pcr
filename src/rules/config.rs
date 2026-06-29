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

#[derive(Debug, Clone)]
pub struct RuleExecutorConfig {
    pub workers: usize,
    pub queue_capacity: usize,
}

impl Default for RuleExecutorConfig {
    fn default() -> Self {
        Self {
            workers: RULE_EXECUTOR_WORKERS,
            queue_capacity: RULE_EXECUTOR_QUEUE_CAPACITY,
        }
    }
}

impl RuleExecutorConfig {
    pub fn from_options(workers: Option<usize>, queue_capacity: Option<usize>) -> Self {
        let default = Self::default();
        Self {
            workers: workers.unwrap_or(default.workers),
            queue_capacity: queue_capacity.unwrap_or(default.queue_capacity),
        }
    }
}
