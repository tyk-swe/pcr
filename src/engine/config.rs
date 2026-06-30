// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

/// Global configuration derived from CLI arguments.
#[derive(Debug, Clone)]
pub(crate) struct EngineConfig {
    pub prometheus_bind: Option<String>,
    pub rule_workers: Option<usize>,
    pub rule_queue: Option<usize>,
    pub send_workers: Option<usize>,
    pub send_queue: Option<usize>,
    pub traffic_policy: crate::domain::policy::TrafficPolicy,
    pub dry_run: bool,
}
