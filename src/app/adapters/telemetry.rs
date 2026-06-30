// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use crate::engine::ports::RuleActionTelemetry;

#[derive(Debug, Default)]
pub(crate) struct UtilRuleActionTelemetry;

impl RuleActionTelemetry for UtilRuleActionTelemetry {
    fn record_rule_action(&self, action: &'static str, status: &'static str) {
        crate::util::telemetry::record_rule_action(action, status);
    }

    fn record_rule_executor_drop(&self, action: &'static str, reason: &'static str) {
        crate::util::telemetry::record_rule_executor_drop(action, reason);
    }
}
