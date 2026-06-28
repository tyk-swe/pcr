// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use log::warn;

use crate::rules::error::RuleActionError;
use crate::rules::model::{PacketContext, RuleLogLevel};
use crate::rules::template::{apply_template, log_message};

pub(super) fn validate_message(message: &str) -> std::result::Result<(), RuleActionError> {
    if message.trim().is_empty() {
        Err(RuleActionError::EmptyLogMessage)
    } else {
        Ok(())
    }
}

pub(super) fn execute(
    rule_name: &str,
    packet: Option<&PacketContext>,
    level: RuleLogLevel,
    message: &str,
) {
    let rendered = apply_template(message, packet);
    if rendered.trim().is_empty() {
        warn!(
            "rule '{}' log action ignored: empty message after template application",
            rule_name
        );
        return;
    }

    log_message(level, rule_name, &rendered);
}
