// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use crate::rules::model::{PacketContext, RuleLogLevel};
use log::{debug, error, info, trace, warn};
use std::borrow::Cow;

pub fn log_message(level: RuleLogLevel, rule_name: &str, message: &str) {
    match level {
        RuleLogLevel::Trace => trace!("rule '{}': {}", rule_name, message),
        RuleLogLevel::Debug => debug!("rule '{}': {}", rule_name, message),
        RuleLogLevel::Info => info!("rule '{}': {}", rule_name, message),
        RuleLogLevel::Warn => warn!("rule '{}': {}", rule_name, message),
        RuleLogLevel::Error => error!("rule '{}': {}", rule_name, message),
    }
}

pub fn apply_template(template: &str, packet: Option<&PacketContext>) -> String {
    let mut result = String::with_capacity(template.len() + 128);
    let mut cursor = 0;

    while let Some(start) = template[cursor..].find('{') {
        let match_index = cursor + start;
        result.push_str(&template[cursor..match_index]);

        let remainder = &template[match_index..];

        if remainder.starts_with("{description}") {
            match packet {
                Some(ctx) => result.push_str(&sanitize_input(&ctx.description)),
                None => result.push_str("<unknown>"),
            }
            cursor = match_index + "{description}".len();
        } else if remainder.starts_with("{source}") {
            match packet.and_then(|ctx| ctx.source.as_deref()) {
                Some(s) => result.push_str(&sanitize_input(s)),
                None => result.push_str("<unknown>"),
            }
            cursor = match_index + "{source}".len();
        } else if remainder.starts_with("{destination}") {
            match packet.and_then(|ctx| ctx.destination.as_deref()) {
                Some(s) => result.push_str(&sanitize_input(s)),
                None => result.push_str("<unknown>"),
            }
            cursor = match_index + "{destination}".len();
        } else if remainder.starts_with("{length}") {
            match packet {
                Some(ctx) => {
                    use std::fmt::Write;
                    let _ = write!(result, "{}", ctx.length);
                }
                None => result.push_str("<unknown>"),
            }
            cursor = match_index + "{length}".len();
        } else if remainder.starts_with("{timestamp}") {
            match packet {
                Some(ctx) => {
                    use std::fmt::Write;
                    let _ = write!(result, "{}", humantime::format_rfc3339(ctx.timestamp));
                }
                None => result.push_str("<unknown>"),
            }
            cursor = match_index + "{timestamp}".len();
        } else {
            result.push('{');
            cursor = match_index + 1;
        }
    }

    result.push_str(&template[cursor..]);
    result
}

fn sanitize_input(input: &str) -> Cow<'_, str> {
    // Retain only non-control characters to prevent log injection (e.g. newlines)
    // and argument confusion.
    if input.chars().any(|c| c.is_control()) {
        Cow::Owned(input.chars().filter(|c| !c.is_control()).collect())
    } else {
        Cow::Borrowed(input)
    }
}

pub fn render_option(field: &mut Option<String>, packet: Option<&PacketContext>) {
    if let Some(value) = field.as_mut() {
        let rendered = apply_template(value, packet);
        *value = rendered;
    }
}
