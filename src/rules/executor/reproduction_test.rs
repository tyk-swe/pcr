// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn send_action_rejects_infinite_send_by_default() {
    let _executor_guard = test_support::executor_lock();
    let executor = RuleSendExecutor::new().expect("create executor");

    let template = RuleSendTemplate::new(PacketRequest {
        transmit: crate::engine::request::TransmissionRequest {
            loop_forever: Some(true),
            ..Default::default()
        },
        ..Default::default()
    });

    let result = executor.dispatch("infinite-rule", &template, None);
    assert!(matches!(
        result,
        Err(RuleError::Action(RuleActionError::InvalidSendMode { .. }))
    ));
}

#[test]
fn send_action_allows_infinite_send_when_configured() {
    let _executor_guard = test_support::executor_lock();
    let config = RuleExecutorConfig {
        allow_unbounded_sends: true,
        dry_run: true,
        ..Default::default()
    };
    let executor = RuleSendExecutor::new_configured(config).expect("create executor");

    let template = RuleSendTemplate::new(PacketRequest {
        transmit: crate::engine::request::TransmissionRequest {
            loop_forever: Some(true),
            ..Default::default()
        },
        ..Default::default()
    });

    // Should succeed with the flag enabled
    let result = executor.dispatch("infinite-rule", &template, None);
    assert!(result.is_ok());
}

#[test]
fn send_action_rejects_flood_without_count() {
    let _executor_guard = test_support::executor_lock();
    let executor = RuleSendExecutor::new().expect("create executor");

    let template = RuleSendTemplate::new(PacketRequest {
        transmit: crate::engine::request::TransmissionRequest {
            flood: Some(true),
            count: None,
            ..Default::default()
        },
        ..Default::default()
    });

    let result = executor.dispatch("flood-rule", &template, None);
    assert!(matches!(
        result,
        Err(RuleError::Action(RuleActionError::InvalidSendMode { .. }))
    ));
}

#[test]
fn send_action_allows_flood_with_count() {
    let _executor_guard = test_support::executor_lock();
    let config = RuleExecutorConfig {
        dry_run: true,
        ..Default::default()
    };
    let executor = RuleSendExecutor::new_configured(config).expect("create executor");

    let template = RuleSendTemplate::new(PacketRequest {
        transmit: crate::engine::request::TransmissionRequest {
            flood: Some(true),
            count: Some(3),
            ..Default::default()
        },
        ..Default::default()
    });

    let result = executor.dispatch("finite-flood-rule", &template, None);
    assert!(result.is_ok());
}

#[test]
fn send_action_rejects_zero_count() {
    let _executor_guard = test_support::executor_lock();
    let executor = RuleSendExecutor::new().expect("create executor");

    let template = RuleSendTemplate::new(PacketRequest {
        transmit: crate::engine::request::TransmissionRequest {
            count: Some(0),
            ..Default::default()
        },
        ..Default::default()
    });

    let result = executor.dispatch("zero-count-rule", &template, None);
    assert!(matches!(
        result,
        Err(RuleError::Action(RuleActionError::InvalidSendMode { .. }))
    ));
}
