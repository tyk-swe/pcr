// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::rules::model::PacketContext;
use packetcraftr::rules::send::{RuleSendDispatcher, RuleSendTemplate};
use packetcraftr::rules::{RuleEngine, RuleError};

#[derive(Debug)]
struct TestRuleSender;

impl RuleSendDispatcher for TestRuleSender {
    fn dispatch(
        &self,
        _rule_name: &str,
        _template: &RuleSendTemplate,
        _packet: Option<&PacketContext>,
    ) -> Result<(), RuleError> {
        Ok(())
    }
}

#[test]
fn rule_sender_contract_is_publicly_implementable() {
    let mut rules = RuleEngine::new().expect("rule engine should initialize");

    rules.configure_sender(TestRuleSender);
}
