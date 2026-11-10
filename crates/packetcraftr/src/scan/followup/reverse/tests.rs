// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn failed_question_carries_its_error_text() {
    let error = dns::Error::InvalidPort;
    let expected = error.to_string();
    let question = batch::Question {
        query_name: "1.2.0.192.in-addr.arpa".to_owned(),
        query_type: dns::QueryType::PTR,
        transaction_id: 7,
        outcome: batch::Outcome::Failed(error),
    };
    let lookup = ReverseLookup::from(question);
    assert_eq!(lookup.status, batch::QuestionStatus::Failed);
    assert_eq!(lookup.outcome, None);
    assert_eq!(lookup.error.as_deref(), Some(expected.as_str()));
    assert!(lookup.names.is_empty());
}
