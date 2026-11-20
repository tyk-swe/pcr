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

#[test]
fn short_lookup_window_leaves_questions_unattempted() {
    let server = "192.0.2.53".parse().unwrap();
    let (client, sends) = crate::engine::operation::testing::client(server);
    let lookup = Lookup {
        template: dns::Request {
            server: Target::Address(server),
            address_family: crate::target::Family::Any,
            server_port: 53,
            source_port: 12_345,
            query_name: String::new(),
            query_type: dns::QueryType::PTR,
            transaction_id: 7,
            recursion_desired: true,
            edns: None,
            transport: dns::TransportMode::Udp,
            attempts: 2,
            timeout: Duration::from_millis(250),
            queries_per_second: None,
            limits: dns::Limits {
                max_duration: Duration::from_secs(30),
                ..dns::Limits::default()
            },
            route: crate::route::Options::default(),
            collection: crate::exchange::Collection::default(),
        },
    };
    let mut operation =
        crate::engine::operation::Operation::new(&client, lookup.template.limits.max_duration);
    let addresses = ["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()];
    let (lookups, stats, last_sent) = lookup
        .lookup(
            &client,
            &mut operation,
            &addresses,
            lookup.template.timeout / 2,
        )
        .unwrap();
    assert_eq!(lookups.len(), addresses.len());
    for (lookup, address) in lookups.iter().zip(addresses) {
        assert_eq!(lookup.query_name, dns::reverse_name(address));
        assert_eq!(lookup.status, batch::QuestionStatus::Unattempted);
        assert_eq!(lookup.error, None);
        assert_eq!(lookup.outcome, None);
    }
    assert_eq!(stats, Stats::default());
    assert_eq!(last_sent, None);
    assert_eq!(sends.load(std::sync::atomic::Ordering::Relaxed), 0);
}
