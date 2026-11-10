// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;

use super::prepare_with_events;
use crate::budget::Deadline;
use crate::expression;
use crate::fuzz::{Case, Limits, Request, Stats, Strategy};
use crate::protocol::builtin;

fn prepare(request: &Request) -> (Vec<Case>, Result<Stats, crate::fuzz::Error>) {
    let registry = builtin::registry();
    let packet = expression::parse(
        "ipv4(src=192.0.2.1,dst=192.0.2.2)/udp(sport=12345,dport=9)/raw(text=hello)",
        &registry,
        expression::Limits::default(),
    )
    .unwrap();
    let mut deadline = Deadline::new(request.limits.max_duration);
    let mut cases = Vec::new();
    let result = prepare_with_events(request, packet, registry, &mut deadline, &mut |case, _| {
        cases.push(case);
        Ok(())
    });
    (cases, result)
}

fn prepared_cases(request: &Request) -> (Vec<Case>, Stats) {
    let (cases, result) = prepare(request);
    (cases, result.unwrap())
}

fn fingerprint(cases: &[Case]) -> Vec<(u64, u64, crate::fuzz::Mutation, Vec<crate::field::Value>)> {
    cases
        .iter()
        .map(|case| {
            (
                case.index,
                case.seed,
                case.mutation.clone(),
                case.shrink_values.clone(),
            )
        })
        .collect()
}

fn byte_limited_request(max_total_bytes: usize) -> Request {
    Request {
        seed: 0x5eed,
        cases: 1,
        strategies: vec![Strategy::Random],
        limits: Limits {
            max_total_bytes,
            max_packet_bytes: max_total_bytes,
            ..Limits::default()
        },
        build: crate::build::Options {
            limits: crate::packet::Limits {
                max_packet_size: max_total_bytes,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Request::default()
    }
}

#[test]
fn preparation_fails_when_retained_bytes_exceed_the_limit() {
    let (cases, result) = prepare(&byte_limited_request(100));
    assert!(cases.is_empty());
    let crate::fuzz::Error::ByteLimit { actual, limit } = result.unwrap_err() else {
        panic!("expected a byte-limit error");
    };
    assert_eq!(limit, 100);
    assert!(actual > limit);

    let (cases, result) = prepare(&byte_limited_request(usize::try_from(actual).unwrap()));
    assert_eq!(cases.len(), 1);
    assert!(result.is_ok());
}

#[test]
fn preparation_reproduces_requested_case_count() {
    let requested = 5;
    let request = Request {
        seed: 0x5eed,
        first_case: 3,
        cases: requested,
        strategies: vec![Strategy::Random],
        limits: Limits {
            max_shrink_steps: 2,
            ..Limits::default()
        },
        ..Request::default()
    };

    let (cases, stats) = prepared_cases(&request);
    assert_eq!(cases.len(), requested);
    assert_eq!(stats.cases_generated, requested as u64);
    assert_eq!(
        cases.iter().map(|case| case.index).collect::<Vec<_>>(),
        (request.first_case..request.first_case + requested as u64).collect::<Vec<_>>()
    );
    assert_eq!(
        cases
            .iter()
            .map(|case| case.seed)
            .collect::<BTreeSet<_>>()
            .len(),
        requested
    );
    assert!(cases.iter().all(|case| case.operation_seed == request.seed));
    assert!(
        cases
            .iter()
            .all(|case| case.shrink_values.len() <= request.limits.max_shrink_steps)
    );

    let (again, _) = prepared_cases(&request);
    assert_eq!(fingerprint(&cases), fingerprint(&again));
}
