// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Inference, Rule, State, connect, raw};
use crate::probe::Transport;
use crate::scan::Reply::{
    self, IcmpAdministrativelyProhibited, IcmpDestinationUnreachable, IcmpEchoReply,
    IcmpPortUnreachable, IcmpTimeExceeded, TcpOther, TcpReset, TcpSynAck, UdpPayload,
};
use crate::scan::connect::Outcome;

fn inferred(transport: Transport, attempts: &[(u64, Option<Reply>)]) -> Inference {
    raw(transport, attempts.iter().copied()).expect("port transports infer")
}

#[test]
fn every_reply_follows_its_method_rule_table() {
    use Rule::{
        SynAck, SynIcmpUnreachable, SynReset, SynSilence, SynTimeExceeded, SynUnclassifiedReply,
        UdpIcmpUnreachable, UdpPortUnreachable, UdpReply, UdpSilence, UdpTimeExceeded,
        UdpUnclassifiedReply,
    };
    let replies = [
        None,
        Some(TcpSynAck),
        Some(TcpReset),
        Some(TcpOther),
        Some(UdpPayload),
        Some(IcmpEchoReply),
        Some(IcmpPortUnreachable),
        Some(IcmpAdministrativelyProhibited),
        Some(IcmpDestinationUnreachable),
        Some(IcmpTimeExceeded),
    ];
    let tcp = [
        SynSilence,
        SynAck,
        SynReset,
        SynUnclassifiedReply,
        SynUnclassifiedReply,
        SynUnclassifiedReply,
        SynIcmpUnreachable,
        SynIcmpUnreachable,
        SynIcmpUnreachable,
        SynTimeExceeded,
    ];
    let udp = [
        UdpSilence,
        UdpUnclassifiedReply,
        UdpUnclassifiedReply,
        UdpUnclassifiedReply,
        UdpReply,
        UdpUnclassifiedReply,
        UdpPortUnreachable,
        UdpIcmpUnreachable,
        UdpIcmpUnreachable,
        UdpTimeExceeded,
    ];
    for (transport, rules) in [(Transport::Tcp, tcp), (Transport::Udp, udp)] {
        for (reply, rule) in replies.into_iter().zip(rules) {
            assert_eq!(
                inferred(transport, &[(7, reply)]),
                Inference {
                    state: rule.state(),
                    rule,
                    supporting: vec![7],
                    conflicting: Vec::new(),
                    unanswered: Vec::new(),
                    failed: Vec::new(),
                },
                "{transport} {reply:?}"
            );
        }
    }
}

#[test]
fn rules_conclude_the_documented_states() {
    let cases = [
        (Rule::SynAck, State::Open),
        (Rule::SynReset, State::Closed),
        (Rule::SynIcmpUnreachable, State::Filtered),
        (Rule::SynTimeExceeded, State::Filtered),
        (Rule::SynUnclassifiedReply, State::Unknown),
        (Rule::SynSilence, State::Filtered),
        (Rule::UdpReply, State::Open),
        (Rule::UdpPortUnreachable, State::Closed),
        (Rule::UdpIcmpUnreachable, State::Filtered),
        (Rule::UdpTimeExceeded, State::Filtered),
        (Rule::UdpUnclassifiedReply, State::Unknown),
        (Rule::UdpSilence, State::OpenOrFiltered),
        (Rule::ConnectConnected, State::Open),
        (Rule::ConnectRefused, State::Closed),
        (Rule::ConnectUnreachable, State::Filtered),
        (Rule::ConnectTimedOut, State::Filtered),
    ];
    for (rule, state) in cases {
        assert_eq!(rule.state(), Some(state), "{}", rule.as_str());
    }
    assert_eq!(Rule::OperationalFailure.state(), None);
}

#[test]
fn icmp_echo_infers_no_port_state() {
    assert_eq!(raw(Transport::Icmp, [(0, Some(IcmpEchoReply))]), None);
}

#[test]
fn a_tcp_port_unreachable_is_filtered_while_its_udp_twin_is_closed() {
    let reply = [(0, Some(IcmpPortUnreachable))];
    assert_eq!(
        inferred(Transport::Tcp, &reply).state,
        Some(State::Filtered)
    );
    assert_eq!(inferred(Transport::Udp, &reply).state, Some(State::Closed));
}

#[test]
fn silent_udp_stays_ambiguous_until_a_reply_decides() {
    let silent = inferred(Transport::Udp, &[(0, None), (1, None)]);
    assert_eq!(
        (silent.state, silent.rule, silent.supporting),
        (Some(State::OpenOrFiltered), Rule::UdpSilence, vec![0, 1])
    );

    // A lost first reply: silence is consistent with loss, not a conflict.
    let answered = inferred(Transport::Udp, &[(0, None), (1, Some(UdpPayload))]);
    assert_eq!(
        (answered.state, answered.supporting, answered.unanswered),
        (Some(State::Open), vec![1], vec![0])
    );
    assert!(answered.conflicting.is_empty());

    // An ICMP error resolves the ambiguity toward filtered.
    let prohibited = inferred(
        Transport::Udp,
        &[(0, None), (1, Some(IcmpAdministrativelyProhibited))],
    );
    assert_eq!(
        (prohibited.state, prohibited.unanswered),
        (Some(State::Filtered), vec![0])
    );
}

#[test]
fn contradictory_replies_are_retained_as_conflicts() {
    let inference = inferred(
        Transport::Udp,
        &[
            (0, Some(IcmpPortUnreachable)),
            (1, Some(UdpPayload)),
            (2, Some(IcmpPortUnreachable)),
        ],
    );
    assert_eq!(
        (inference.state, inference.rule),
        (Some(State::Open), Rule::UdpReply)
    );
    assert_eq!(
        (inference.supporting, inference.conflicting),
        (vec![1], vec![0, 2])
    );

    // A reset outranks an ICMP error on the same port, which conflicts.
    let reset = inferred(
        Transport::Tcp,
        &[(0, Some(IcmpPortUnreachable)), (1, Some(TcpReset))],
    );
    assert_eq!(
        (reset.rule, reset.supporting, reset.conflicting),
        (Rule::SynReset, vec![1], vec![0])
    );
}

#[test]
fn duplicate_and_agreeing_attempts_all_support_the_state() {
    // SYN silence and ICMP errors agree on filtered; the stronger rule names it.
    let filtered = inferred(
        Transport::Tcp,
        &[
            (0, None),
            (1, Some(IcmpTimeExceeded)),
            (2, Some(IcmpDestinationUnreachable)),
        ],
    );
    assert_eq!(
        (filtered.rule, filtered.supporting),
        (Rule::SynIcmpUnreachable, vec![0, 1, 2])
    );

    let duplicates = inferred(
        Transport::Tcp,
        &[(4, Some(TcpSynAck)), (9, Some(TcpSynAck))],
    );
    assert_eq!(
        (duplicates.rule, duplicates.supporting),
        (Rule::SynAck, vec![4, 9])
    );
}

#[test]
fn delivery_order_does_not_change_the_conclusion() {
    let attempts = [(0, Some(TcpOther)), (1, Some(TcpReset)), (2, None)];
    let ordered = inferred(Transport::Tcp, &attempts);
    let reordered = inferred(Transport::Tcp, &[attempts[2], attempts[0], attempts[1]]);
    assert_eq!(ordered, reordered);
    assert_eq!(
        (ordered.rule, ordered.conflicting, ordered.unanswered),
        (Rule::SynReset, vec![0], vec![2])
    );

    // Equal-ranked rules: the earliest attempt decides whatever the order.
    let tied = [
        (5, Some(IcmpAdministrativelyProhibited)),
        (3, Some(IcmpDestinationUnreachable)),
    ];
    assert_eq!(inferred(Transport::Udp, &tied).supporting, vec![3, 5]);
}

#[test]
fn socket_failures_are_operational_and_never_a_port_state() {
    for outcome in [Outcome::LocalError, Outcome::DeadlineExpired] {
        assert_eq!(
            connect([(3, outcome), (1, outcome)]),
            Inference {
                state: None,
                rule: Rule::OperationalFailure,
                supporting: Vec::new(),
                conflicting: Vec::new(),
                unanswered: Vec::new(),
                failed: vec![1, 3],
            },
            "{outcome:?}"
        );
    }

    let mixed = connect([(0, Outcome::DeadlineExpired), (1, Outcome::Refused)]);
    assert_eq!(
        (mixed.state, mixed.rule, mixed.supporting, mixed.failed),
        (Some(State::Closed), Rule::ConnectRefused, vec![1], vec![0])
    );
}

#[test]
fn connect_outcomes_follow_the_socket_rule_table() {
    let cases = [
        (Outcome::Connected, Rule::ConnectConnected),
        (Outcome::Refused, Rule::ConnectRefused),
        (Outcome::Unreachable, Rule::ConnectUnreachable),
        (Outcome::TimedOut, Rule::ConnectTimedOut),
    ];
    for (outcome, rule) in cases {
        assert_eq!(connect([(0, outcome)]).rule, rule, "{outcome:?}");
    }
    let late = connect([(0, Outcome::TimedOut), (1, Outcome::Connected)]);
    assert_eq!(
        (late.state, late.supporting, late.unanswered),
        (Some(State::Open), vec![1], vec![0])
    );
}
