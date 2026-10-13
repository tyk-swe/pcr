// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Inference, Rule, State, connect, raw};
use crate::probe::Transport;
use crate::scan::Reply::{
    self, IcmpAdministrativelyProhibited, IcmpDestinationUnreachable, IcmpEchoReply,
    IcmpPortUnreachable, IcmpTimeExceeded, TcpOther, TcpReset, TcpSynAck, UdpPayload,
};
use crate::scan::TcpScan;
use crate::scan::connect::Outcome;

fn inferred(transport: Transport, attempts: &[(u64, Option<Reply>)]) -> Inference {
    raw(
        transport,
        attempts.iter().map(|&(sequence, reply)| super::Attempt {
            sequence,
            reply,
            tcp_scan: None,
            sctp_scan: None,
            tcp_window: None,
        }),
    )
    .expect("port transports infer")
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
    assert_eq!(
        raw(
            Transport::Icmp,
            [super::Attempt {
                sequence: 0,
                reply: Some(IcmpEchoReply),
                tcp_scan: None,
                sctp_scan: None,
                tcp_window: None,
            }]
        ),
        None
    );
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

fn diagnostic(mode: TcpScan, attempts: &[(u64, Option<Reply>, Option<u16>)]) -> Inference {
    raw(
        Transport::Tcp,
        attempts
            .iter()
            .map(|&(sequence, reply, window)| super::Attempt {
                sequence,
                reply,
                tcp_scan: Some(mode),
                sctp_scan: None,
                tcp_window: window,
            }),
    )
    .expect("TCP diagnostics infer")
}

fn single(
    mode: TcpScan,
    reply: Option<Reply>,
    window: Option<u16>,
) -> (Option<State>, &'static str) {
    let inference = diagnostic(mode, &[(1, reply, window)]);
    (inference.state, inference.rule.as_str())
}

#[test]
fn diagnostic_modes_follow_their_exact_rule_and_state_tables() {
    use State::{Closed, Filtered, Open, OpenOrFiltered, Unfiltered, Unknown};
    let replies = [
        None,
        Some(TcpReset),
        Some(TcpSynAck),
        Some(TcpOther),
        Some(UdpPayload),
        Some(IcmpEchoReply),
        Some(IcmpPortUnreachable),
        Some(IcmpAdministrativelyProhibited),
        Some(IcmpDestinationUnreachable),
        Some(IcmpTimeExceeded),
    ];
    // silence, reset, three other direct replies, three unreachable, time exceeded
    let others = |unreachable: &'static str, other: &'static str| {
        [
            (None, "silence"),
            (Some(TcpReset), "reset"),
            (Some(TcpSynAck), other),
            (Some(TcpOther), other),
            (Some(UdpPayload), other),
            (Some(IcmpEchoReply), other),
            (Some(IcmpPortUnreachable), unreachable),
            (Some(IcmpAdministrativelyProhibited), unreachable),
            (Some(IcmpDestinationUnreachable), unreachable),
            (Some(IcmpTimeExceeded), "time_exceeded"),
        ]
    };
    assert_eq!(replies.len(), others("x", "y").len());
    let ack = [
        Filtered, Unfiltered, Unknown, Unknown, Unknown, Unknown, Filtered, Filtered, Filtered,
        Unknown,
    ];
    for ((reply, suffix), state) in others("icmp_unreachable", "unclassified_reply")
        .into_iter()
        .zip(ack)
    {
        let (actual, rule) = single(TcpScan::Ack, reply, Some(0));
        assert_eq!(
            (actual, rule),
            (Some(state), format!("tcp_ack.{suffix}").as_str())
        );
    }
    let family = [
        OpenOrFiltered,
        Closed,
        Unknown,
        Unknown,
        Unknown,
        Unknown,
        Filtered,
        Filtered,
        Filtered,
        Unknown,
    ];
    for (mode, prefix) in [
        (TcpScan::Fin, "tcp_fin"),
        (TcpScan::Null, "tcp_null"),
        (TcpScan::Xmas, "tcp_xmas"),
        (TcpScan::Maimon, "tcp_maimon"),
    ] {
        for ((reply, suffix), state) in others("icmp_unreachable", "unclassified_reply")
            .into_iter()
            .zip(family)
        {
            let (actual, rule) = single(mode, reply, Some(0));
            assert_eq!(
                (actual, rule),
                (Some(state), format!("{prefix}.{suffix}").as_str())
            );
        }
    }
    let window = [
        Filtered, Open, Unknown, Unknown, Unknown, Unknown, Filtered, Filtered, Filtered, Unknown,
    ];
    for ((reply, suffix), state) in others("icmp_unreachable", "unclassified_reply")
        .into_iter()
        .zip(window)
    {
        let suffix = if suffix == "reset" {
            "reset_nonzero"
        } else {
            suffix
        };
        let (actual, rule) = single(TcpScan::Window, reply, Some(9));
        assert_eq!(
            (actual, rule),
            (Some(state), format!("tcp_window.{suffix}").as_str())
        );
    }
    for reply in replies {
        let (state, rule) = single(TcpScan::Custom { flags: 0x002 }, reply, Some(9));
        let expected = if reply.is_none() {
            "tcp_custom.silence"
        } else {
            "tcp_custom.reply"
        };
        assert_eq!((state, rule), (Some(Unknown), expected), "{reply:?}");
    }
}

#[test]
fn window_inference_reads_the_retained_reset_window_only() {
    assert_eq!(
        single(TcpScan::Window, Some(TcpReset), Some(0)),
        (Some(State::Closed), "tcp_window.reset_zero")
    );
    assert_eq!(
        single(TcpScan::Window, Some(TcpReset), Some(1)),
        (Some(State::Open), "tcp_window.reset_nonzero")
    );
    assert_eq!(
        single(TcpScan::Window, Some(TcpReset), None),
        (Some(State::Unknown), "tcp_window.unclassified_reply")
    );
    assert_eq!(
        single(TcpScan::Window, Some(TcpOther), Some(0)),
        (Some(State::Unknown), "tcp_window.unclassified_reply")
    );
}

#[test]
fn contradictory_windows_keep_the_earliest_and_report_the_conflict_in_any_order() {
    let attempts = [
        (4, Some(TcpReset), Some(512)),
        (2, Some(TcpReset), Some(0)),
        (3, None, None),
    ];
    let forward = diagnostic(TcpScan::Window, &attempts);
    let mut reversed = attempts;
    reversed.reverse();
    assert_eq!(forward, diagnostic(TcpScan::Window, &reversed));
    assert_eq!(forward.rule.as_str(), "tcp_window.reset_zero");
    assert_eq!(forward.state, Some(State::Closed));
    assert_eq!(forward.supporting, vec![2]);
    assert_eq!(forward.conflicting, vec![4]);
    assert_eq!(forward.unanswered, vec![3]);
}

#[test]
fn replies_outrank_icmp_and_silence_under_diagnostics() {
    let inference = diagnostic(
        TcpScan::Fin,
        &[
            (1, None, None),
            (2, Some(IcmpAdministrativelyProhibited), None),
            (3, Some(TcpReset), Some(0)),
            (4, Some(IcmpTimeExceeded), None),
        ],
    );
    assert_eq!(inference.state, Some(State::Closed));
    assert_eq!(inference.rule.as_str(), "tcp_fin.reset");
    assert_eq!(inference.supporting, vec![3]);
    assert_eq!(inference.conflicting, vec![2, 4]);
    assert_eq!(inference.unanswered, vec![1]);
}

#[test]
fn custom_replies_never_make_silent_attempts_support_them() {
    let inference = diagnostic(
        TcpScan::Custom { flags: 0x001 },
        &[(1, None, None), (2, Some(TcpReset), Some(0))],
    );
    assert_eq!(inference.rule.as_str(), "tcp_custom.reply");
    assert_eq!(inference.state, Some(State::Unknown));
    assert_eq!(
        (inference.supporting, inference.unanswered),
        (vec![2], vec![1])
    );
}

#[test]
fn diagnostic_state_names_the_unfiltered_conclusion() {
    assert_eq!(State::Unfiltered.as_str(), "unfiltered");
}

#[test]
fn sctp_init_cookie_echo_and_ip_protocol_rules_follow_their_state_tables() {
    use crate::scan::SctpScan;
    use Reply::{IcmpProtocolUnreachable, IpProtocolPayload, SctpAbort, SctpInitAck, SctpOther};

    let sctp = |mode: SctpScan, reply: Option<Reply>| {
        raw(
            Transport::Sctp,
            [super::Attempt {
                sequence: 1,
                reply,
                tcp_scan: None,
                sctp_scan: Some(mode),
                tcp_window: None,
            }],
        )
        .expect("SCTP infers")
    };
    assert_eq!(
        (
            sctp(SctpScan::Init, Some(SctpInitAck)).state,
            sctp(SctpScan::Init, Some(SctpInitAck)).rule.as_str()
        ),
        (Some(State::Open), "sctp_init.init_ack")
    );
    assert_eq!(
        (
            sctp(SctpScan::Init, Some(SctpAbort)).state,
            sctp(SctpScan::Init, Some(SctpAbort)).rule.as_str()
        ),
        (Some(State::Closed), "sctp_init.abort")
    );
    assert_eq!(
        (
            sctp(SctpScan::Init, Some(SctpOther)).state,
            sctp(SctpScan::Init, Some(SctpOther)).rule.as_str()
        ),
        (Some(State::Unknown), "sctp_init.unclassified_reply")
    );
    assert_eq!(
        (
            sctp(SctpScan::Init, Some(IcmpAdministrativelyProhibited)).state,
            sctp(SctpScan::Init, Some(IcmpAdministrativelyProhibited))
                .rule
                .as_str()
        ),
        (Some(State::Filtered), "sctp_init.icmp_unreachable")
    );
    assert_eq!(
        (
            sctp(SctpScan::Init, None).state,
            sctp(SctpScan::Init, None).rule.as_str()
        ),
        (Some(State::Filtered), "sctp_init.silence")
    );

    assert_eq!(
        (
            sctp(SctpScan::CookieEcho, Some(SctpAbort)).state,
            sctp(SctpScan::CookieEcho, Some(SctpAbort)).rule.as_str()
        ),
        (Some(State::Closed), "sctp_cookie_echo.abort")
    );
    assert_eq!(
        (
            sctp(SctpScan::CookieEcho, Some(SctpInitAck)).state,
            sctp(SctpScan::CookieEcho, Some(SctpInitAck)).rule.as_str()
        ),
        (Some(State::Unknown), "sctp_cookie_echo.unclassified_reply")
    );
    assert_eq!(
        (
            sctp(SctpScan::CookieEcho, Some(IcmpTimeExceeded)).state,
            sctp(SctpScan::CookieEcho, Some(IcmpTimeExceeded))
                .rule
                .as_str()
        ),
        (Some(State::Unknown), "sctp_cookie_echo.time_exceeded")
    );
    assert_eq!(
        (
            sctp(SctpScan::CookieEcho, None).state,
            sctp(SctpScan::CookieEcho, None).rule.as_str()
        ),
        (Some(State::OpenOrFiltered), "sctp_cookie_echo.silence")
    );

    assert_eq!(
        (
            inferred(Transport::Ip, &[(1, Some(IpProtocolPayload))]).state,
            inferred(Transport::Ip, &[(1, Some(IpProtocolPayload))])
                .rule
                .as_str()
        ),
        (Some(State::Open), "ip_protocol.reply")
    );
    assert_eq!(
        (
            inferred(Transport::Ip, &[(1, Some(IcmpProtocolUnreachable))]).state,
            inferred(Transport::Ip, &[(1, Some(IcmpProtocolUnreachable))])
                .rule
                .as_str()
        ),
        (Some(State::Closed), "ip_protocol.protocol_unreachable")
    );
    assert_eq!(
        (
            inferred(Transport::Ip, &[(1, Some(IcmpDestinationUnreachable))]).state,
            inferred(Transport::Ip, &[(1, Some(IcmpDestinationUnreachable))])
                .rule
                .as_str()
        ),
        (Some(State::Filtered), "ip_protocol.icmp_unreachable")
    );
    assert_eq!(
        (
            inferred(Transport::Ip, &[(1, None)]).state,
            inferred(Transport::Ip, &[(1, None)]).rule.as_str()
        ),
        (Some(State::OpenOrFiltered), "ip_protocol.silence")
    );
}
