// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Port inference: a scan-method-dependent conclusion drawn from one
//! endpoint's attempts. Attempt outcomes stay authoritative; an inference
//! names the rule that produced it, the attempts that support it, the
//! attempts that disagree, and the attempts that observed nothing about the
//! port because the operation itself failed.

use super::Reply;
use super::connect::Outcome;
use crate::probe::Transport;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum State {
    Open,
    Closed,
    Filtered,
    /// Silence a UDP service and a filter both explain.
    OpenOrFiltered,
    /// A reply arrived that the method's rules do not interpret.
    Unknown,
}

impl State {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
            Self::Filtered => "filtered",
            Self::OpenOrFiltered => "open_or_filtered",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Rule {
    SynAck,
    SynReset,
    /// Any ICMP destination-unreachable error, port unreachable included:
    /// for TCP it shows a filter or router, not a closed port.
    SynIcmpUnreachable,
    SynTimeExceeded,
    SynUnclassifiedReply,
    SynSilence,
    UdpReply,
    UdpPortUnreachable,
    /// Destination unreachable other than port unreachable.
    UdpIcmpUnreachable,
    UdpTimeExceeded,
    UdpUnclassifiedReply,
    UdpSilence,
    ConnectConnected,
    ConnectRefused,
    ConnectUnreachable,
    ConnectTimedOut,
    /// No attempt observed the port: every attempt failed locally or at the
    /// operation deadline. Not a port state.
    OperationalFailure,
}

impl Rule {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SynAck => "tcp_syn.syn_ack",
            Self::SynReset => "tcp_syn.reset",
            Self::SynIcmpUnreachable => "tcp_syn.icmp_unreachable",
            Self::SynTimeExceeded => "tcp_syn.time_exceeded",
            Self::SynUnclassifiedReply => "tcp_syn.unclassified_reply",
            Self::SynSilence => "tcp_syn.silence",
            Self::UdpReply => "udp.reply",
            Self::UdpPortUnreachable => "udp.port_unreachable",
            Self::UdpIcmpUnreachable => "udp.icmp_unreachable",
            Self::UdpTimeExceeded => "udp.time_exceeded",
            Self::UdpUnclassifiedReply => "udp.unclassified_reply",
            Self::UdpSilence => "udp.silence",
            Self::ConnectConnected => "tcp_connect.connected",
            Self::ConnectRefused => "tcp_connect.refused",
            Self::ConnectUnreachable => "tcp_connect.unreachable",
            Self::ConnectTimedOut => "tcp_connect.timed_out",
            Self::OperationalFailure => "operational_failure",
        }
    }

    /// The state the rule concludes; `None` only for operational failure.
    pub const fn state(self) -> Option<State> {
        Some(match self {
            Self::SynAck | Self::UdpReply | Self::ConnectConnected => State::Open,
            Self::SynReset | Self::UdpPortUnreachable | Self::ConnectRefused => State::Closed,
            Self::SynIcmpUnreachable
            | Self::SynTimeExceeded
            | Self::SynSilence
            | Self::UdpIcmpUnreachable
            | Self::UdpTimeExceeded
            | Self::ConnectUnreachable
            | Self::ConnectTimedOut => State::Filtered,
            Self::SynUnclassifiedReply | Self::UdpUnclassifiedReply => State::Unknown,
            Self::UdpSilence => State::OpenOrFiltered,
            Self::OperationalFailure => return None,
        })
    }

    /// Whether the rule concludes from the absence of any reply.
    const fn is_silence(self) -> bool {
        matches!(
            self,
            Self::SynSilence | Self::UdpSilence | Self::ConnectTimedOut
        )
    }

    /// Which attempt decides: a reply from the endpoint outranks an ICMP
    /// error from the path, which outranks an uninterpreted reply, which
    /// outranks silence. The order mirrors the attempt classification ranks.
    const fn rank(self) -> u8 {
        match self {
            Self::SynAck | Self::UdpReply | Self::ConnectConnected => 6,
            Self::SynReset | Self::UdpPortUnreachable | Self::ConnectRefused => 5,
            Self::SynIcmpUnreachable | Self::UdpIcmpUnreachable | Self::ConnectUnreachable => 4,
            Self::SynTimeExceeded | Self::UdpTimeExceeded => 3,
            Self::SynUnclassifiedReply | Self::UdpUnclassifiedReply => 2,
            Self::SynSilence | Self::UdpSilence | Self::ConnectTimedOut => 1,
            Self::OperationalFailure => 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inference {
    /// Absent when no attempt observed the port.
    pub state: Option<State>,
    pub rule: Rule,
    /// Each attempt's probe sequence lands in exactly one list, ascending.
    /// Attempts whose own observation concludes `state`.
    pub supporting: Vec<u64>,
    /// Attempts whose reply concludes a different state.
    pub conflicting: Vec<u64>,
    /// Silent attempts beside a reply-based conclusion they do not share;
    /// silence is consistent with loss and neither supports nor contradicts.
    pub unanswered: Vec<u64>,
    /// Attempts that ended in an operational failure and observed nothing.
    pub failed: Vec<u64>,
}

/// Raw packet attempts, each with its correlated reply or `None` for
/// silence. ICMP echo is a host observation and infers no port state.
pub(crate) fn raw(
    transport: Transport,
    attempts: impl IntoIterator<Item = (u64, Option<Reply>)>,
) -> Option<Inference> {
    let rule = match transport {
        Transport::Tcp => syn_rule,
        Transport::Udp => udp_rule,
        Transport::Icmp => return None,
    };
    Some(conclude(
        attempts
            .into_iter()
            .map(|(sequence, reply)| (sequence, Some(rule(reply)))),
    ))
}

const fn syn_rule(reply: Option<Reply>) -> Rule {
    match reply {
        Some(Reply::TcpSynAck) => Rule::SynAck,
        Some(Reply::TcpReset) => Rule::SynReset,
        Some(
            Reply::IcmpPortUnreachable
            | Reply::IcmpAdministrativelyProhibited
            | Reply::IcmpDestinationUnreachable,
        ) => Rule::SynIcmpUnreachable,
        Some(Reply::IcmpTimeExceeded) => Rule::SynTimeExceeded,
        Some(Reply::TcpOther | Reply::UdpPayload | Reply::IcmpEchoReply) => {
            Rule::SynUnclassifiedReply
        }
        None => Rule::SynSilence,
    }
}

const fn udp_rule(reply: Option<Reply>) -> Rule {
    match reply {
        Some(Reply::UdpPayload) => Rule::UdpReply,
        Some(Reply::IcmpPortUnreachable) => Rule::UdpPortUnreachable,
        Some(Reply::IcmpAdministrativelyProhibited | Reply::IcmpDestinationUnreachable) => {
            Rule::UdpIcmpUnreachable
        }
        Some(Reply::IcmpTimeExceeded) => Rule::UdpTimeExceeded,
        Some(Reply::TcpSynAck | Reply::TcpReset | Reply::TcpOther | Reply::IcmpEchoReply) => {
            Rule::UdpUnclassifiedReply
        }
        None => Rule::UdpSilence,
    }
}

/// Socket attempts; local errors and the operation deadline are failures.
pub(crate) fn connect(attempts: impl IntoIterator<Item = (u64, Outcome)>) -> Inference {
    conclude(attempts.into_iter().map(|(sequence, outcome)| {
        let rule = match outcome {
            Outcome::Connected => Rule::ConnectConnected,
            Outcome::Refused => Rule::ConnectRefused,
            Outcome::Unreachable => Rule::ConnectUnreachable,
            Outcome::TimedOut => Rule::ConnectTimedOut,
            Outcome::LocalError | Outcome::DeadlineExpired => return (sequence, None),
        };
        (sequence, Some(rule))
    }))
}

/// The highest-ranked rule decides; the earliest attempt wins a tie, so
/// delivery order never changes the conclusion.
fn conclude(attempts: impl Iterator<Item = (u64, Option<Rule>)>) -> Inference {
    let mut attempts: Vec<_> = attempts.collect();
    attempts.sort_unstable_by_key(|(sequence, _)| *sequence);
    let decisive = attempts
        .iter()
        .filter_map(|(_, rule)| *rule)
        .reduce(|best, next| {
            if next.rank() > best.rank() {
                next
            } else {
                best
            }
        });
    let state = decisive.and_then(Rule::state);
    let mut inference = Inference {
        state,
        rule: decisive.unwrap_or(Rule::OperationalFailure),
        supporting: Vec::new(),
        conflicting: Vec::new(),
        unanswered: Vec::new(),
        failed: Vec::new(),
    };
    for (sequence, rule) in attempts {
        let bucket = match rule {
            None => &mut inference.failed,
            Some(rule) if rule.state() == state => &mut inference.supporting,
            Some(rule) if rule.is_silence() => &mut inference.unanswered,
            Some(_) => &mut inference.conflicting,
        };
        bucket.push(sequence);
    }
    inference
}

#[cfg(test)]
mod tests;
