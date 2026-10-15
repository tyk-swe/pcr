// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Port inference: a scan-method-dependent conclusion drawn from one
//! endpoint's attempts. Attempt outcomes stay authoritative; an inference
//! names the rule that produced it, the attempts that support it, the
//! attempts that disagree, and the attempts that observed nothing about the
//! port because the operation itself failed.

use super::connect::Outcome;
use super::{Reply, SctpScan, TcpScan};
use crate::probe::Transport;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum State {
    Open,
    Closed,
    Filtered,
    /// Silence that either an open service or a filter explains: a silent UDP
    /// port, or a silent FIN, NULL, Xmas, or Maimon probe.
    OpenOrFiltered,
    /// An ACK probe's reset: packets reach the port, which says nothing about
    /// whether a service listens.
    Unfiltered,
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
            Self::Unfiltered => "unfiltered",
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
    SctpInitAck,
    SctpInitAbort,
    SctpInitIcmpUnreachable,
    SctpInitTimeExceeded,
    SctpInitUnclassifiedReply,
    SctpInitSilence,
    SctpCookieEchoAbort,
    SctpCookieEchoIcmpUnreachable,
    SctpCookieEchoTimeExceeded,
    SctpCookieEchoUnclassifiedReply,
    SctpCookieEchoSilence,
    IpProtocolReply,
    IpProtocolUnreachable,
    IpProtocolIcmpUnreachable,
    IpProtocolTimeExceeded,
    IpProtocolUnclassifiedReply,
    IpProtocolSilence,
    ConnectConnected,
    ConnectRefused,
    ConnectUnreachable,
    ConnectTimedOut,
    /// A stack-dependent TCP diagnostic conclusion.
    TcpDiagnostic(DiagnosticRule),
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
            Self::SctpInitAck => "sctp_init.init_ack",
            Self::SctpInitAbort => "sctp_init.abort",
            Self::SctpInitIcmpUnreachable => "sctp_init.icmp_unreachable",
            Self::SctpInitTimeExceeded => "sctp_init.time_exceeded",
            Self::SctpInitUnclassifiedReply => "sctp_init.unclassified_reply",
            Self::SctpInitSilence => "sctp_init.silence",
            Self::SctpCookieEchoAbort => "sctp_cookie_echo.abort",
            Self::SctpCookieEchoIcmpUnreachable => "sctp_cookie_echo.icmp_unreachable",
            Self::SctpCookieEchoTimeExceeded => "sctp_cookie_echo.time_exceeded",
            Self::SctpCookieEchoUnclassifiedReply => "sctp_cookie_echo.unclassified_reply",
            Self::SctpCookieEchoSilence => "sctp_cookie_echo.silence",
            Self::IpProtocolReply => "ip_protocol.reply",
            Self::IpProtocolUnreachable => "ip_protocol.protocol_unreachable",
            Self::IpProtocolIcmpUnreachable => "ip_protocol.icmp_unreachable",
            Self::IpProtocolTimeExceeded => "ip_protocol.time_exceeded",
            Self::IpProtocolUnclassifiedReply => "ip_protocol.unclassified_reply",
            Self::IpProtocolSilence => "ip_protocol.silence",
            Self::ConnectConnected => "tcp_connect.connected",
            Self::ConnectRefused => "tcp_connect.refused",
            Self::ConnectUnreachable => "tcp_connect.unreachable",
            Self::ConnectTimedOut => "tcp_connect.timed_out",
            Self::TcpDiagnostic(rule) => rule.as_str(),
            Self::OperationalFailure => "operational_failure",
        }
    }

    /// The state the rule concludes; `None` only for operational failure.
    pub const fn state(self) -> Option<State> {
        Some(match self {
            Self::SynAck
            | Self::UdpReply
            | Self::SctpInitAck
            | Self::IpProtocolReply
            | Self::ConnectConnected => State::Open,
            Self::SynReset
            | Self::UdpPortUnreachable
            | Self::SctpInitAbort
            | Self::SctpCookieEchoAbort
            | Self::IpProtocolUnreachable
            | Self::ConnectRefused => State::Closed,
            Self::SynIcmpUnreachable
            | Self::SynTimeExceeded
            | Self::SynSilence
            | Self::UdpIcmpUnreachable
            | Self::UdpTimeExceeded
            | Self::SctpInitIcmpUnreachable
            | Self::SctpInitTimeExceeded
            | Self::SctpInitSilence
            | Self::SctpCookieEchoIcmpUnreachable
            | Self::IpProtocolIcmpUnreachable
            | Self::IpProtocolTimeExceeded
            | Self::ConnectUnreachable
            | Self::ConnectTimedOut => State::Filtered,
            Self::SynUnclassifiedReply
            | Self::UdpUnclassifiedReply
            | Self::SctpInitUnclassifiedReply
            | Self::SctpCookieEchoTimeExceeded
            | Self::SctpCookieEchoUnclassifiedReply
            | Self::IpProtocolUnclassifiedReply => State::Unknown,
            Self::UdpSilence | Self::SctpCookieEchoSilence | Self::IpProtocolSilence => {
                State::OpenOrFiltered
            }
            Self::TcpDiagnostic(rule) => rule.state(),
            Self::OperationalFailure => return None,
        })
    }

    /// Whether the rule concludes from the absence of any reply.
    const fn is_silence(self) -> bool {
        matches!(
            self,
            Self::SynSilence
                | Self::UdpSilence
                | Self::SctpInitSilence
                | Self::SctpCookieEchoSilence
                | Self::IpProtocolSilence
                | Self::ConnectTimedOut
        ) || matches!(self, Self::TcpDiagnostic(rule) if matches!(rule.outcome, Observed::Silence))
    }

    /// Which attempt decides: a reply from the endpoint outranks an ICMP
    /// error from the path, which outranks an uninterpreted reply, which
    /// outranks silence. Diagnostic rules use the same order, ranking resets above ICMP
    /// errors even where the attempt classification does not.
    const fn rank(self) -> u8 {
        match self {
            Self::SynAck
            | Self::UdpReply
            | Self::SctpInitAck
            | Self::IpProtocolReply
            | Self::ConnectConnected => 6,
            Self::SynReset
            | Self::UdpPortUnreachable
            | Self::SctpInitAbort
            | Self::SctpCookieEchoAbort
            | Self::IpProtocolUnreachable
            | Self::ConnectRefused => 5,
            Self::SynIcmpUnreachable
            | Self::UdpIcmpUnreachable
            | Self::SctpInitIcmpUnreachable
            | Self::SctpCookieEchoIcmpUnreachable
            | Self::IpProtocolIcmpUnreachable
            | Self::ConnectUnreachable => 4,
            Self::SynTimeExceeded
            | Self::UdpTimeExceeded
            | Self::SctpInitTimeExceeded
            | Self::SctpCookieEchoTimeExceeded
            | Self::IpProtocolTimeExceeded => 3,
            Self::SynUnclassifiedReply
            | Self::UdpUnclassifiedReply
            | Self::SctpInitUnclassifiedReply
            | Self::SctpCookieEchoUnclassifiedReply
            | Self::IpProtocolUnclassifiedReply => 2,
            Self::SynSilence
            | Self::UdpSilence
            | Self::SctpInitSilence
            | Self::SctpCookieEchoSilence
            | Self::IpProtocolSilence
            | Self::ConnectTimedOut => 1,
            Self::TcpDiagnostic(rule) => rule.outcome.rank(),
            Self::OperationalFailure => 0,
        }
    }

    const fn is_custom_silence(self) -> bool {
        matches!(
            self,
            Self::TcpDiagnostic(DiagnosticRule {
                method: DiagnosticMethod::Custom,
                outcome: Observed::Silence,
            })
        )
    }
}

/// The TCP diagnostic mode a rule interprets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DiagnosticMethod {
    Ack,
    Window,
    Fin,
    Null,
    Xmas,
    Maimon,
    Custom,
}

impl DiagnosticMethod {
    /// `None` for SYN, whose rules are the original `tcp_syn.*` set.
    const fn of(mode: TcpScan) -> Option<Self> {
        Some(match mode {
            TcpScan::Syn => return None,
            TcpScan::Ack => Self::Ack,
            TcpScan::Window => Self::Window,
            TcpScan::Fin => Self::Fin,
            TcpScan::Null => Self::Null,
            TcpScan::Xmas => Self::Xmas,
            TcpScan::Maimon => Self::Maimon,
            TcpScan::Custom { .. } => Self::Custom,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Observed {
    Reset,
    ResetNonzeroWindow,
    ResetZeroWindow,
    IcmpUnreachable,
    TimeExceeded,
    UnclassifiedReply,
    Silence,
    Reply,
}

impl Observed {
    const fn rank(self) -> u8 {
        match self {
            Self::Reset | Self::ResetNonzeroWindow | Self::ResetZeroWindow | Self::Reply => 5,
            Self::IcmpUnreachable => 4,
            Self::TimeExceeded => 3,
            Self::UnclassifiedReply => 2,
            Self::Silence => 1,
        }
    }
}

/// One TCP diagnostic conclusion: the mode's interpretation of what one
/// attempt observed. Construction stays inside this module so only
/// combinations a mode can conclude exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DiagnosticRule {
    method: DiagnosticMethod,
    outcome: Observed,
}

macro_rules! rule_id {
    ($prefix:literal, $outcome:expr) => {
        match $outcome {
            Observed::Reset => concat!($prefix, ".reset"),
            Observed::ResetNonzeroWindow => concat!($prefix, ".reset_nonzero"),
            Observed::ResetZeroWindow => concat!($prefix, ".reset_zero"),
            Observed::IcmpUnreachable => concat!($prefix, ".icmp_unreachable"),
            Observed::TimeExceeded => concat!($prefix, ".time_exceeded"),
            Observed::UnclassifiedReply => concat!($prefix, ".unclassified_reply"),
            Observed::Silence => concat!($prefix, ".silence"),
            Observed::Reply => concat!($prefix, ".reply"),
        }
    };
}

impl DiagnosticRule {
    pub const fn method(self) -> DiagnosticMethod {
        self.method
    }

    pub const fn as_str(self) -> &'static str {
        match self.method {
            DiagnosticMethod::Ack => rule_id!("tcp_ack", self.outcome),
            DiagnosticMethod::Window => rule_id!("tcp_window", self.outcome),
            DiagnosticMethod::Fin => rule_id!("tcp_fin", self.outcome),
            DiagnosticMethod::Null => rule_id!("tcp_null", self.outcome),
            DiagnosticMethod::Xmas => rule_id!("tcp_xmas", self.outcome),
            DiagnosticMethod::Maimon => rule_id!("tcp_maimon", self.outcome),
            DiagnosticMethod::Custom => rule_id!("tcp_custom", self.outcome),
        }
    }

    const fn state(self) -> State {
        match (self.method, self.outcome) {
            (DiagnosticMethod::Custom, _)
            | (_, Observed::UnclassifiedReply | Observed::TimeExceeded) => State::Unknown,
            (DiagnosticMethod::Ack, Observed::Reset) => State::Unfiltered,
            (DiagnosticMethod::Window, Observed::ResetNonzeroWindow) => State::Open,
            (DiagnosticMethod::Window, Observed::ResetZeroWindow) => State::Closed,
            (_, Observed::IcmpUnreachable)
            | (DiagnosticMethod::Ack | DiagnosticMethod::Window, _) => State::Filtered,
            (_, Observed::Reset) => State::Closed,
            (_, _) => State::OpenOrFiltered,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inference {
    /// Absent when no attempt observed the port.
    pub state: Option<State>,
    pub rule: Rule,
    /// Each attempt's probe sequence lands in exactly one list, ascending.
    /// attempt_error whose own observation concludes `state`.
    pub supporting: Vec<u64>,
    /// attempt_error whose reply concludes a different state.
    pub conflicting: Vec<u64>,
    /// Silent attempts beside a reply-based conclusion they do not share;
    /// silence is consistent with loss and neither supports nor contradicts.
    pub unanswered: Vec<u64>,
    /// attempt_error that ended in an operational failure and observed nothing.
    pub failed: Vec<u64>,
}

/// One raw attempt: its correlated reply or `None` for silence, the TCP mode
/// it sent, and the window the correlated TCP response advertised.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Attempt {
    pub(crate) sequence: u64,
    pub(crate) reply: Option<Reply>,
    pub(crate) tcp_scan: Option<TcpScan>,
    pub(crate) sctp_scan: Option<SctpScan>,
    pub(crate) tcp_window: Option<u16>,
}

/// Raw packet attempts. ICMP echo is a host observation and infers no port
/// state.
pub(crate) fn raw(
    transport: Transport,
    attempts: impl IntoIterator<Item = Attempt>,
) -> Option<Inference> {
    if transport == Transport::Icmp {
        return None;
    }
    Some(conclude(attempts.into_iter().map(|attempt| {
        let rule = match transport {
            Transport::Tcp => match attempt.tcp_scan.and_then(DiagnosticMethod::of) {
                Some(method) => diagnostic_rule(method, attempt.reply, attempt.tcp_window),
                None => syn_rule(attempt.reply),
            },
            Transport::Udp => udp_rule(attempt.reply),
            Transport::Sctp => sctp_rule(attempt.sctp_scan.unwrap_or_default(), attempt.reply),
            Transport::Ip => ip_protocol_rule(attempt.reply),
            Transport::Icmp => unreachable!("ICMP echo is filtered above"),
        };
        (attempt.sequence, Some(rule))
    })))
}

fn diagnostic_rule(method: DiagnosticMethod, reply: Option<Reply>, window: Option<u16>) -> Rule {
    let outcome = match (method, reply) {
        (_, None) => Observed::Silence,
        (DiagnosticMethod::Custom, Some(_)) => Observed::Reply,
        (
            _,
            Some(
                Reply::IcmpPortUnreachable
                | Reply::IcmpAdministrativelyProhibited
                | Reply::IcmpDestinationUnreachable,
            ),
        ) => Observed::IcmpUnreachable,
        (_, Some(Reply::IcmpTimeExceeded)) => Observed::TimeExceeded,
        (DiagnosticMethod::Window, Some(Reply::TcpReset)) => match window {
            Some(0) => Observed::ResetZeroWindow,
            Some(_) => Observed::ResetNonzeroWindow,
            None => Observed::UnclassifiedReply,
        },
        (_, Some(Reply::TcpReset)) => Observed::Reset,
        (_, Some(_)) => Observed::UnclassifiedReply,
    };
    Rule::TcpDiagnostic(DiagnosticRule { method, outcome })
}

const fn syn_rule(reply: Option<Reply>) -> Rule {
    match reply {
        Some(Reply::TcpSynAck) => Rule::SynAck,
        Some(Reply::TcpReset) => Rule::SynReset,
        Some(
            Reply::IcmpPortUnreachable
            | Reply::IcmpProtocolUnreachable
            | Reply::IcmpAdministrativelyProhibited
            | Reply::IcmpDestinationUnreachable,
        ) => Rule::SynIcmpUnreachable,
        Some(Reply::IcmpTimeExceeded) => Rule::SynTimeExceeded,
        Some(_) => Rule::SynUnclassifiedReply,
        None => Rule::SynSilence,
    }
}

const fn udp_rule(reply: Option<Reply>) -> Rule {
    match reply {
        Some(Reply::UdpPayload) => Rule::UdpReply,
        Some(Reply::IcmpPortUnreachable) => Rule::UdpPortUnreachable,
        Some(
            Reply::IcmpProtocolUnreachable
            | Reply::IcmpAdministrativelyProhibited
            | Reply::IcmpDestinationUnreachable,
        ) => Rule::UdpIcmpUnreachable,
        Some(Reply::IcmpTimeExceeded) => Rule::UdpTimeExceeded,
        Some(_) => Rule::UdpUnclassifiedReply,
        None => Rule::UdpSilence,
    }
}

const fn sctp_rule(mode: SctpScan, reply: Option<Reply>) -> Rule {
    match (mode, reply) {
        (SctpScan::Init, Some(Reply::SctpInitAck)) => Rule::SctpInitAck,
        (SctpScan::Init, Some(Reply::SctpAbort)) => Rule::SctpInitAbort,
        (
            SctpScan::Init,
            Some(
                Reply::IcmpPortUnreachable
                | Reply::IcmpProtocolUnreachable
                | Reply::IcmpAdministrativelyProhibited
                | Reply::IcmpDestinationUnreachable,
            ),
        ) => Rule::SctpInitIcmpUnreachable,
        (SctpScan::Init, Some(Reply::IcmpTimeExceeded)) => Rule::SctpInitTimeExceeded,
        (SctpScan::Init, Some(_)) => Rule::SctpInitUnclassifiedReply,
        (SctpScan::Init, None) => Rule::SctpInitSilence,
        (SctpScan::CookieEcho, Some(Reply::SctpAbort)) => Rule::SctpCookieEchoAbort,
        (
            SctpScan::CookieEcho,
            Some(
                Reply::IcmpPortUnreachable
                | Reply::IcmpProtocolUnreachable
                | Reply::IcmpAdministrativelyProhibited
                | Reply::IcmpDestinationUnreachable,
            ),
        ) => Rule::SctpCookieEchoIcmpUnreachable,
        (SctpScan::CookieEcho, Some(Reply::IcmpTimeExceeded)) => Rule::SctpCookieEchoTimeExceeded,
        (SctpScan::CookieEcho, Some(_)) => Rule::SctpCookieEchoUnclassifiedReply,
        (SctpScan::CookieEcho, None) => Rule::SctpCookieEchoSilence,
    }
}

const fn ip_protocol_rule(reply: Option<Reply>) -> Rule {
    match reply {
        Some(Reply::IpProtocolPayload) => Rule::IpProtocolReply,
        Some(Reply::IcmpProtocolUnreachable) => Rule::IpProtocolUnreachable,
        Some(
            Reply::IcmpPortUnreachable
            | Reply::IcmpAdministrativelyProhibited
            | Reply::IcmpDestinationUnreachable,
        ) => Rule::IpProtocolIcmpUnreachable,
        Some(Reply::IcmpTimeExceeded) => Rule::IpProtocolTimeExceeded,
        Some(_) => Rule::IpProtocolUnclassifiedReply,
        None => Rule::IpProtocolSilence,
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
            Some(rule) if rule.is_custom_silence() && !decisive.is_some_and(Rule::is_silence) => {
                &mut inference.unanswered
            }
            Some(rule) if rule.state() == state => &mut inference.supporting,
            Some(rule) if rule.is_silence() => &mut inference.unanswered,
            Some(_) => &mut inference.conflicting,
        };
        bucket.push(sequence);
    }
    inference
}
