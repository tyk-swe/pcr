// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The kind of reply a probe received.

use crate::engine::correlation::Correlation;

/// What a correlated reply was, beside the classification it earned. Port
/// inference reads this rather than the classification, because one
/// classification can cover replies that mean different things per method.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Reply {
    TcpSynAck,
    TcpReset,
    /// A correlated TCP segment that is neither SYN/ACK nor a reset.
    TcpOther,
    UdpPayload,
    SctpInitAck,
    SctpAbort,
    SctpOther,
    IcmpEchoReply,
    IcmpTimestampReply,
    IcmpNetmaskReply,
    IpProtocolPayload,
    IcmpPortUnreachable,
    IcmpProtocolUnreachable,
    IcmpAdministrativelyProhibited,
    /// Destination unreachable other than port unreachable or prohibition.
    IcmpDestinationUnreachable,
    IcmpTimeExceeded,
}

impl Reply {
    pub(crate) const fn from_correlation(correlation: Correlation) -> Self {
        match correlation {
            Correlation::TcpSynAck => Self::TcpSynAck,
            Correlation::TcpReset => Self::TcpReset,
            Correlation::TcpOther => Self::TcpOther,
            Correlation::UdpReply => Self::UdpPayload,
            Correlation::SctpInitAck => Self::SctpInitAck,
            Correlation::SctpAbort => Self::SctpAbort,
            Correlation::SctpOther => Self::SctpOther,
            Correlation::IcmpReply => Self::IcmpEchoReply,
            Correlation::IcmpTimestampReply => Self::IcmpTimestampReply,
            Correlation::IcmpNetmaskReply => Self::IcmpNetmaskReply,
            Correlation::IpProtocolReply => Self::IpProtocolPayload,
            Correlation::PortUnreachable => Self::IcmpPortUnreachable,
            Correlation::ProtocolUnreachable => Self::IcmpProtocolUnreachable,
            Correlation::AdministrativelyProhibited => Self::IcmpAdministrativelyProhibited,
            Correlation::DestinationUnreachable => Self::IcmpDestinationUnreachable,
            Correlation::TimeExceeded => Self::IcmpTimeExceeded,
        }
    }
}
