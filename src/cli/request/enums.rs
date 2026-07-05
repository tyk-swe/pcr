// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use super::{cli_enums, req};

#[cfg(any(feature = "traceroute", feature = "fuzz"))]
use super::{cli_commands, cmd};

impl From<cli_enums::FragmentProfile> for req::FragmentProfile {
    fn from(profile: cli_enums::FragmentProfile) -> Self {
        match profile {
            cli_enums::FragmentProfile::Overlap => Self::Overlap,
            cli_enums::FragmentProfile::Teardrop => Self::Teardrop,
            cli_enums::FragmentProfile::TinyOverlap => Self::TinyOverlap,
        }
    }
}

impl From<cli_enums::LogLevel> for req::LogLevel {
    fn from(level: cli_enums::LogLevel) -> Self {
        match level {
            cli_enums::LogLevel::Trace => Self::Trace,
            cli_enums::LogLevel::Debug => Self::Debug,
            cli_enums::LogLevel::Info => Self::Info,
            cli_enums::LogLevel::Warn => Self::Warn,
            cli_enums::LogLevel::Error => Self::Error,
        }
    }
}

impl From<cli_enums::Icmpv6ErrorKind> for req::Icmpv6ErrorKind {
    fn from(kind: cli_enums::Icmpv6ErrorKind) -> Self {
        match kind {
            cli_enums::Icmpv6ErrorKind::DestinationUnreachable => Self::DestinationUnreachable,
            cli_enums::Icmpv6ErrorKind::PacketTooBig => Self::PacketTooBig,
            cli_enums::Icmpv6ErrorKind::TimeExceeded => Self::TimeExceeded,
            cli_enums::Icmpv6ErrorKind::ParameterProblem => Self::ParameterProblem,
        }
    }
}

impl From<cli_enums::Icmpv6ErrorCode> for req::Icmpv6ErrorCode {
    fn from(code: cli_enums::Icmpv6ErrorCode) -> Self {
        match code {
            cli_enums::Icmpv6ErrorCode::DestinationUnreachableNoRoute => {
                Self::DestinationUnreachableNoRoute
            }
            cli_enums::Icmpv6ErrorCode::DestinationUnreachableAdminProhibited => {
                Self::DestinationUnreachableAdminProhibited
            }
            cli_enums::Icmpv6ErrorCode::DestinationUnreachableBeyondScope => {
                Self::DestinationUnreachableBeyondScope
            }
            cli_enums::Icmpv6ErrorCode::DestinationUnreachableAddressUnreachable => {
                Self::DestinationUnreachableAddressUnreachable
            }
            cli_enums::Icmpv6ErrorCode::DestinationUnreachablePortUnreachable => {
                Self::DestinationUnreachablePortUnreachable
            }
            cli_enums::Icmpv6ErrorCode::DestinationUnreachableSourcePolicy => {
                Self::DestinationUnreachableSourcePolicy
            }
            cli_enums::Icmpv6ErrorCode::DestinationUnreachableRejectRoute => {
                Self::DestinationUnreachableRejectRoute
            }
            cli_enums::Icmpv6ErrorCode::DestinationUnreachableSourceRoutingError => {
                Self::DestinationUnreachableSourceRoutingError
            }
            cli_enums::Icmpv6ErrorCode::TimeExceededHopLimit => Self::TimeExceededHopLimit,
            cli_enums::Icmpv6ErrorCode::TimeExceededReassembly => Self::TimeExceededReassembly,
            cli_enums::Icmpv6ErrorCode::ParameterProblemErroneousHeader => {
                Self::ParameterProblemErroneousHeader
            }
            cli_enums::Icmpv6ErrorCode::ParameterProblemUnrecognizedNextHeader => {
                Self::ParameterProblemUnrecognizedNextHeader
            }
            cli_enums::Icmpv6ErrorCode::ParameterProblemUnrecognizedOption => {
                Self::ParameterProblemUnrecognizedOption
            }
        }
    }
}

#[cfg(feature = "traceroute")]
impl From<cli_commands::TracerouteProtocol> for cmd::TracerouteProtocol {
    fn from(protocol: cli_commands::TracerouteProtocol) -> Self {
        match protocol {
            cli_commands::TracerouteProtocol::Udp => Self::Udp,
            cli_commands::TracerouteProtocol::Tcp => Self::Tcp,
            cli_commands::TracerouteProtocol::Icmp => Self::Icmp,
        }
    }
}

#[cfg(feature = "fuzz")]
impl From<cli_commands::FuzzProtocol> for cmd::FuzzProtocol {
    fn from(protocol: cli_commands::FuzzProtocol) -> Self {
        match protocol {
            cli_commands::FuzzProtocol::Tcp => Self::Tcp,
            cli_commands::FuzzProtocol::Udp => Self::Udp,
            cli_commands::FuzzProtocol::Icmp => Self::Icmp,
        }
    }
}

#[cfg(feature = "fuzz")]
impl From<cli_commands::FuzzStrategy> for cmd::FuzzStrategy {
    fn from(strategy: cli_commands::FuzzStrategy) -> Self {
        match strategy {
            cli_commands::FuzzStrategy::BitFlip => Self::BitFlip,
            cli_commands::FuzzStrategy::ByteSwap => Self::ByteSwap,
            cli_commands::FuzzStrategy::RandomPayload => Self::RandomPayload,
            cli_commands::FuzzStrategy::Boundary => Self::Boundary,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cli::enums as cli_enums;
    use crate::domain::request as req;

    #[cfg(any(feature = "traceroute", feature = "fuzz"))]
    use crate::cli::commands as cli_commands;

    #[cfg(any(feature = "traceroute", feature = "fuzz"))]
    use crate::domain::command as cmd;

    #[test]
    fn enum_mappings_preserve_cli_variants() {
        for (cli, domain) in [
            (
                cli_enums::FragmentProfile::Overlap,
                req::FragmentProfile::Overlap,
            ),
            (
                cli_enums::FragmentProfile::Teardrop,
                req::FragmentProfile::Teardrop,
            ),
            (
                cli_enums::FragmentProfile::TinyOverlap,
                req::FragmentProfile::TinyOverlap,
            ),
        ] {
            assert_eq!(req::FragmentProfile::from(cli), domain);
        }

        for (cli, domain) in [
            (cli_enums::LogLevel::Trace, req::LogLevel::Trace),
            (cli_enums::LogLevel::Debug, req::LogLevel::Debug),
            (cli_enums::LogLevel::Info, req::LogLevel::Info),
            (cli_enums::LogLevel::Warn, req::LogLevel::Warn),
            (cli_enums::LogLevel::Error, req::LogLevel::Error),
        ] {
            assert_eq!(req::LogLevel::from(cli), domain);
        }

        for (cli, domain) in [
            (
                cli_enums::Icmpv6ErrorKind::DestinationUnreachable,
                req::Icmpv6ErrorKind::DestinationUnreachable,
            ),
            (
                cli_enums::Icmpv6ErrorKind::PacketTooBig,
                req::Icmpv6ErrorKind::PacketTooBig,
            ),
            (
                cli_enums::Icmpv6ErrorKind::TimeExceeded,
                req::Icmpv6ErrorKind::TimeExceeded,
            ),
            (
                cli_enums::Icmpv6ErrorKind::ParameterProblem,
                req::Icmpv6ErrorKind::ParameterProblem,
            ),
        ] {
            assert_eq!(req::Icmpv6ErrorKind::from(cli), domain);
        }

        for (cli, domain) in [
            (
                cli_enums::Icmpv6ErrorCode::DestinationUnreachableNoRoute,
                req::Icmpv6ErrorCode::DestinationUnreachableNoRoute,
            ),
            (
                cli_enums::Icmpv6ErrorCode::DestinationUnreachableAdminProhibited,
                req::Icmpv6ErrorCode::DestinationUnreachableAdminProhibited,
            ),
            (
                cli_enums::Icmpv6ErrorCode::DestinationUnreachableBeyondScope,
                req::Icmpv6ErrorCode::DestinationUnreachableBeyondScope,
            ),
            (
                cli_enums::Icmpv6ErrorCode::DestinationUnreachableAddressUnreachable,
                req::Icmpv6ErrorCode::DestinationUnreachableAddressUnreachable,
            ),
            (
                cli_enums::Icmpv6ErrorCode::DestinationUnreachablePortUnreachable,
                req::Icmpv6ErrorCode::DestinationUnreachablePortUnreachable,
            ),
            (
                cli_enums::Icmpv6ErrorCode::DestinationUnreachableSourcePolicy,
                req::Icmpv6ErrorCode::DestinationUnreachableSourcePolicy,
            ),
            (
                cli_enums::Icmpv6ErrorCode::DestinationUnreachableRejectRoute,
                req::Icmpv6ErrorCode::DestinationUnreachableRejectRoute,
            ),
            (
                cli_enums::Icmpv6ErrorCode::DestinationUnreachableSourceRoutingError,
                req::Icmpv6ErrorCode::DestinationUnreachableSourceRoutingError,
            ),
            (
                cli_enums::Icmpv6ErrorCode::TimeExceededHopLimit,
                req::Icmpv6ErrorCode::TimeExceededHopLimit,
            ),
            (
                cli_enums::Icmpv6ErrorCode::TimeExceededReassembly,
                req::Icmpv6ErrorCode::TimeExceededReassembly,
            ),
            (
                cli_enums::Icmpv6ErrorCode::ParameterProblemErroneousHeader,
                req::Icmpv6ErrorCode::ParameterProblemErroneousHeader,
            ),
            (
                cli_enums::Icmpv6ErrorCode::ParameterProblemUnrecognizedNextHeader,
                req::Icmpv6ErrorCode::ParameterProblemUnrecognizedNextHeader,
            ),
            (
                cli_enums::Icmpv6ErrorCode::ParameterProblemUnrecognizedOption,
                req::Icmpv6ErrorCode::ParameterProblemUnrecognizedOption,
            ),
        ] {
            assert_eq!(req::Icmpv6ErrorCode::from(cli), domain);
        }
    }

    #[cfg(feature = "traceroute")]
    #[test]
    fn traceroute_protocol_mapping_preserves_all_variants() {
        for (cli, domain) in [
            (
                cli_commands::TracerouteProtocol::Udp,
                cmd::TracerouteProtocol::Udp,
            ),
            (
                cli_commands::TracerouteProtocol::Tcp,
                cmd::TracerouteProtocol::Tcp,
            ),
            (
                cli_commands::TracerouteProtocol::Icmp,
                cmd::TracerouteProtocol::Icmp,
            ),
        ] {
            assert_eq!(cmd::TracerouteProtocol::from(cli), domain);
        }
    }

    #[cfg(feature = "fuzz")]
    #[test]
    fn fuzz_enum_mapping_preserves_all_variants() {
        for (cli, domain) in [
            (cli_commands::FuzzProtocol::Tcp, cmd::FuzzProtocol::Tcp),
            (cli_commands::FuzzProtocol::Udp, cmd::FuzzProtocol::Udp),
            (cli_commands::FuzzProtocol::Icmp, cmd::FuzzProtocol::Icmp),
        ] {
            assert_eq!(cmd::FuzzProtocol::from(cli), domain);
        }

        for (cli, domain) in [
            (
                cli_commands::FuzzStrategy::BitFlip,
                cmd::FuzzStrategy::BitFlip,
            ),
            (
                cli_commands::FuzzStrategy::ByteSwap,
                cmd::FuzzStrategy::ByteSwap,
            ),
            (
                cli_commands::FuzzStrategy::RandomPayload,
                cmd::FuzzStrategy::RandomPayload,
            ),
            (
                cli_commands::FuzzStrategy::Boundary,
                cmd::FuzzStrategy::Boundary,
            ),
        ] {
            assert_eq!(cmd::FuzzStrategy::from(cli), domain);
        }
    }
}
