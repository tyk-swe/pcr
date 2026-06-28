// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use clap::ValueEnum;
use log::LevelFilter;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    /// Concise summary.
    Summary,
    /// Field-by-field breakdown.
    Detailed,
    /// Hexadecimal dump.
    Hex,
    /// Machine-readable JSON.
    Json,
}

/// Predefined fragmentation behaviours for rapid testing/attacks.
#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FragmentProfile {
    /// Minimal overlapping pair.
    Overlap,
    /// Classic teardrop.
    Teardrop,
    /// Extra-small MTU.
    TinyOverlap,
}

impl fmt::Display for FragmentProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            FragmentProfile::Overlap => "overlap",
            FragmentProfile::Teardrop => "teardrop",
            FragmentProfile::TinyOverlap => "tiny-overlap",
        };
        f.write_str(label)
    }
}

/// Supported logging levels for explicit override.
#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    /// Very low priority, verbose.
    Trace,
    /// Lower priority.
    Debug,
    /// Useful information.
    Info,
    /// Hazardous situations.
    Warn,
    /// Serious errors.
    Error,
}

impl LogLevel {
    pub fn to_level_filter(self) -> LevelFilter {
        match self {
            LogLevel::Trace => LevelFilter::Trace,
            LogLevel::Debug => LevelFilter::Debug,
            LogLevel::Info => LevelFilter::Info,
            LogLevel::Warn => LevelFilter::Warn,
            LogLevel::Error => LevelFilter::Error,
        }
    }
}

impl From<OutputFormat> for crate::output::OutputFormat {
    fn from(format: OutputFormat) -> Self {
        match format {
            OutputFormat::Summary => Self::Summary,
            OutputFormat::Detailed => Self::Detailed,
            OutputFormat::Hex => Self::Hex,
            OutputFormat::Json => Self::Json,
        }
    }
}

/// Common ICMPv6 error message families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[clap(rename_all = "kebab-case")]
#[serde(rename_all = "kebab-case")]
pub enum Icmpv6ErrorKind {
    DestinationUnreachable,
    PacketTooBig,
    TimeExceeded,
    ParameterProblem,
}

/// Well-known ICMPv6 error message codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[clap(rename_all = "kebab-case")]
#[serde(rename_all = "kebab-case")]
pub enum Icmpv6ErrorCode {
    /// No route to destination.
    DestinationUnreachableNoRoute,
    /// Communication with destination administratively prohibited.
    DestinationUnreachableAdminProhibited,
    /// Beyond scope of source address.
    DestinationUnreachableBeyondScope,
    /// Address unreachable.
    DestinationUnreachableAddressUnreachable,
    /// Port unreachable.
    DestinationUnreachablePortUnreachable,
    /// Source address failed ingress/egress policy.
    DestinationUnreachableSourcePolicy,
    /// Reject route to destination.
    DestinationUnreachableRejectRoute,
    /// Error in source routing header.
    DestinationUnreachableSourceRoutingError,
    /// Hop limit exceeded in transit.
    TimeExceededHopLimit,
    /// Fragment reassembly time exceeded.
    TimeExceededReassembly,
    /// Erroneous header field encountered.
    ParameterProblemErroneousHeader,
    /// Unrecognized Next Header type encountered.
    ParameterProblemUnrecognizedNextHeader,
    /// Unrecognized IPv6 option encountered.
    ParameterProblemUnrecognizedOption,
}
