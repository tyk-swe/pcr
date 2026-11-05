// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;

use serde::Serialize;

use packetcraftr_core::error::{Classification, Classified, Kind};

/// Current output contract identifier.
pub const SCHEMA: &str = packetcraftr_core::security::OUTPUT_SCHEMA;

pub use crate::commands::Command;

impl Command {
    pub fn require_format(self, format: Format) -> Result<Format, Error> {
        if self.formats().contains(&format) {
            Ok(format)
        } else {
            Err(Error::UnsupportedFormat {
                command: self,
                format,
            })
        }
    }
}

impl fmt::Display for Command {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, clap::ValueEnum)]
pub enum Format {
    Text,
    Json,
    Csv,
    Ndjson,
    Hex,
    Raw,
    Pcap,
    #[value(name = "pcapng")]
    PcapNg,
}

impl Format {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Json => "json",
            Self::Csv => "csv",
            Self::Ndjson => "ndjson",
            Self::Hex => "hex",
            Self::Raw => "raw",
            Self::Pcap => "pcap",
            Self::PcapNg => "pcapng",
        }
    }

    pub(crate) fn unreachable(self) -> ! {
        unreachable!("dispatch already selected a supported format: {self}")
    }
}

impl fmt::Display for Format {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Aggregate,
    Stream,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error(
        "{command} does not support {format} output; choose {}",
        supported_formats(command)
    )]
    UnsupportedFormat { command: Command, format: Format },
    #[error("capture timestamp is outside the signed output range")]
    TimestampOutOfRange,
    #[error("source frame must be a non-zero unsigned 64-bit position")]
    InvalidSourceFrame,
    #[error("fuzz events are incoherent: {0}")]
    IncoherentFuzzEvents(#[from] packetcraftr_core::fuzz::IncoherentReport),
    #[error("{value} has no representation in the published output contract")]
    Unpublished { value: &'static str },
}

fn supported_formats(command: &Command) -> String {
    command
        .formats()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::UnsupportedFormat { .. } => Classification::new(
                packetcraftr_core::error::Code::CliOutputFormat,
                Kind::Usage,
                Some("choose one of the formats listed for this command"),
            ),
            Self::TimestampOutOfRange => Classification::new(
                packetcraftr_core::error::Code::PacketTimestampRange,
                Kind::Packet,
                Some("use a capture whose timestamp fits signed 64-bit Unix seconds"),
            ),
            Self::InvalidSourceFrame => Classification::new(
                packetcraftr_core::error::Code::InternalSourceFrame,
                Kind::Internal,
                Some("use the one-based source position assigned while reading or capturing"),
            ),
            Self::IncoherentFuzzEvents(_) => Classification::new(
                packetcraftr_core::error::Code::InternalFuzzEventCoherence,
                Kind::Internal,
                Some("collect cases from exactly one complete campaign in publication order"),
            ),
            Self::Unpublished { .. } => Classification::new(
                packetcraftr_core::error::Code::InternalError,
                Kind::Internal,
                None,
            ),
        }
    }
}

/// One published output shape: the Rust types that serialize to a schema
/// envelope definition for one command, the stream events they emit, and one
/// checked-in example validating against that definition. The output-schema
/// checker fails on any row whose definition, types, events, or example no
/// longer agree with the schema, the sources, and the examples.
pub struct PublishedType {
    pub definition: &'static str,
    pub command: &'static str,
    pub rust_types: &'static [&'static str],
    pub events: &'static [&'static str],
    pub example: &'static str,
}

/// Every aggregate and stream envelope definition in the current output
/// schema, keyed by the command that publishes it.
pub const PUBLISHED_TYPES: &[PublishedType] = &[
    PublishedType {
        definition: "buildSuccess",
        command: "build",
        rust_types: &["crate::commands::packet::build::output::Report"],
        events: &[],
        example: "examples/documents/output-build-event.json",
    },
    PublishedType {
        definition: "dissectSuccess",
        command: "dissect",
        rust_types: &["crate::commands::packet::dissect::output::Report"],
        events: &[],
        example: "examples/documents/output-dissect-diagnostic-success.json",
    },
    PublishedType {
        definition: "protocolsSuccess",
        command: "protocols",
        rust_types: &["crate::output::protocols::Summary"],
        events: &[],
        example: "examples/documents/output-protocols-detail-success.json",
    },
    PublishedType {
        definition: "planSuccess",
        command: "plan",
        rust_types: &["crate::commands::network::plan::output::Report"],
        events: &[],
        example: "examples/documents/output-plan-success.json",
    },
    PublishedType {
        definition: "sendSuccess",
        command: "send",
        rust_types: &["crate::commands::network::send::output::Report"],
        events: &[],
        example: "examples/documents/output-send-success.json",
    },
    PublishedType {
        definition: "exchangeSuccess",
        command: "exchange",
        rust_types: &["crate::commands::network::exchange::output::Report"],
        events: &[],
        example: "examples/documents/output-exchange-success.json",
    },
    PublishedType {
        definition: "differentialSuccess",
        command: "differential",
        rust_types: &[
            "crate::commands::network::differential::output::PlanReport",
            "crate::commands::network::differential::output::Report",
        ],
        events: &[],
        example: "examples/documents/output-differential-plan-success.json",
    },
    PublishedType {
        definition: "differentialResponderSuccess",
        command: "differential-responder",
        rust_types: &["crate::commands::network::differential::output::ResponderReport"],
        events: &[],
        example: "examples/documents/output-differential-responder-success.json",
    },
    PublishedType {
        definition: "differentialJoinSuccess",
        command: "differential-join",
        rust_types: &["crate::commands::network::differential::output::Report"],
        events: &[],
        example: "examples/documents/output-differential-join-success.json",
    },
    PublishedType {
        definition: "expertSuccess",
        command: "expert",
        rust_types: &["crate::output::expert::Report"],
        events: &[],
        example: "examples/documents/output-expert-complete.json",
    },
    PublishedType {
        definition: "followSuccess",
        command: "follow",
        rust_types: &["crate::output::follow::Report"],
        events: &[],
        example: "examples/documents/output-follow-complete.json",
    },
    PublishedType {
        definition: "replaySuccess",
        command: "replay",
        rust_types: &["crate::commands::network::replay::output::Report"],
        events: &[],
        example: "examples/documents/output-replay-bit-rate-success.json",
    },
    PublishedType {
        definition: "scanSuccess",
        command: "scan",
        rust_types: &["crate::commands::network::scan::output::Report"],
        events: &[],
        example: "examples/documents/output-scan-ip-protocol.json",
    },
    PublishedType {
        definition: "statsSuccess",
        command: "stats",
        rust_types: &["crate::output::stats::Report"],
        events: &[],
        example: "examples/documents/output-stats-clock.json",
    },
    PublishedType {
        definition: "tlsSuccess",
        command: "tls",
        rust_types: &["crate::output::tls::Report"],
        events: &[],
        example: "examples/documents/output-tls-success.json",
    },
    PublishedType {
        definition: "tracerouteSuccess",
        command: "traceroute",
        rust_types: &[
            "crate::commands::network::traceroute::output::Report",
            "crate::commands::network::traceroute::output::multipath::Report",
        ],
        events: &[],
        example: "examples/documents/output-traceroute-multipath-success.json",
    },
    PublishedType {
        definition: "dnsSuccess",
        command: "dns",
        rust_types: &["crate::commands::network::dns::output::BatchResult"],
        events: &[],
        example: "examples/documents/output-dns-any-success.json",
    },
    PublishedType {
        definition: "fuzzSuccess",
        command: "fuzz",
        rust_types: &["crate::commands::packet::fuzz::output::Report"],
        events: &[],
        example: "examples/documents/output-fuzz-success.json",
    },
    PublishedType {
        definition: "interfacesSuccess",
        command: "interfaces",
        rust_types: &["crate::commands::network::interfaces::output::Report"],
        events: &[],
        example: "examples/documents/output-interfaces-success.json",
    },
    PublishedType {
        definition: "routesSuccess",
        command: "routes",
        rust_types: &["crate::commands::network::routes::output::Report"],
        events: &[],
        example: "examples/documents/output-routes-success.json",
    },
    PublishedType {
        definition: "fragmentSuccess",
        command: "fragment",
        rust_types: &["crate::commands::packet::fragment::output::Report"],
        events: &[],
        example: "examples/documents/output-fragment-success.json",
    },
    PublishedType {
        definition: "mergeSuccess",
        command: "merge",
        rust_types: &["crate::commands::files::merge::output::Report"],
        events: &[],
        example: "examples/documents/output-merge-complete.json",
    },
    PublishedType {
        definition: "projectionAggregateSuccess",
        command: "dissect",
        rust_types: &["crate::output::projection::Report"],
        events: &[],
        example: "examples/documents/output-dissect-fields-success.json",
    },
    PublishedType {
        definition: "projectionAggregateSuccess",
        command: "read",
        rust_types: &["crate::output::projection::Report"],
        events: &[],
        example: "examples/documents/output-read-fields-success.json",
    },
    PublishedType {
        definition: "scanConnectSuccess",
        command: "scan",
        rust_types: &["crate::commands::network::scan::output::connect::Report"],
        events: &[],
        example: "examples/documents/output-scan-connect-success.json",
    },
    PublishedType {
        definition: "targetListSuccess",
        command: "scan",
        rust_types: &["crate::commands::network::scan::output::list::Report"],
        events: &[],
        example: "examples/documents/output-scan-list-aggregate.json",
    },
    PublishedType {
        definition: "dnsAnalysisSuccess",
        command: "dns-read",
        rust_types: &["crate::output::dns_read::Report"],
        events: &[],
        example: "examples/documents/output-dns-read-success.json",
    },
    PublishedType {
        definition: "httpSuccess",
        command: "http",
        rust_types: &["crate::output::http::Report"],
        events: &[],
        example: "examples/documents/output-http-success.json",
    },
    PublishedType {
        definition: "exportSuccess",
        command: "export",
        rust_types: &["crate::commands::files::export::output::Report"],
        events: &[],
        example: "examples/documents/output-export-complete.json",
    },
    PublishedType {
        definition: "rewriteSuccess",
        command: "rewrite",
        rust_types: &["crate::commands::files::rewrite::output::Report"],
        events: &[],
        example: "examples/documents/output-rewrite-complete.json",
    },
    PublishedType {
        definition: "captureAggregateSuccess",
        command: "capture",
        rust_types: &["crate::output::capture::Summary"],
        events: &[],
        example: "examples/documents/output-capture-complete.json",
    },
    PublishedType {
        definition: "verifyForwardingSuccess",
        command: "verify-forwarding",
        rust_types: &["crate::output::verify_forwarding::Report"],
        events: &[],
        example: "examples/documents/output-verify-forwarding-complete.json",
    },
    PublishedType {
        definition: "http2Success",
        command: "http2",
        rust_types: &["crate::output::http2::Report"],
        events: &[],
        example: "examples/documents/output-http2-success.json",
    },
    PublishedType {
        definition: "identifySuccess",
        command: "identify",
        rust_types: &["crate::commands::network::identify::output::Report"],
        events: &[],
        example: "examples/documents/output-identify-success.json",
    },
    PublishedType {
        definition: "osSuccess",
        command: "identify-os",
        rust_types: &["crate::commands::network::identify_os::output::Report"],
        events: &[],
        example: "examples/documents/output-os.json",
    },
    PublishedType {
        definition: "securitySuccess",
        command: "audit-http",
        rust_types: &["crate::output::security::Report"],
        events: &[],
        example: "examples/documents/output-audit-http-complete.json",
    },
    PublishedType {
        definition: "securitySuccess",
        command: "audit-tls",
        rust_types: &["crate::output::security::Report"],
        events: &[],
        example: "examples/documents/output-audit-tls-complete.json",
    },
    PublishedType {
        definition: "securitySuccess",
        command: "beacons",
        rust_types: &["crate::output::security::Report"],
        events: &[],
        example: "examples/documents/output-beacons-complete.json",
    },
    PublishedType {
        definition: "securitySuccess",
        command: "dns-anomalies",
        rust_types: &["crate::output::security::Report"],
        events: &[],
        example: "examples/documents/output-dns-anomalies-complete.json",
    },
    PublishedType {
        definition: "securitySuccess",
        command: "hunt",
        rust_types: &["crate::output::security::Report"],
        events: &[],
        example: "examples/documents/output-hunt-complete.json",
    },
    PublishedType {
        definition: "securitySuccess",
        command: "report",
        rust_types: &["crate::output::security::Report"],
        events: &[],
        example: "examples/documents/output-report-success.json",
    },
    PublishedType {
        definition: "securitySuccess",
        command: "scan-diff",
        rust_types: &["crate::output::security::Report"],
        events: &[],
        example: "examples/documents/output-scan-diff-complete.json",
    },
    PublishedType {
        definition: "messagesSuccess",
        command: "messages",
        rust_types: &["crate::output::messages::Report"],
        events: &[],
        example: "examples/documents/output-messages-success.json",
    },
    PublishedType {
        definition: "buildStreamSuccess",
        command: "build",
        rust_types: &[
            "crate::commands::packet::build::output::Complete",
            "crate::commands::packet::build::output::PacketEvent",
        ],
        events: &["complete", "packet"],
        example: "examples/documents/output-build-complete.json",
    },
    PublishedType {
        definition: "readSuccess",
        command: "read",
        rust_types: &[
            "crate::commands::files::read::output::Event",
            "crate::commands::files::read::output::Frame",
        ],
        events: &["complete", "frame"],
        example: "examples/documents/output-read-complete.json",
    },
    PublishedType {
        definition: "captureSuccess",
        command: "capture",
        rust_types: &[
            "crate::output::capture::Summary",
            "crate::commands::files::read::output::Frame",
        ],
        events: &["complete", "frame"],
        example: "examples/documents/output-capture-complete.json",
    },
    PublishedType {
        definition: "expertStreamSuccess",
        command: "expert",
        rust_types: &[
            "crate::output::expert::Finding",
            "crate::output::expert::Report",
            "crate::output::reassembly::Event",
        ],
        events: &[
            "complete",
            "finding",
            "ip_datagram_completed",
            "ip_datagram_incomplete",
            "ip_overlap_resolved",
        ],
        example: "examples/documents/output-expert-complete.json",
    },
    PublishedType {
        definition: "followStreamSuccess",
        command: "follow",
        rust_types: &[
            "crate::output::follow::Chunk",
            "crate::output::follow::Report",
            "crate::output::reassembly::Event",
        ],
        events: &[
            "chunk",
            "complete",
            "ip_datagram_completed",
            "ip_datagram_incomplete",
            "ip_overlap_resolved",
        ],
        example: "examples/documents/output-follow-complete.json",
    },
    PublishedType {
        definition: "exchangeStreamSuccess",
        command: "exchange",
        rust_types: &["crate::commands::network::exchange::output::Event"],
        events: &[
            "complete",
            "diagnostic",
            "response",
            "sent",
            "unanswered",
            "undecoded",
            "unsolicited",
        ],
        example: "examples/documents/output-exchange-complete.json",
    },
    PublishedType {
        definition: "differentialStreamSuccess",
        command: "differential",
        rust_types: &["crate::commands::network::differential::output::Event"],
        events: &["attempt", "complete", "diagnostic"],
        example: "examples/documents/output-differential-attempt-event.json",
    },
    PublishedType {
        definition: "differentialResponderStreamSuccess",
        command: "differential-responder",
        rust_types: &["crate::commands::network::differential::output::ResponderEvent"],
        events: &["complete", "received"],
        example: "examples/documents/output-differential-responder-complete.json",
    },
    PublishedType {
        definition: "replayFrameSuccess",
        command: "replay",
        rust_types: &[
            "crate::commands::network::replay::output::Frame",
            "crate::commands::network::replay::output::Report",
        ],
        events: &["complete", "frame"],
        example: "examples/documents/output-replay-complete.json",
    },
    PublishedType {
        definition: "scanStreamSuccess",
        command: "scan",
        rust_types: &[
            "crate::commands::network::scan::output::event::Event",
            "crate::commands::network::scan::output::host::Host",
            "crate::commands::network::traceroute::output::hosts::Event",
        ],
        events: &[
            "complete",
            "diagnostic",
            "endpoint",
            "host",
            "observation_quality",
            "probe",
            "probe_sent",
            "traceroute_host",
            "traceroute_probe",
            "traceroute_undecoded",
            "unattributed",
            "undecoded",
        ],
        example: "examples/documents/output-scan-complete.json",
    },
    PublishedType {
        definition: "tracerouteStreamSuccess",
        command: "traceroute",
        rust_types: &[
            "crate::commands::network::traceroute::output::Event",
            "crate::commands::network::traceroute::output::hosts::Event",
            "crate::commands::network::traceroute::output::multipath::Event",
        ],
        events: &[
            "complete",
            "diagnostic",
            "flow",
            "flow_complete",
            "probe",
            "topology",
            "undecoded",
            "unmatched",
        ],
        example: "examples/documents/output-traceroute-complete.json",
    },
    PublishedType {
        definition: "dnsStreamSuccess",
        command: "dns",
        rust_types: &["crate::commands::network::dns::output::report::Event"],
        events: &[
            "attempt",
            "complete",
            "diagnostic",
            "record",
            "rejected",
            "undecoded",
        ],
        example: "examples/documents/output-dns-attempt-response-event.json",
    },
    PublishedType {
        definition: "fuzzCaseSuccess",
        command: "fuzz",
        rust_types: &["crate::commands::packet::fuzz::output::Event"],
        events: &["case", "complete"],
        example: "examples/documents/output-fuzz-complete.json",
    },
    PublishedType {
        definition: "tlsStreamSuccess",
        command: "tls",
        rust_types: &[
            "crate::output::reassembly::Event",
            "crate::output::tls::Event",
        ],
        events: &[
            "complete",
            "ip_datagram_completed",
            "ip_datagram_incomplete",
            "ip_overlap_resolved",
            "session",
        ],
        example: "examples/documents/output-tls-alert-event.json",
    },
    PublishedType {
        definition: "fragmentStreamSuccess",
        command: "fragment",
        rust_types: &[
            "crate::commands::packet::fragment::output::Complete",
            "crate::commands::packet::fragment::output::Fragment",
        ],
        events: &["complete", "fragment"],
        example: "examples/documents/output-fragment-complete.json",
    },
    PublishedType {
        definition: "mergeStreamSuccess",
        command: "merge",
        rust_types: &["crate::commands::files::merge::output::Report"],
        events: &["complete"],
        example: "examples/documents/output-merge-complete.json",
    },
    PublishedType {
        definition: "projectionStreamSuccess",
        command: "capture",
        rust_types: &[
            "crate::output::projection::Complete",
            "crate::output::projection::RowEvent",
        ],
        events: &["complete", "fields"],
        example: "examples/documents/output-dissect-complete.json",
    },
    PublishedType {
        definition: "projectionStreamSuccess",
        command: "dissect",
        rust_types: &[
            "crate::output::projection::Complete",
            "crate::output::projection::RowEvent",
        ],
        events: &["complete", "fields"],
        example: "examples/documents/output-dissect-complete.json",
    },
    PublishedType {
        definition: "projectionStreamSuccess",
        command: "read",
        rust_types: &[
            "crate::output::projection::Complete",
            "crate::output::projection::RowEvent",
        ],
        events: &["complete", "fields"],
        example: "examples/documents/output-read-fields-complete.json",
    },
    PublishedType {
        definition: "scanConnectStreamSuccess",
        command: "scan",
        rust_types: &[
            "crate::commands::network::scan::output::connect::EndpointEvent",
            "crate::commands::network::scan::output::connect::ProbeEvent",
            "crate::commands::network::scan::output::connect::Report",
        ],
        events: &["complete", "connect_endpoint", "connect_probe"],
        example: "examples/documents/output-scan-connect-complete.json",
    },
    PublishedType {
        definition: "targetListStreamSuccess",
        command: "scan",
        rust_types: &[
            "crate::commands::network::scan::output::list::Complete",
            "crate::commands::network::scan::output::list::TargetEvent",
        ],
        events: &["complete", "target"],
        example: "examples/documents/output-scan-list-complete.json",
    },
    PublishedType {
        definition: "dnsAnalysisStreamSuccess",
        command: "dns-read",
        rust_types: &[
            "crate::output::dns_read::Issue",
            "crate::output::dns_read::Message",
            "crate::output::dns_read::Report",
            "crate::output::dns_read::Transaction",
            "crate::output::reassembly::Event",
        ],
        events: &[
            "complete",
            "dns_message",
            "dns_stream_issue",
            "dns_transaction",
            "ip_datagram_completed",
            "ip_datagram_incomplete",
            "ip_overlap_resolved",
        ],
        example: "examples/documents/output-dns-read-complete.json",
    },
    PublishedType {
        definition: "httpStreamSuccess",
        command: "http",
        rust_types: &[
            "crate::output::http::Issue",
            "crate::output::http::Message",
            "crate::output::http::Report",
            "crate::output::reassembly::Event",
        ],
        events: &[
            "complete",
            "http_message",
            "http_stream_issue",
            "ip_datagram_completed",
            "ip_datagram_incomplete",
            "ip_overlap_resolved",
        ],
        example: "examples/documents/output-http-complete.json",
    },
    PublishedType {
        definition: "exportStreamSuccess",
        command: "export",
        rust_types: &["crate::commands::files::export::output::Report"],
        events: &["complete"],
        example: "examples/documents/output-export-complete.json",
    },
    PublishedType {
        definition: "rewriteStreamSuccess",
        command: "rewrite",
        rust_types: &["crate::commands::files::rewrite::output::Report"],
        events: &["complete"],
        example: "examples/documents/output-rewrite-complete.json",
    },
    PublishedType {
        definition: "verifyForwardingStreamSuccess",
        command: "verify-forwarding",
        rust_types: &["crate::output::verify_forwarding::Report"],
        events: &["complete"],
        example: "examples/documents/output-verify-forwarding-complete.json",
    },
    PublishedType {
        definition: "http2StreamSuccess",
        command: "http2",
        rust_types: &[
            "crate::output::http2::Connection",
            "crate::output::http2::Issue",
            "crate::output::http2::Message",
            "crate::output::http2::Report",
            "crate::output::http2::frame::Frame",
            "crate::output::reassembly::Event",
        ],
        events: &[
            "complete",
            "http2_connection",
            "http2_frame",
            "http2_issue",
            "http2_message",
            "ip_datagram_completed",
            "ip_datagram_incomplete",
            "ip_overlap_resolved",
        ],
        example: "examples/documents/output-http2-complete.json",
    },
    PublishedType {
        definition: "identifyStreamSuccess",
        command: "identify",
        rust_types: &[
            "crate::commands::network::identify::output::Complete",
            "crate::commands::network::identify::output::Record",
        ],
        events: &["complete", "identify_endpoint"],
        example: "examples/documents/output-identify-complete.json",
    },
    PublishedType {
        definition: "osStreamSuccess",
        command: "identify-os",
        rust_types: &["crate::commands::network::identify_os::output::Event"],
        events: &[
            "complete",
            "diagnostic",
            "os_additional",
            "os_preparation",
            "os_probe",
            "os_undecoded",
        ],
        example: "examples/documents/output-os-complete.json",
    },
    PublishedType {
        definition: "securityStreamSuccess",
        command: "audit-http",
        rust_types: &[
            "crate::output::security::FindingRecord",
            "crate::output::security::Report",
        ],
        events: &["complete", "finding"],
        example: "examples/documents/output-audit-http-complete.json",
    },
    PublishedType {
        definition: "securityStreamSuccess",
        command: "audit-tls",
        rust_types: &[
            "crate::output::security::FindingRecord",
            "crate::output::security::Report",
        ],
        events: &["complete", "finding"],
        example: "examples/documents/output-audit-tls-complete.json",
    },
    PublishedType {
        definition: "securityStreamSuccess",
        command: "beacons",
        rust_types: &[
            "crate::output::security::FindingRecord",
            "crate::output::security::Report",
        ],
        events: &["complete", "finding"],
        example: "examples/documents/output-beacons-complete.json",
    },
    PublishedType {
        definition: "securityStreamSuccess",
        command: "dns-anomalies",
        rust_types: &[
            "crate::output::security::FindingRecord",
            "crate::output::security::Report",
        ],
        events: &["complete", "finding"],
        example: "examples/documents/output-dns-anomalies-complete.json",
    },
    PublishedType {
        definition: "securityStreamSuccess",
        command: "hunt",
        rust_types: &[
            "crate::output::security::FindingRecord",
            "crate::output::security::Report",
        ],
        events: &["complete", "finding"],
        example: "examples/documents/output-hunt-complete.json",
    },
    PublishedType {
        definition: "securityStreamSuccess",
        command: "scan-diff",
        rust_types: &[
            "crate::output::security::FindingRecord",
            "crate::output::security::Report",
        ],
        events: &["complete", "finding"],
        example: "examples/documents/output-scan-diff-complete.json",
    },
    PublishedType {
        definition: "messagesStreamSuccess",
        command: "messages",
        rust_types: &[
            "crate::output::messages::Issue",
            "crate::output::messages::Message",
            "crate::output::messages::Report",
            "crate::output::reassembly::Event",
        ],
        events: &[
            "complete",
            "ip_datagram_completed",
            "ip_datagram_incomplete",
            "ip_overlap_resolved",
            "protocol_issue",
            "protocol_message",
        ],
        example: "examples/documents/output-messages-complete.json",
    },
];
