use crate::commands::offline_analysis::output::{Clock, Endpoint, Scope};
use crate::output::{contract, published_enum};
use packetcraftr_core::analysis::{self, quic};
use serde::Serialize;

published_enum! { pub(crate) enum Direction from quic::Direction { Client => "client", Server => "server", } }
published_enum! { pub(crate) enum EarlyData from quic::EarlyData {
    NotObserved => "not_observed", Unknown => "unknown", Accepted => "accepted", Rejected => "rejected",
} }
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Path {
    pub source: Endpoint,
    pub destination: Endpoint,
}
impl From<analysis::FlowKey> for Path {
    fn from(flow: analysis::FlowKey) -> Self {
        Self {
            source: analysis::Endpoint {
                address: flow.source,
                port: flow.source_port,
            }
            .into(),
            destination: analysis::Endpoint {
                address: flow.destination,
                port: flow.destination_port,
            }
            .into(),
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Range {
    pub offset: u64,
    pub length: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
}
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Stream {
    pub id: u64,
    pub direction: Direction,
    pub ranges: Vec<Range>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reset_error: Option<u64>,
    pub complete: bool,
    pub conflicting_overlap: bool,
    pub final_size_error: bool,
    pub omitted_bytes: u64,
    pub early_data: bool,
}
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Diagnostic {
    pub frame: u64,
    pub code: String,
    pub message: String,
}
impl From<quic::Diagnostic> for Diagnostic {
    fn from(d: quic::Diagnostic) -> Self {
        Self {
            frame: d.frame,
            code: d.code,
            message: d.message,
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub(crate) struct TransportParameter {
    pub id: u64,
    pub value_hex: String,
}
impl From<quic::TransportParameter> for TransportParameter {
    fn from(p: quic::TransportParameter) -> Self {
        Self {
            id: p.id,
            value_hex: p.value_hex,
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Connection {
    pub connection: u64,
    pub scope: Scope,
    pub version: u32,
    pub client_endpoint: Endpoint,
    pub server_endpoint: Endpoint,
    pub first_frame: u64,
    pub last_frame: u64,
    pub source_frames: Vec<u64>,
    pub source_frames_omitted: u64,
    pub connection_ids: Vec<String>,
    pub paths: Vec<Path>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    pub sni_is_outer: bool,
    pub offered_alpn: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub negotiated_alpn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher_suite: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja3: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_hello_frame: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_hello_frame: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hello_elapsed_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_finished_frame: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_finished_frame: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handshake_done_frame: Option<u64>,
    pub early_data: EarlyData,
    pub client_transport_parameters: Vec<TransportParameter>,
    pub server_transport_parameters: Vec<TransportParameter>,
    pub streams: Vec<Stream>,
    pub metrics: Metrics,
    pub diagnostics: Vec<Diagnostic>,
    pub diagnostics_omitted: u64,
    pub pending_packets: u64,
    pub closed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub close_error: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub close_reason: Option<String>,
    pub stateless_reset: bool,
    pub incomplete: bool,
    pub end_reason: String,
}
impl Connection {
    pub(super) fn from_core(
        c: quic::Connection,
        streams: Vec<Stream>,
    ) -> Result<Self, contract::Error> {
        Ok(Self {
            connection: c.connection,
            scope: Scope::try_from(c.scope)?,
            version: c.version,
            client_endpoint: c.client_endpoint.into(),
            server_endpoint: c.server_endpoint.into(),
            first_frame: c.first_frame,
            last_frame: c.last_frame,
            source_frames: c.source_frames,
            source_frames_omitted: c.source_frames_omitted,
            connection_ids: c.connection_ids,
            paths: c.paths.into_iter().map(Path::from).collect(),
            sni: c.sni,
            sni_is_outer: c.sni_is_outer,
            offered_alpn: c.offered_alpn,
            negotiated_alpn: c.negotiated_alpn,
            cipher_suite: c.cipher_suite,
            ja3: c.ja3,
            ja4: c.ja4,
            client_hello_frame: c.client_hello_frame,
            server_hello_frame: c.server_hello_frame,
            hello_elapsed_ms: c.hello_elapsed_ms,
            client_finished_frame: c.client_finished_frame,
            server_finished_frame: c.server_finished_frame,
            handshake_done_frame: c.handshake_done_frame,
            early_data: c.early_data.into(),
            client_transport_parameters: c
                .client_transport_parameters
                .into_iter()
                .map(TransportParameter::from)
                .collect(),
            server_transport_parameters: c
                .server_transport_parameters
                .into_iter()
                .map(TransportParameter::from)
                .collect(),
            streams,
            metrics: c.metrics.into(),
            diagnostics: c.diagnostics.into_iter().map(Diagnostic::from).collect(),
            diagnostics_omitted: c.diagnostics_omitted,
            pending_packets: c.pending_packets,
            closed: c.closed,
            close_error: c.close_error,
            close_reason: c.close_reason,
            stateless_reset: c.stateless_reset,
            incomplete: c.incomplete,
            end_reason: c.end_reason,
        })
    }
}
#[derive(Debug, Serialize)]
pub(crate) struct Summary {
    pub engine: EngineSummary,
    pub frames_read: u64,
    pub frames_matched: u64,
    pub bytes_read: u64,
    pub clock: Clock,
    pub ip_reassembly: crate::commands::offline_analysis::output::reassembly::Report,
    pub incomplete_sources: u64,
    pub source_outcomes_omitted: u64,
    pub input_incomplete: bool,
    pub connections_selected: u64,
    pub connections_omitted: u64,
    pub application_output_bytes: u64,
}
#[derive(Debug, Serialize)]
pub(crate) struct Report {
    pub connections: Vec<Connection>,
    pub summary: Summary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture: Option<crate::output::capture::Snapshot>,
}
#[derive(Debug, Serialize)]
pub(crate) struct StreamData {
    pub connection: u64,
    pub stream: u64,
    pub direction: Direction,
    pub offset: u64,
    pub data_hex: String,
    pub early_data: bool,
}
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub(crate) enum Event {
    Connection {
        connection: Box<Connection>,
    },
    StreamData {
        stream_data: StreamData,
    },
    Complete {
        summary: Box<Summary>,
        #[serde(skip_serializing_if = "Option::is_none")]
        capture: Option<Box<crate::output::capture::Snapshot>>,
    },
}
impl crate::output::stream::StreamRecord for Event {
    fn event_name(&self) -> &'static str {
        match self {
            Self::Connection { .. } => "connection",
            Self::StreamData { .. } => "stream_data",
            Self::Complete { .. } => "complete",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Metrics {
    pub packets: u64,
    pub decrypted_packets: u64,
    pub initial_packets: u64,
    pub handshake_packets: u64,
    pub zero_rtt_packets: u64,
    pub one_rtt_packets: u64,
    pub duplicate_packets: u64,
    pub reordered_packets: u64,
    pub observed_packet_gaps: u64,
    pub repeated_stream_bytes: u64,
    pub datagrams: u64,
    pub datagram_bytes: u64,
    pub flow_control_blocks: u64,
    pub key_updates: u64,
    pub path_challenges: u64,
    pub validated_paths: u64,
    pub retry_packets: u64,
    pub authentication_failures: u64,
    pub ack_samples: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_ack_elapsed_ms: Option<f64>,
}
impl From<quic::Metrics> for Metrics {
    fn from(value: quic::Metrics) -> Self {
        Self {
            packets: value.packets,
            decrypted_packets: value.decrypted_packets,
            initial_packets: value.initial_packets,
            handshake_packets: value.handshake_packets,
            zero_rtt_packets: value.zero_rtt_packets,
            one_rtt_packets: value.one_rtt_packets,
            duplicate_packets: value.duplicate_packets,
            reordered_packets: value.reordered_packets,
            observed_packet_gaps: value.observed_packet_gaps,
            repeated_stream_bytes: value.repeated_stream_bytes,
            datagrams: value.datagrams,
            datagram_bytes: value.datagram_bytes,
            flow_control_blocks: value.flow_control_blocks,
            key_updates: value.key_updates,
            path_challenges: value.path_challenges,
            validated_paths: value.validated_paths,
            retry_packets: value.retry_packets,
            authentication_failures: value.authentication_failures,
            ack_samples: value.ack_samples,
            min_ack_elapsed_ms: value.min_ack_elapsed_ms,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct EngineSummary {
    pub connections: u64,
    pub packets: u64,
    pub decrypted_packets: u64,
    pub connections_evicted: u64,
    pub buffer_limit_hits: u64,
    pub unsupported_versions: u64,
    pub unassociated_packets: u64,
    pub malformed_datagrams: u64,
    pub ambiguous_packets: u64,
    pub keylog_records_added: u64,
    pub keylog_records_rejected: u64,
}
impl From<quic::Summary> for EngineSummary {
    fn from(value: quic::Summary) -> Self {
        Self {
            connections: value.connections,
            packets: value.packets,
            decrypted_packets: value.decrypted_packets,
            connections_evicted: value.connections_evicted,
            buffer_limit_hits: value.buffer_limit_hits,
            unsupported_versions: value.unsupported_versions,
            unassociated_packets: value.unassociated_packets,
            malformed_datagrams: value.malformed_datagrams,
            ambiguous_packets: value.ambiguous_packets,
            keylog_records_added: value.keylog_records_added,
            keylog_records_rejected: value.keylog_records_rejected,
        }
    }
}
