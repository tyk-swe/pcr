use crate::analysis::{Endpoint, FlowKey, scope};
use bytes::Bytes;
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Client,
    Server,
}
impl Direction {
    pub const fn index(self) -> usize {
        match self {
            Self::Client => 0,
            Self::Server => 1,
        }
    }
    pub const fn reverse(self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EarlyData {
    NotObserved,
    Unknown,
    Accepted,
    Rejected,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Range {
    pub offset: u64,
    pub data: Bytes,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Stream {
    pub id: u64,
    pub direction: Direction,
    pub ranges: Vec<Range>,
    pub final_size: Option<u64>,
    pub reset_error: Option<u64>,
    pub complete: bool,
    pub conflicting_overlap: bool,
    pub final_size_error: bool,
    pub omitted_bytes: u64,
    pub early_data: bool,
}
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Metrics {
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
    pub min_ack_elapsed_ms: Option<f64>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Diagnostic {
    pub frame: u64,
    pub code: String,
    pub message: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TransportParameter {
    pub id: u64,
    pub value_hex: String,
}
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Connection {
    pub connection: u64,
    pub scope: scope::Definition,
    pub version: u32,
    pub client_endpoint: Endpoint,
    pub server_endpoint: Endpoint,
    pub first_frame: u64,
    pub last_frame: u64,
    pub source_frames: Vec<u64>,
    pub source_frames_omitted: u64,
    pub connection_ids: Vec<String>,
    pub paths: Vec<FlowKey>,
    pub sni: Option<String>,
    pub sni_is_outer: bool,
    pub offered_alpn: Vec<String>,
    pub negotiated_alpn: Option<String>,
    pub cipher_suite: Option<u16>,
    pub ja3: Option<String>,
    pub ja4: Option<String>,
    pub client_hello_frame: Option<u64>,
    pub server_hello_frame: Option<u64>,
    pub hello_elapsed_ms: Option<f64>,
    pub client_finished_frame: Option<u64>,
    pub server_finished_frame: Option<u64>,
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
    pub close_error: Option<u64>,
    pub close_reason: Option<String>,
    pub stateless_reset: bool,
    pub incomplete: bool,
    pub end_reason: String,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
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
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    Connection { connection: Box<Connection> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_connections: usize,
    pub max_buffered_bytes: usize,
    pub max_stream_bytes: usize,
    pub max_pending_packets: usize,
    pub max_streams_per_connection: usize,
    pub max_ranges: usize,
    pub max_connection_ids: usize,
    pub max_diagnostics: usize,
    pub idle_expiry: std::time::Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: 8192,
            max_buffered_bytes: 64 * 1024 * 1024,
            max_stream_bytes: 1024 * 1024,
            max_pending_packets: 64,
            max_streams_per_connection: 4096,
            max_ranges: 4096,
            max_connection_ids: 64,
            max_diagnostics: 64,
            idle_expiry: std::time::Duration::from_secs(120),
        }
    }
}
impl Limits {
    pub fn validate(&self) -> Result<(), super::Error> {
        if [
            self.max_connections,
            self.max_buffered_bytes,
            self.max_stream_bytes,
            self.max_pending_packets,
            self.max_streams_per_connection,
            self.max_ranges,
            self.max_connection_ids,
            self.max_diagnostics,
        ]
        .contains(&0)
            || self.idle_expiry.is_zero()
        {
            return Err(super::Error::Limit);
        }
        Ok(())
    }
}
