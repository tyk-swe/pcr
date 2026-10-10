// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use packetcraftr::identify::Limits;

use crate::command_options::{Bounded, IdentificationPolicyArgs};

pub(crate) const AFTER_LONG_HELP: &str = r"Examples:
  packetcraftr identify 127.0.0.1:8080 --transport tcp
  packetcraftr --output json identify 192.0.2.53:5353 --transport udp
  packetcraftr --output ndjson identify '[::1]:2222' --intensity 1
  packetcraftr identify 192.0.2.1:8080 --corpus service-probes.json

Select numeric endpoints reported by a scan explicitly. A scan never starts
identification. Requests are reviewed, bounded and read-only; no authentication,
hostname resolution, redirects, or TLS negotiation is performed. Received fields
are unauthenticated claims. Matched versions are not vulnerability findings.
Sensitive-service exclusions apply before planning; --ignore-exclusions is an
explicit override. JSON aggregates results; NDJSON emits one endpoint record per
selected endpoint followed by exactly one complete or error terminal record.";

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub(crate) enum Transport {
    Tcp,
    Udp,
}

impl From<Transport> for packetcraftr_core::document::service_probes::Transport {
    fn from(value: Transport) -> Self {
        match value {
            Transport::Tcp => Self::Tcp,
            Transport::Udp => Self::Udp,
        }
    }
}

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Selected numeric IP:port endpoints; IPv6 uses `[address]:port`.
    #[arg(value_name = "ENDPOINT", required = true)]
    pub(crate) endpoints: Vec<SocketAddr>,
    /// Transport of every selected endpoint; services may use any port.
    #[arg(long, value_enum, default_value = "tcp")]
    pub(crate) transport: Transport,
    /// Versioned, bounded JSON probe and match corpus; default is bundled data.
    #[arg(long, value_name = "PATH")]
    pub(crate) corpus: Option<PathBuf>,
    /// Versioned sensitive-service exclusions; default is bundled reviewed data.
    #[arg(long, value_name = "PATH", conflicts_with = "ignore_exclusions")]
    pub(crate) exclusions: Option<PathBuf>,
    /// Explicitly disable sensitive-service exclusions for this operation.
    #[arg(long)]
    pub(crate) ignore_exclusions: bool,
    /// Maximum probe intensity; only corpus probes at or below it are planned.
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u8).range(1..=9))]
    pub(crate) intensity: u8,
    /// Maximum operation duration, including preparation and publication.
    #[arg(long, default_value_t = 35_000, value_parser = clap::value_parser!(u64).range(1..=3_600_000))]
    pub(crate) max_duration_ms: u64,
    /// Maximum identification duration; partial evidence is published on expiry.
    #[arg(long, default_value_t = millis(Limits::default().operation.timeout))]
    pub(crate) operation_timeout_ms: u64,
    /// Maximum attempts across the operation.
    #[arg(long, default_value_t = Limits::default().operation.attempts)]
    pub(crate) max_attempts: u64,
    /// Maximum application bytes written across the operation.
    #[arg(long, default_value_t = Limits::default().operation.write_bytes)]
    pub(crate) max_write_bytes: u64,
    /// Maximum exact response bytes retained across the operation.
    #[arg(long, default_value_t = Limits::default().operation.read_bytes)]
    pub(crate) max_read_bytes: u64,
    /// Maximum elapsed time for one numeric host.
    #[arg(long, default_value_t = millis(Limits::default().host.timeout))]
    pub(crate) host_timeout_ms: u64,
    /// Maximum attempts for one numeric host.
    #[arg(long, default_value_t = Limits::default().host.attempts)]
    pub(crate) host_max_attempts: u64,
    /// Maximum application bytes written to one numeric host.
    #[arg(long, default_value_t = Limits::default().host.write_bytes)]
    pub(crate) host_max_write_bytes: u64,
    /// Maximum response bytes read from one numeric host.
    #[arg(long, default_value_t = Limits::default().host.read_bytes)]
    pub(crate) host_max_read_bytes: u64,
    /// Maximum duration of one connection or datagram exchange.
    #[arg(long, default_value_t = millis(Limits::default().connection.timeout))]
    pub(crate) connection_timeout_ms: u64,
    /// Maximum attempts admitted to one connection.
    #[arg(long, default_value_t = Limits::default().connection.attempts)]
    pub(crate) connection_max_attempts: u64,
    /// Maximum application bytes written on one connection.
    #[arg(long, default_value_t = Limits::default().connection.write_bytes)]
    pub(crate) connection_max_write_bytes: u64,
    /// Maximum response bytes read on one connection.
    #[arg(long, default_value_t = Limits::default().connection.read_bytes)]
    pub(crate) connection_max_read_bytes: u64,
    /// Maximum duration of one probe.
    #[arg(long, default_value_t = millis(Limits::default().probe.timeout))]
    pub(crate) probe_timeout_ms: u64,
    /// Maximum attempts for one corpus probe at one endpoint.
    #[arg(long, default_value_t = Limits::default().probe.attempts)]
    pub(crate) probe_max_attempts: u64,
    /// Maximum application bytes written by one probe.
    #[arg(long, default_value_t = Limits::default().probe.write_bytes)]
    pub(crate) probe_max_write_bytes: u64,
    /// Maximum response bytes read by one probe.
    #[arg(long, default_value_t = Limits::default().probe.read_bytes)]
    pub(crate) probe_max_read_bytes: u64,
    #[command(flatten)]
    pub(crate) policy: IdentificationPolicyArgs,
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).expect("default identification duration fits u64")
}

impl Bounded for Args {
    fn max_duration(&self) -> Duration {
        Duration::from_millis(self.max_duration_ms)
    }
}
