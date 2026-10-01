// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use clap::{Args, ValueEnum};
use packetcraftr_core::conversation::{
    self, Close, Conversation, DEFAULT_CLIENT_ISN, DEFAULT_MSS, DEFAULT_SERVER_ISN, MAX_FRAMES,
    Protocol,
};
use packetcraftr_core::error::Kind;
use packetcraftr_core::packet::Packet;
use packetcraftr_core::registry::Registry;

use crate::command_options::PacketBudgetArgs;
use crate::errors::CliError;
use crate::input::{InputKind, read_bounded_file_allow_empty};

/// The nanoseconds between generated frames when --session-step-ns is absent.
const DEFAULT_STEP_NS: u64 = 1_000_000;
/// The largest UDP payload an IPv4 datagram can carry.
const MAX_UDP_RESPONSE_IPV4: usize = 65_507;
/// The largest UDP payload an IPv6 datagram can carry.
const MAX_UDP_RESPONSE_IPV6: usize = 65_527;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum SessionProtocol {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum SessionClose {
    Fin,
    Rst,
    None,
}

impl From<SessionClose> for Close {
    fn from(value: SessionClose) -> Self {
        match value {
            SessionClose::Fin => Self::Fin,
            SessionClose::Rst => Self::Rst,
            SessionClose::None => Self::None,
        }
    }
}

/// Options that expand the recipe into a deterministic conversation.
#[derive(Debug, Args)]
pub(crate) struct SessionArgs {
    /// Expand the recipe, a client-to-server packet, into a complete TCP or
    /// UDP conversation. Its layers after the transport are the client
    /// request. TCP adds the handshake, MSS-sized segments with their ACKs,
    /// the response, and the close; UDP adds one reply frame. Reverse frames
    /// swap Ethernet and IP addresses and ports. A UDP request keeps its typed
    /// layers; a TCP request and every response are raw bytes, which strict
    /// mode refuses on a UDP port that dissects a protocol, such as a reply
    /// from port 53, so use --mode permissive there. At most 4096 frames;
    /// conflicts with --axis.
    #[arg(
        long = "session",
        value_enum,
        value_name = "tcp|udp",
        conflicts_with = "axes"
    )]
    pub(crate) session: Option<SessionProtocol>,
    /// File holding the server's response payload; without it the server only
    /// acknowledges.
    #[arg(
        long = "session-response-file",
        value_name = "PATH",
        requires = "session"
    )]
    response_file: Option<PathBuf>,
    /// Largest TCP payload per segment, 1..=65535 and within the recipe's TCP
    /// window. Defaults to 1460.
    #[arg(
        long = "session-mss",
        value_name = "N",
        requires = "session",
        value_parser = clap::value_parser!(u16).range(1..)
    )]
    mss: Option<u16>,
    /// How the TCP conversation ends: a FIN/ACK exchange, one RST, or an open
    /// flow. Defaults to fin.
    #[arg(
        long = "session-close",
        value_enum,
        value_name = "fin|rst|none",
        requires = "session"
    )]
    close: Option<SessionClose>,
    /// Client initial sequence number. Defaults to 268435456.
    #[arg(long = "session-client-isn", value_name = "N", requires = "session")]
    client_isn: Option<u32>,
    /// Server initial sequence number. Defaults to 536870912.
    #[arg(long = "session-server-isn", value_name = "N", requires = "session")]
    server_isn: Option<u32>,
    /// Nanoseconds between consecutive frames, starting at --timestamp.
    /// Requires PCAP or PCAPNG output. Defaults to 1000000.
    #[arg(
        long = "session-step-ns",
        value_name = "NANOSECONDS",
        requires = "session"
    )]
    step_ns: Option<u64>,
}

/// A resolved conversation request.
pub(crate) struct Session {
    conversation: Conversation,
    protocol: SessionProtocol,
    response: Bytes,
    pub(crate) step: Duration,
    /// Whether the step was chosen, which only capture output can honor.
    pub(crate) step_chosen: bool,
}

impl SessionArgs {
    /// Validates the options and reads the response. `maximum` is the packet
    /// budget the conversation's frame count and byte total stay within.
    pub(crate) fn resolve(
        self,
        registry: &Arc<Registry>,
        budget: PacketBudgetArgs,
        mode: packetcraftr_core::codec::Mode,
        maximum: usize,
    ) -> Result<Option<Session>, CliError> {
        let Some(protocol) = self.session else {
            return Ok(None);
        };
        let mut options = conversation::Options::new(match protocol {
            SessionProtocol::Tcp => Protocol::Tcp,
            SessionProtocol::Udp => Protocol::Udp,
        });
        if matches!(protocol, SessionProtocol::Udp) {
            for (name, given) in [
                ("--session-mss", self.mss.is_some()),
                ("--session-close", self.close.is_some()),
                ("--session-client-isn", self.client_isn.is_some()),
                ("--session-server-isn", self.server_isn.is_some()),
            ] {
                if given {
                    return Err(CliError::new(
                        Kind::Usage,
                        format!("{name} requires --session tcp"),
                    ));
                }
            }
        }
        options.mss = self.mss.unwrap_or(DEFAULT_MSS);
        options.close = self.close.map_or(Close::Fin, Close::from);
        options.client_isn = self.client_isn.unwrap_or(DEFAULT_CLIENT_ISN);
        options.server_isn = self.server_isn.unwrap_or(DEFAULT_SERVER_ISN);
        options.max_frames = maximum.min(MAX_FRAMES);
        let response = match &self.response_file {
            Some(path) => {
                let byte_budget = maximum.saturating_mul(budget.max_packet_size);
                let limit = match protocol {
                    SessionProtocol::Tcp => options
                        .max_frames
                        .saturating_mul(usize::from(options.mss))
                        .min(byte_budget),
                    // The recipe is not parsed yet, so the read takes the
                    // looser IPv6 ceiling; `expand` applies the recipe's own.
                    SessionProtocol::Udp => MAX_UDP_RESPONSE_IPV6.min(byte_budget),
                };
                let bytes = read_bounded_file_allow_empty(path, limit, InputKind::SessionResponse)?;
                if bytes.is_empty() {
                    return Err(CliError::new(
                        Kind::Usage,
                        format!(
                            "session response file {} is empty; omit --session-response-file for a server that only acknowledges",
                            path.display()
                        ),
                    ));
                }
                Bytes::from(bytes)
            }
            None => Bytes::new(),
        };
        let conversation = Conversation::new(Arc::clone(registry), options)
            .with_build_options(budget.build_options(mode));
        Ok(Some(Session {
            conversation,
            protocol,
            response,
            step: Duration::from_nanos(self.step_ns.unwrap_or(DEFAULT_STEP_NS)),
            step_chosen: self.step_ns.is_some(),
        }))
    }
}

/// The UDP payload the recipe's network layer can carry: 20 bytes of header
/// room under IPv4's total length, only the 16-bit payload length under IPv6.
fn udp_response_limit(recipe: &Packet) -> (usize, &'static str) {
    for layer in recipe.iter() {
        if layer.is::<packetcraftr_core::protocol::network::Ipv6>() {
            return (MAX_UDP_RESPONSE_IPV6, "IPv6");
        }
        if layer.is::<packetcraftr_core::protocol::network::Ipv4>() {
            return (MAX_UDP_RESPONSE_IPV4, "IPv4");
        }
    }
    (MAX_UDP_RESPONSE_IPV4, "IPv4")
}

impl Session {
    /// Expands `recipe` into the whole conversation, checking its size first.
    pub(crate) fn expand(&self, recipe: &Packet) -> Result<Vec<Packet>, CliError> {
        if matches!(self.protocol, SessionProtocol::Udp) && !self.response.is_empty() {
            let (limit, family) = udp_response_limit(recipe);
            if self.response.len() > limit {
                return Err(CliError::new(
                    Kind::Usage,
                    format!(
                        "session response input exceeds {limit} byte limit for the recipe's {family} network layer"
                    ),
                ));
            }
        }
        self.conversation
            .expand(recipe, &self.response)
            .map_err(CliError::classified)
    }
}

/// The timestamp of the `ordinal`th frame, `step` after the previous one.
pub(crate) fn frame_timestamp(
    base: SystemTime,
    step: Duration,
    ordinal: u64,
) -> Result<SystemTime, CliError> {
    let nanoseconds = step.as_nanos().saturating_mul(u128::from(ordinal));
    let offset = u64::try_from(nanoseconds / 1_000_000_000)
        .ok()
        .and_then(|seconds| {
            // The remainder is below one second, so it fits u32.
            let sub = u32::try_from(nanoseconds % 1_000_000_000).ok()?;
            Some(Duration::new(seconds, sub))
        });
    offset
        .and_then(|offset| base.checked_add(offset))
        .ok_or_else(|| {
            CliError::new(
                Kind::Usage,
                "--session-step-ns moves a frame timestamp outside the representable range",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_timestamps_advance_by_the_step_and_refuse_overflow() {
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        assert_eq!(
            frame_timestamp(base, Duration::from_nanos(1_500_000_000), 3).unwrap(),
            base + Duration::new(4, 500_000_000),
        );
        assert_eq!(frame_timestamp(base, Duration::ZERO, 4095).unwrap(), base);
        let error = frame_timestamp(base, Duration::from_nanos(u64::MAX), u64::MAX)
            .expect_err("the offset exceeds the clock range");
        assert_eq!(error.exit_code(), 2);
    }
}
