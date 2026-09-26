// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Operation declarations and the policy/resolver boundary used by live workflows.
//! Client preparation and injected workflow authorization apply the same
//! [`Policy`]. Discovery is authorized before it runs; final
//! materialized bytes are authorized again at the transmission boundary.

use std::net::IpAddr;

use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::packet::Packet;
use packetcraftr_netio::link::Mode as LinkMode;

use super::{Error, Policy, authorize_permissive_live};

/// The packet-count and conservative wire-byte ceilings a live operation
/// declares. Policy authorizes them before any side effect; the operation then
/// charges its running budget against them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireLimits {
    packets: u64,
    wire_bytes: u64,
}

impl WireLimits {
    /// Prospective packets that reach the wire and the conservative total of
    /// their wire bytes. [`DnsOperation::limits`] uses the same policy fields
    /// for a documented aggregate of raw UDP packets plus bounded TCP socket
    /// connections/messages and application bytes; it does not claim that
    /// kernel-managed TCP has an exact packet count.
    #[must_use]
    pub const fn new(packets: u64, wire_bytes: u64) -> Self {
        Self {
            packets,
            wire_bytes,
        }
    }

    #[must_use]
    pub const fn packets(&self) -> u64 {
        self.packets
    }

    #[must_use]
    pub const fn wire_bytes(&self) -> u64 {
        self.wire_bytes
    }
}

/// The socket connection, framed message, and application byte ceilings a
/// live operation declares. Kernel-managed TCP packets cannot be counted as
/// exact [`WireLimits`]. The workflow enforces its own deadline.
///
/// [`SocketLimits::none`] declares no socket use; otherwise all three counts
/// are required.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketLimits {
    connections: u64,
    messages: u64,
    application_bytes: u64,
}

impl SocketLimits {
    #[must_use]
    pub const fn new(connections: u64, messages: u64, application_bytes: u64) -> Self {
        Self {
            connections,
            messages,
            application_bytes,
        }
    }

    #[must_use]
    pub const fn none() -> Self {
        Self::new(0, 0, 0)
    }

    #[must_use]
    pub const fn connections(&self) -> u64 {
        self.connections
    }

    #[must_use]
    pub const fn messages(&self) -> u64 {
        self.messages
    }

    #[must_use]
    pub const fn application_bytes(&self) -> u64 {
        self.application_bytes
    }
}

/// Summing declared limits overflowed. The published code keeps its original
/// `policy.budget_overflow` spelling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("operation traffic budget overflowed")]
pub struct LimitOverflow;
impl packetcraftr_core::error::Classified for LimitOverflow {
    fn classification(&self) -> packetcraftr_core::error::Classification {
        packetcraftr_core::error::Classification::new(
            "policy.budget_overflow",
            packetcraftr_core::error::Kind::Policy,
            Some("reduce the finite operation budget"),
        )
    }
}

/// Complete authorization shape for DNS that may use raw UDP and kernel TCP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DnsOperation {
    udp: WireLimits,
    tcp: SocketLimits,
    limits: WireLimits,
}

/// Authorized numeric endpoints and finite limits on kernel socket operations.
#[derive(Clone, Copy, Debug)]
pub struct SocketOperation<'a> {
    endpoints: &'a [std::net::SocketAddr],
    sockets: SocketLimits,
    limits: WireLimits,
}
impl<'a> SocketOperation<'a> {
    pub fn new(
        endpoints: &'a [std::net::SocketAddr],
        sockets: SocketLimits,
    ) -> Result<Self, LimitOverflow> {
        let units = sockets
            .connections
            .checked_add(sockets.messages)
            .ok_or(LimitOverflow)?;
        Ok(Self {
            endpoints,
            sockets,
            limits: WireLimits::new(units, sockets.application_bytes),
        })
    }
    pub fn endpoints(&self) -> &'a [std::net::SocketAddr] {
        self.endpoints
    }
    pub const fn sockets(&self) -> SocketLimits {
        self.sockets
    }
    pub const fn limits(&self) -> WireLimits {
        self.limits
    }
}

impl DnsOperation {
    pub fn new(udp: WireLimits, tcp: SocketLimits) -> Result<Self, LimitOverflow> {
        let packets = udp
            .packets
            .checked_add(tcp.connections)
            .and_then(|total| total.checked_add(tcp.messages))
            .ok_or(LimitOverflow)?;
        let bytes = udp
            .wire_bytes
            .checked_add(tcp.application_bytes)
            .ok_or(LimitOverflow)?;
        Ok(Self {
            udp,
            tcp,
            limits: WireLimits::new(packets, bytes),
        })
    }

    #[must_use]
    pub const fn udp(&self) -> WireLimits {
        self.udp
    }

    #[must_use]
    pub const fn tcp(&self) -> SocketLimits {
        self.tcp
    }

    /// Aggregate limits policy authorizes. The packet field counts UDP packets plus TCP
    /// connection/message traffic units; the byte field counts UDP wire bytes
    /// plus framed TCP application bytes.
    #[must_use]
    pub const fn limits(&self) -> WireLimits {
        self.limits
    }
}

/// Declares whether transmitted bytes need the permissive-live opt-in and
/// whether the caller supplied it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermissiveLive {
    /// Every packet builds strictly; no opt-in is involved.
    NotRequired,
    /// At least one packet requires the per-operation opt-in.
    Required { allowed: bool },
}

/// Fuzz authorization: all candidate packets, the route destination, and the
/// permissive-live opt-in.
#[derive(Clone, Copy, Debug)]
pub struct DeclaredPackets<'a> {
    limits: WireLimits,
    packets: &'a [&'a Packet],
    destination: Option<IpAddr>,
    permissive_live: PermissiveLive,
}

impl<'a> DeclaredPackets<'a> {
    /// `destination` is a route destination supplied outside the packets, or
    /// `None` to route from the packets alone.
    #[must_use]
    pub const fn new(
        limits: WireLimits,
        packets: &'a [&'a Packet],
        destination: Option<IpAddr>,
        permissive_live: PermissiveLive,
    ) -> Self {
        Self {
            limits,
            packets,
            destination,
            permissive_live,
        }
    }

    #[must_use]
    pub const fn limits(&self) -> WireLimits {
        self.limits
    }

    /// Packets whose declared destinations must be authorized before a route,
    /// capture, neighbor, or transmission provider can observe them.
    #[must_use]
    pub const fn packets(&self) -> &'a [&'a Packet] {
        self.packets
    }

    /// A route destination chosen outside the packets themselves.
    #[must_use]
    pub const fn destination(&self) -> Option<IpAddr> {
        self.destination
    }

    #[must_use]
    pub const fn permissive_live(&self) -> PermissiveLive {
        self.permissive_live
    }
}

/// A replay operation: one exact captured frame with the link mode it would
/// be transmitted in.
#[derive(Clone, Copy, Debug)]
pub struct ReplayFrame<'a> {
    limits: WireLimits,
    frame: &'a Frame,
    mode: LinkMode,
}

impl<'a> ReplayFrame<'a> {
    #[must_use]
    pub const fn new(limits: WireLimits, frame: &'a Frame, mode: LinkMode) -> Self {
        Self {
            limits,
            frame,
            mode,
        }
    }

    #[must_use]
    pub const fn limits(&self) -> WireLimits {
        self.limits
    }

    #[must_use]
    pub const fn frame(&self) -> &'a Frame {
        self.frame
    }

    #[must_use]
    pub const fn mode(&self) -> LinkMode {
        self.mode
    }
}

/// What a workflow declares about the operation it wants to run.
///
/// There is deliberately no `Default` and no permissive fallback:
///
/// ```compile_fail,E0599
/// let _ = packetcraftr::policy::Operation::default();
/// ```
///
/// Limit fields cannot be left out or filled from a default either:
///
/// ```compile_fail
/// let _ = packetcraftr::policy::WireLimits { packets: 1, ..Default::default() };
/// ```
///
/// A declared-packet request must state its destination and permissive-live
/// position even when both are "none":
///
/// ```compile_fail,E0061
/// use packetcraftr::policy::{DeclaredPackets, WireLimits};
/// let packets: Vec<packetcraftr_core::packet::Packet> = Vec::new();
/// let _ = DeclaredPackets::new(WireLimits::new(1, 1), &packets);
/// ```
///
/// Each variant is a complete request shape: every field a shape needs is a
/// constructor argument, no field has a default, and an authorizer matches
/// the shapes exhaustively. Adding a requirement to a shape, or a new shape,
/// therefore fails to compile at every construction site and every
/// authorizer until each says what it does with it.
#[derive(Clone, Copy, Debug)]
pub enum Operation<'a> {
    /// Ordinary socket operations; the endpoint list is authorized before connection.
    Socket(SocketOperation<'a>),
    /// Only the wire limits of a packet workflow whose destinations are
    /// authorized separately: scan and traceroute targets as the client
    /// resolves them, and send packets as they are prepared.
    Wire(WireLimits),
    /// DNS raw-UDP and socket limits, using [`SocketLimits::none`] without TCP
    /// continuation. Unlike [`Operation::Wire`], destination authorization
    /// follows limits approval and server resolution.
    Dns(DnsOperation),
    Declared(DeclaredPackets<'a>),
    Replay(ReplayFrame<'a>),
}

impl Operation<'_> {
    #[must_use]
    pub const fn limits(&self) -> WireLimits {
        match self {
            Self::Socket(socket) => socket.limits(),
            Self::Wire(limits) => *limits,
            Self::Dns(dns) => dns.limits(),
            Self::Declared(declared) => declared.limits,
            Self::Replay(replay) => replay.limits,
        }
    }

    /// Stable name of the shape, for authorizers that reject one explicitly.
    #[must_use]
    pub const fn shape(&self) -> &'static str {
        match self {
            Self::Socket(_) => "socket",
            Self::Wire(_) => "wire",
            Self::Dns(_) => "dns",
            Self::Declared(_) => "declared-packet",
            Self::Replay(_) => "replay",
        }
    }
}

/// Classified internal error for an operation shape the authorizer cannot
/// approve.
#[must_use]
pub(crate) fn unsupported_operation(
    authorizer: &'static str,
    request: &Operation<'_>,
) -> BoundaryError {
    BoundaryError::from_error(Error::UnsupportedOperation {
        authorizer,
        operation: request.shape(),
    })
}

/// Operation authorization inside a workflow engine. Target resolution is the
/// separate [`ResolveTarget`](crate::target::ResolveTarget) seam, which only
/// workflows that take a declared target require.
pub(crate) trait Authorizer {
    /// Approves the complete operation before it can produce live side effects.
    fn authorize_operation(&mut self, request: Operation<'_>) -> Result<(), BoundaryError>;
}

impl Policy {
    /// Authorizes the complete declared operation before live side effects.
    /// Exact materialized bytes are checked separately after route discovery.
    pub fn authorize(&self, request: Operation<'_>) -> Result<(), Error> {
        self.validate()?;
        let limits = request.limits();
        if matches!(request, Operation::Dns(_) | Operation::Socket(_)) {
            self.authorize_traffic_limits(limits.packets(), limits.wire_bytes())?;
        } else {
            self.authorize_wire_limits(limits.packets(), limits.wire_bytes())?;
        }
        match request {
            Operation::Socket(socket) => {
                for endpoint in socket.endpoints() {
                    self.authorize_destination(endpoint.ip())?;
                }
                Ok(())
            }
            Operation::Wire(_) | Operation::Dns(_) => Ok(()),
            Operation::Declared(declared) => {
                if let PermissiveLive::Required { allowed } = declared.permissive_live() {
                    authorize_permissive_live(self, allowed)?;
                }
                if let Some(destination) = declared.destination() {
                    self.authorize_destination(destination)?;
                }
                for packet in declared.packets() {
                    self.authorize_packet_destinations(packet)?;
                }
                Ok(())
            }
            Operation::Replay(_) => Err(Error::UnsupportedOperation {
                authorizer: "the policy authorizer",
                operation: request.shape(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use packetcraftr_core::frame::LinkType;

    use packetcraftr_core::error::Classified;

    use super::*;

    fn documentation_packet() -> Packet {
        let mut packet = Packet::new();
        packet
            .push(packetcraftr_core::protocol::network::Ipv4 {
                source: std::net::Ipv4Addr::new(192, 0, 2, 1),
                destination: std::net::Ipv4Addr::new(192, 0, 2, 2),
                ..packetcraftr_core::protocol::network::Ipv4::default()
            })
            .push(packetcraftr_core::protocol::transport::Udp::default());
        packet
    }

    #[test]
    fn policy_applies_the_aggregate_dns_socket_limits() {
        let policy = crate::policy::Policy {
            max_packets_per_operation: 2,
            ..crate::policy::Policy::default()
        };
        let dns = Operation::Dns(
            DnsOperation::new(WireLimits::new(1, 40), SocketLimits::new(1, 1, 22)).unwrap(),
        );
        let error = policy
            .authorize(dns)
            .expect_err("UDP plus TCP connection/message units exceed the policy");
        assert_eq!(error.classification().code, "policy.traffic_unit_limit");
    }

    #[test]
    fn the_policy_rejects_replay_requests_explicitly() {
        let policy = crate::policy::Policy::default();
        let frame = Frame::new(std::time::UNIX_EPOCH, LinkType::RAW, vec![0x45_u8; 20])
            .expect("fixture frame");

        let error = policy
            .authorize(Operation::Replay(ReplayFrame::new(
                WireLimits::new(1, 20),
                &frame,
                LinkMode::Layer3,
            )))
            .expect_err("policy authorization cannot stand in for the replay round trip");

        assert_eq!(
            error.classification().code,
            "internal.unsupported_operation"
        );
        assert!(error.to_string().contains("replay"));
    }

    #[test]
    fn limits_rejection_precedes_destination_and_permissive_checks() {
        let policy = crate::policy::Policy {
            max_packets_per_operation: 1,
            max_bytes_per_operation: 10,
            ..crate::policy::Policy::default()
        };
        let packet = documentation_packet();
        let packets = [&packet];
        let public = std::net::IpAddr::V4(std::net::Ipv4Addr::new(224, 0, 0, 251));

        let packet_error = policy
            .authorize(Operation::Declared(DeclaredPackets::new(
                WireLimits::new(2, 1),
                &packets,
                Some(public),
                PermissiveLive::Required { allowed: false },
            )))
            .expect_err("packet limit fails first");
        assert_eq!(packet_error.classification().code, "policy.packet_limit");

        let byte_error = policy
            .authorize(Operation::Declared(DeclaredPackets::new(
                WireLimits::new(1, 11),
                &packets,
                Some(public),
                PermissiveLive::Required { allowed: false },
            )))
            .expect_err("byte limit fails before the destination gate");
        assert_eq!(byte_error.classification().code, "policy.byte_limit");

        let limits_only = policy
            .authorize(Operation::Wire(WireLimits::new(2, 1)))
            .expect_err("limits-only requests are checked too");
        assert_eq!(limits_only.classification().code, "policy.packet_limit");
    }

    #[test]
    fn declared_requests_state_destination_and_permissive_live_explicitly() {
        let policy = crate::policy::Policy::default();
        let packet = documentation_packet();
        let packets = [&packet];
        // Multicast counts as public under the policy and never names a host.
        let public = std::net::IpAddr::V4(std::net::Ipv4Addr::new(224, 0, 0, 251));

        policy
            .authorize(Operation::Declared(DeclaredPackets::new(
                WireLimits::new(1, 1),
                &packets,
                None,
                PermissiveLive::NotRequired,
            )))
            .expect("documentation packets with no chosen destination");

        let destination_error = policy
            .authorize(Operation::Declared(DeclaredPackets::new(
                WireLimits::new(1, 1),
                &packets,
                Some(public),
                PermissiveLive::NotRequired,
            )))
            .expect_err("a public chosen destination is refused");
        assert_eq!(
            destination_error.classification().code,
            "policy.public_destination"
        );

        let opt_in_error = policy
            .authorize(Operation::Declared(DeclaredPackets::new(
                WireLimits::new(1, 1),
                &packets,
                None,
                PermissiveLive::Required { allowed: false },
            )))
            .expect_err("permissive bytes need the per-operation opt-in");
        assert_eq!(
            opt_in_error.classification().code,
            Error::PermissiveLiveOptIn.classification().code
        );

        let policy_error = policy
            .authorize(Operation::Declared(DeclaredPackets::new(
                WireLimits::new(1, 1),
                &packets,
                None,
                PermissiveLive::Required { allowed: true },
            )))
            .expect_err("the opt-in alone does not override the policy");
        assert_eq!(
            policy_error.classification().code,
            crate::policy::Error::PermissivePacket.classification().code
        );
    }

    #[test]
    fn aggregate_dns_limits_reject_overflow_in_each_quantity() {
        assert!(
            DnsOperation::new(WireLimits::new(u64::MAX, 0), SocketLimits::new(1, 0, 0)).is_err()
        );
        assert!(
            DnsOperation::new(WireLimits::new(0, 0), SocketLimits::new(u64::MAX, 1, 0)).is_err()
        );
        assert!(
            DnsOperation::new(WireLimits::new(0, u64::MAX), SocketLimits::new(0, 0, 1)).is_err()
        );
        assert_eq!(
            DnsOperation::new(WireLimits::new(u64::MAX, u64::MAX), SocketLimits::none())
                .unwrap()
                .limits(),
            WireLimits::new(u64::MAX, u64::MAX)
        );
    }
}
