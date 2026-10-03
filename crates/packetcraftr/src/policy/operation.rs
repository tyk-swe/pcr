// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Operation declarations and the policy/resolver boundary used by live workflows.

use std::net::IpAddr;

use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::packet::Packet;

use super::{Error, Policy, authorize_permissive_live};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireLimits {
    packets: u64,
    wire_bytes: u64,
}

impl WireLimits {
    #[must_use]
    pub const fn new(packets: u64, wire_bytes: u64) -> Self {
        Self {
            packets,
            wire_bytes,
        }
    }

    pub const fn validate(&self) -> Result<(), Error> {
        Ok(())
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

    pub const fn validate(&self) -> Result<(), Error> {
        Ok(())
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DnsOperation {
    udp: WireLimits,
    tcp: SocketLimits,
    limits: WireLimits,
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermissiveLive {
    NotRequired,
    Required { allowed: bool },
}

#[derive(Clone, Copy, Debug)]
pub struct DeclaredPackets<'a> {
    limits: WireLimits,
    packets: &'a [&'a Packet],
    destination: Option<IpAddr>,
    permissive_live: PermissiveLive,
}

impl<'a> DeclaredPackets<'a> {
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

    #[must_use]
    pub const fn packets(&self) -> &'a [&'a Packet] {
        self.packets
    }

    #[must_use]
    pub const fn destination(&self) -> Option<IpAddr> {
        self.destination
    }

    #[must_use]
    pub const fn permissive_live(&self) -> PermissiveLive {
        self.permissive_live
    }
}

/// There is deliberately no `Default` and no permissive fallback:
///
/// ```compile_fail,E0599
/// let _ = packetcraftr::policy::Operation::default();
/// ```
///
/// ```compile_fail
/// let _ = packetcraftr::policy::WireLimits { packets: 1, ..Default::default() };
/// ```
///
/// ```compile_fail,E0061
/// use packetcraftr::policy::{DeclaredPackets, WireLimits};
/// let packets: Vec<packetcraftr_core::packet::Packet> = Vec::new();
/// let _ = DeclaredPackets::new(WireLimits::new(1, 1), &packets);
/// ```
#[derive(Clone, Copy, Debug)]
pub enum Operation<'a> {
    Socket(SocketOperation<'a>),
    Wire(WireLimits),
    Dns(DnsOperation),
    Declared(DeclaredPackets<'a>),
}

impl Operation<'_> {
    #[must_use]
    pub const fn limits(&self) -> WireLimits {
        match self {
            Self::Socket(socket) => socket.limits(),
            Self::Wire(limits) => *limits,
            Self::Dns(dns) => dns.limits(),
            Self::Declared(declared) => declared.limits,
        }
    }
}

pub(crate) trait Authorizer {
    fn authorize_operation(&mut self, request: Operation<'_>) -> Result<(), BoundaryError>;
}

impl Authorizer for &Policy {
    fn authorize_operation(&mut self, request: Operation<'_>) -> Result<(), BoundaryError> {
        self.authorize(request).map_err(BoundaryError::from_error)
    }
}

impl Policy {
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
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

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
