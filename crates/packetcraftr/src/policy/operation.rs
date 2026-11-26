// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Operation declarations and the policy/resolver boundary used by live workflows.

use std::net::IpAddr;

use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::packet::Packet;

use super::{Error, Policy, authorize_permissive_live};

/// Declared packet and wire-byte maxima. Every pair, including zero for no
/// traffic, is a legal declaration. [`TrafficOperation::new`] rejects an aggregate
/// that overflows with [`LimitOverflow`], and [`Policy::authorize`] enforces
/// the policy ceilings.
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

    #[must_use]
    pub const fn packets(&self) -> u64 {
        self.packets
    }

    #[must_use]
    pub const fn wire_bytes(&self) -> u64 {
        self.wire_bytes
    }
}

/// Declared connection, message, and application-byte maxima. Every value,
/// including zero for no traffic, is a legal declaration.
/// [`SocketOperation::new`] and [`TrafficOperation::new`] reject an aggregate that
/// overflows with [`LimitOverflow`], and [`Policy::authorize`] enforces the
/// policy ceilings and destinations.
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
            crate::code::PolicyBudgetOverflow,
            packetcraftr_core::error::Kind::Policy,
            Some("reduce the finite operation budget"),
        )
    }
}

/// Combined raw-packet and socket traffic maxima for a single composite operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrafficOperation {
    wire: WireLimits,
    socket: SocketLimits,
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
    /// Refine independent component maxima with a workflow-enforced shared
    /// traffic bound. This never increases either the units or byte allowance.
    pub(crate) fn with_traffic_unit_bound(mut self, bound: u64) -> Self {
        self.limits = WireLimits::new(self.limits.packets().min(bound), self.limits.wire_bytes());
        self
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

impl TrafficOperation {
    pub fn new(wire: WireLimits, socket: SocketLimits) -> Result<Self, LimitOverflow> {
        let packets = wire
            .packets
            .checked_add(socket.connections)
            .and_then(|total| total.checked_add(socket.messages))
            .ok_or(LimitOverflow)?;
        let bytes = wire
            .wire_bytes
            .checked_add(socket.application_bytes)
            .ok_or(LimitOverflow)?;
        Ok(Self {
            wire,
            socket,
            limits: WireLimits::new(packets, bytes),
        })
    }

    #[must_use]
    pub const fn wire(&self) -> WireLimits {
        self.wire
    }

    #[must_use]
    pub const fn socket(&self) -> SocketLimits {
        self.socket
    }

    /// Aggregate limits policy authorizes. The packet field counts wire packets
    /// plus socket connection/message traffic units; the byte field counts wire
    /// bytes plus application bytes.
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
    Traffic(TrafficOperation),
    Declared(DeclaredPackets<'a>),
}

impl Operation<'_> {
    #[must_use]
    pub const fn limits(&self) -> WireLimits {
        match self {
            Self::Socket(socket) => socket.limits(),
            Self::Wire(limits) => *limits,
            Self::Traffic(traffic) => traffic.limits(),
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
        if matches!(request, Operation::Traffic(_) | Operation::Socket(_)) {
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
            Operation::Wire(_) | Operation::Traffic(_) => Ok(()),
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
    use packetcraftr_core::error::{Classified, Kind};

    fn ceilings(units: u64, bytes: u64) -> Policy {
        Policy {
            max_packets_per_operation: units,
            max_bytes_per_operation: bytes,
            ..Policy::default()
        }
    }

    fn socket(limits: SocketLimits) -> Result<(), Error> {
        ceilings(10, 100).authorize(Operation::Socket(
            SocketOperation::new(&[], limits).unwrap(),
        ))
    }

    fn traffic(wire: WireLimits, socket: SocketLimits) -> Result<(), Error> {
        ceilings(10, 100).authorize(Operation::Traffic(
            TrafficOperation::new(wire, socket).unwrap(),
        ))
    }

    #[test]
    fn aggregate_overflow_reports_budget_error() {
        assert_eq!(
            SocketOperation::new(&[], SocketLimits::new(u64::MAX, 1, 0)).err(),
            Some(LimitOverflow)
        );
        assert_eq!(
            SocketOperation::new(&[], SocketLimits::new(u64::MAX - 1, 1, u64::MAX))
                .map(|operation| operation.limits()),
            Ok(WireLimits::new(u64::MAX, u64::MAX))
        );
        for (wire, socket) in [
            (WireLimits::new(u64::MAX, 0), SocketLimits::new(1, 0, 0)),
            (WireLimits::new(u64::MAX - 1, 0), SocketLimits::new(1, 1, 0)),
            (WireLimits::new(0, u64::MAX), SocketLimits::new(0, 0, 1)),
        ] {
            assert_eq!(TrafficOperation::new(wire, socket), Err(LimitOverflow));
        }
        assert_eq!(
            TrafficOperation::new(WireLimits::new(u64::MAX - 2, 1), SocketLimits::new(1, 1, 2))
                .map(|operation| operation.limits()),
            Ok(WireLimits::new(u64::MAX, 3))
        );
        let classification = LimitOverflow.classification();
        assert_eq!(classification.code.as_str(), "policy.budget_overflow");
        assert_eq!(classification.kind, Kind::Policy);
    }

    #[test]
    fn zero_budget_allows_no_traffic() {
        let policy = ceilings(0, 0);
        let zero = SocketLimits::new(0, 0, 0);
        assert!(
            policy
                .authorize(Operation::Socket(SocketOperation::new(&[], zero).unwrap()))
                .is_ok()
        );
        assert!(
            policy
                .authorize(Operation::Traffic(
                    TrafficOperation::new(WireLimits::new(0, 0), zero).unwrap()
                ))
                .is_ok()
        );
        assert!(
            policy
                .authorize(Operation::Wire(WireLimits::new(0, 0)))
                .is_ok()
        );
    }

    #[test]
    fn socket_limits_accept_exact_total() {
        assert!(socket(SocketLimits::new(4, 6, 100)).is_ok());
        assert!(matches!(
            socket(SocketLimits::new(4, 7, 100)),
            Err(Error::TrafficUnitLimit {
                actual: 11,
                limit: 10
            })
        ));
        assert!(matches!(
            socket(SocketLimits::new(4, 6, 101)),
            Err(Error::TrafficByteLimit {
                actual: 101,
                limit: 100
            })
        ));
    }

    #[test]
    fn traffic_limits_accept_exact_total() {
        let socket = SocketLimits::new(2, 3, 40);
        assert!(traffic(WireLimits::new(5, 60), socket).is_ok());
        assert!(matches!(
            traffic(WireLimits::new(6, 60), socket),
            Err(Error::TrafficUnitLimit {
                actual: 11,
                limit: 10
            })
        ));
        assert!(matches!(
            traffic(WireLimits::new(5, 61), socket),
            Err(Error::TrafficByteLimit {
                actual: 101,
                limit: 100
            })
        ));
    }

    #[test]
    fn wire_limits_accept_exact_total() {
        let policy = ceilings(10, 100);
        assert!(
            policy
                .authorize(Operation::Wire(WireLimits::new(10, 100)))
                .is_ok()
        );
        assert!(matches!(
            policy.authorize(Operation::Wire(WireLimits::new(11, 100))),
            Err(Error::PacketLimit {
                actual: 11,
                limit: 10
            })
        ));
        assert!(matches!(
            policy.authorize(Operation::Wire(WireLimits::new(10, 101))),
            Err(Error::ByteLimit {
                actual: 101,
                limit: 100
            })
        ));
    }

    #[test]
    fn declared_destination_requires_allowlisting() {
        let packets: [&Packet; 0] = [];
        let declared = |destination: Option<IpAddr>| {
            Operation::Declared(DeclaredPackets::new(
                WireLimits::new(1, 1),
                &packets,
                destination,
                PermissiveLive::NotRequired,
            ))
        };
        let policy = Policy {
            allowed_destinations: vec!["10.0.0.1".parse().unwrap()],
            ..ceilings(10, 100)
        };
        assert!(matches!(
            policy.authorize(declared(Some("192.0.2.1".parse().unwrap()))),
            Err(Error::DestinationNotAllowed { .. })
        ));
        assert!(
            policy
                .authorize(declared(Some("10.0.0.1".parse().unwrap())))
                .is_ok()
        );
        assert!(policy.authorize(declared(None)).is_ok());
    }

    #[test]
    fn the_shared_policy_authorizer_propagates_denials() {
        let policy = ceilings(10, 100);
        let mut authorizer: &Policy = &policy;
        let error = authorizer
            .authorize_operation(Operation::Wire(WireLimits::new(11, 100)))
            .unwrap_err();
        assert_eq!(error.classification().code.as_str(), "policy.packet_limit");
        assert!(
            authorizer
                .authorize_operation(Operation::Wire(WireLimits::new(10, 100)))
                .is_ok()
        );
    }
}
