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
use crate::target::{Authorized, Resolver, Target};

/// Mandatory packet-count and conservative wire-byte budgets for a live
/// operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireBudget {
    packets: u64,
    wire_bytes: u64,
}

impl WireBudget {
    /// Prospective packets that reach the wire and the conservative total of
    /// their wire bytes. [`DnsOperation::budget`] uses the same policy fields
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

/// Authorization limits for socket connections, framed messages, and
/// application bytes. Kernel-managed TCP packets cannot be counted as an exact
/// [`WireBudget`]. The workflow enforces its own deadline.
///
/// [`SocketBudget::none`] declares no socket use; otherwise all three counts
/// are required.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketBudget {
    connections: u64,
    messages: u64,
    application_bytes: u64,
}

impl SocketBudget {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("operation traffic budget overflowed")]
pub struct BudgetOverflow;
impl packetcraftr_core::error::Classified for BudgetOverflow {
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
    udp: WireBudget,
    tcp: SocketBudget,
    budget: WireBudget,
}

/// Authorized numeric endpoints and a finite budget of kernel socket operations.
#[derive(Clone, Copy, Debug)]
pub struct SocketOperation<'a> {
    endpoints: &'a [std::net::SocketAddr],
    sockets: SocketBudget,
    budget: WireBudget,
}
impl<'a> SocketOperation<'a> {
    pub fn new(
        endpoints: &'a [std::net::SocketAddr],
        sockets: SocketBudget,
    ) -> Result<Self, BudgetOverflow> {
        let units = sockets
            .connections
            .checked_add(sockets.messages)
            .ok_or(BudgetOverflow)?;
        Ok(Self {
            endpoints,
            sockets,
            budget: WireBudget::new(units, sockets.application_bytes),
        })
    }
    pub fn endpoints(&self) -> &'a [std::net::SocketAddr] {
        self.endpoints
    }
    pub const fn sockets(&self) -> SocketBudget {
        self.sockets
    }
    pub const fn budget(&self) -> WireBudget {
        self.budget
    }
}

impl DnsOperation {
    pub fn new(udp: WireBudget, tcp: SocketBudget) -> Result<Self, BudgetOverflow> {
        let packets = udp
            .packets
            .checked_add(tcp.connections)
            .and_then(|total| total.checked_add(tcp.messages))
            .ok_or(BudgetOverflow)?;
        let bytes = udp
            .wire_bytes
            .checked_add(tcp.application_bytes)
            .ok_or(BudgetOverflow)?;
        Ok(Self {
            udp,
            tcp,
            budget: WireBudget::new(packets, bytes),
        })
    }

    #[must_use]
    pub const fn udp(&self) -> WireBudget {
        self.udp
    }

    #[must_use]
    pub const fn tcp(&self) -> SocketBudget {
        self.tcp
    }

    /// Aggregate policy charge. The packet field counts UDP packets plus TCP
    /// connection/message traffic units; the byte field counts UDP wire bytes
    /// plus framed TCP application bytes.
    #[must_use]
    pub const fn budget(&self) -> WireBudget {
        self.budget
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
    budget: WireBudget,
    packets: &'a [&'a Packet],
    destination: Option<IpAddr>,
    permissive_live: PermissiveLive,
}

impl<'a> DeclaredPackets<'a> {
    /// `destination` is a route destination supplied outside the packets, or
    /// `None` to route from the packets alone.
    #[must_use]
    pub const fn new(
        budget: WireBudget,
        packets: &'a [&'a Packet],
        destination: Option<IpAddr>,
        permissive_live: PermissiveLive,
    ) -> Self {
        Self {
            budget,
            packets,
            destination,
            permissive_live,
        }
    }

    #[must_use]
    pub const fn budget(&self) -> WireBudget {
        self.budget
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
    budget: WireBudget,
    frame: &'a Frame,
    mode: LinkMode,
}

impl<'a> ReplayFrame<'a> {
    #[must_use]
    pub const fn new(budget: WireBudget, frame: &'a Frame, mode: LinkMode) -> Self {
        Self {
            budget,
            frame,
            mode,
        }
    }

    #[must_use]
    pub const fn budget(&self) -> WireBudget {
        self.budget
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
/// Budget fields cannot be left out or filled from a default either:
///
/// ```compile_fail
/// let _ = packetcraftr::policy::WireBudget { packets: 1, ..Default::default() };
/// ```
///
/// A declared-packet request must state its destination and permissive-live
/// position even when both are "none":
///
/// ```compile_fail,E0061
/// use packetcraftr::policy::{DeclaredPackets, WireBudget};
/// let packets: Vec<packetcraftr_core::packet::Packet> = Vec::new();
/// let _ = DeclaredPackets::new(WireBudget::new(1, 1), &packets);
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
    /// A packet-oriented target workflow — scan or traceroute — whose
    /// destinations were already authorized through
    /// [`Authorizer::resolve_and_authorize`]; only the budget remains to be
    /// approved.
    Budgeted(WireBudget),
    /// DNS raw-UDP and socket budgets, using [`SocketBudget::none`] without TCP
    /// continuation. Unlike [`Operation::Budgeted`], destination authorization
    /// follows budget approval and server resolution.
    Dns(DnsOperation),
    Declared(DeclaredPackets<'a>),
    Replay(ReplayFrame<'a>),
}

impl Operation<'_> {
    #[must_use]
    pub const fn budget(&self) -> WireBudget {
        match self {
            Self::Socket(socket) => socket.budget(),
            Self::Budgeted(budget) => *budget,
            Self::Dns(dns) => dns.budget(),
            Self::Declared(declared) => declared.budget,
            Self::Replay(replay) => replay.budget,
        }
    }

    /// Stable name of the shape, for authorizers that reject one explicitly.
    #[must_use]
    pub const fn shape(&self) -> &'static str {
        match self {
            Self::Socket(_) => "socket",
            Self::Budgeted(_) => "budgeted",
            Self::Dns(_) => "dns",
            Self::Declared(_) => "declared-packet",
            Self::Replay(_) => "replay",
        }
    }
}

/// Classified internal error for an operation shape the authorizer cannot
/// approve.
#[must_use]
pub fn unsupported_operation(authorizer: &'static str, request: &Operation<'_>) -> BoundaryError {
    BoundaryError::from_error(Error::UnsupportedOperation {
        authorizer,
        operation: request.shape(),
    })
}

/// Injectable operation authorization and target resolution for live workflows.
pub trait Authorizer {
    /// Approves the complete operation before it can produce live side effects.
    fn authorize_operation(&mut self, request: Operation<'_>) -> Result<(), BoundaryError>;

    /// Applies source policy to the final route after destination/budget
    /// authorization and before replay delay or transmission. Defaults to
    /// denial for authorizers without route-aware validation.
    fn authorize_final_wire(
        &mut self,
        _frame: &Frame,
        _route: &crate::route::Plan,
    ) -> Result<(), BoundaryError> {
        Err(BoundaryError::new(
            "this authorizer does not authorize final wire routes",
            packetcraftr_core::error::Classification::new(
                "internal.final_wire_authorization",
                packetcraftr_core::error::Kind::Internal,
                Some("route final wire bytes through a route-aware authorizer"),
            ),
            Vec::new(),
        ))
    }

    /// Resolves a declared target and authorizes every address it yields.
    ///
    /// Workflows that never take a declared target (fuzz and replay work from
    /// packets and captures) leave this at the fail-closed default.
    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
        let _ = target;
        Err(no_resolver())
    }
}

/// Missing resolver is a caller wiring fault, not a policy or I/O failure.
fn no_resolver() -> BoundaryError {
    BoundaryError::new(
        "this authorizer does not resolve declared targets",
        packetcraftr_core::error::Classification::new(
            "internal.target_resolution",
            packetcraftr_core::error::Kind::Internal,
            Some("resolve targets through an authorizer built with a resolver"),
        ),
        Vec::new(),
    )
}

/// Applies client policy and an optional resolver to workflow operations.
/// [`Authorizer::resolve_and_authorize`] reports a wiring fault if no resolver
/// exists.
pub struct PolicyAuthorizer<'a> {
    policy: &'a crate::policy::Policy,
    resolver: Option<&'a dyn Resolver>,
}

impl<'a> PolicyAuthorizer<'a> {
    /// Authorizer for a workflow that resolves declared targets.
    pub fn new(policy: &'a crate::policy::Policy, resolver: &'a dyn Resolver) -> Self {
        Self {
            policy,
            resolver: Some(resolver),
        }
    }

    /// Authorizer for a workflow that authorizes packets rather than names, so
    /// resolution fails closed.
    #[must_use]
    pub const fn for_packets(policy: &'a crate::policy::Policy) -> Self {
        Self {
            policy,
            resolver: None,
        }
    }
}

impl Authorizer for PolicyAuthorizer<'_> {
    fn authorize_operation(&mut self, request: Operation<'_>) -> Result<(), BoundaryError> {
        self.policy
            .authorize(request)
            .map_err(BoundaryError::from_error)
    }

    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
        match (self.resolver, target) {
            (Some(resolver), _) => self
                .policy
                .resolve_target(target, resolver)
                .map_err(BoundaryError::from_error),
            // A numeric target names its own address; the policy still gates
            // that destination. A declared hostname without a resolver is a
            // wiring fault in the caller, not a policy denial.
            (None, Target::Address(address)) => self
                .policy
                .authorize_numeric_target(target, *address)
                .map_err(BoundaryError::from_error),
            (None, Target::Hostname(_)) => Err(no_resolver()),
        }
    }
}

impl Policy {
    /// Authorizes the complete declared operation before live side effects.
    /// Exact materialized bytes are checked separately after route discovery.
    pub fn authorize(&self, request: Operation<'_>) -> Result<(), Error> {
        self.validate()?;
        let budget = request.budget();
        if matches!(request, Operation::Dns(_) | Operation::Socket(_)) {
            self.authorize_traffic_budget(budget.packets(), budget.wire_bytes())?;
        } else {
            self.authorize_wire_budget(budget.packets(), budget.wire_bytes())?;
        }
        match request {
            Operation::Socket(socket) => {
                for endpoint in socket.endpoints() {
                    self.authorize_destination(endpoint.ip())?;
                }
                Ok(())
            }
            Operation::Budgeted(_) | Operation::Dns(_) => Ok(()),
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

    struct OperationOnlyAuthorizer;

    impl Authorizer for OperationOnlyAuthorizer {
        fn authorize_operation(&mut self, _request: Operation<'_>) -> Result<(), BoundaryError> {
            Ok(())
        }
    }

    fn hostname_target() -> Target {
        "documentation.invalid".parse().expect("hostname target")
    }

    #[test]
    fn an_authorizer_without_a_resolver_refuses_to_resolve_a_declared_target() {
        let error = OperationOnlyAuthorizer
            .resolve_and_authorize(&hostname_target())
            .expect_err("the default resolution seam is fail-closed");

        assert_eq!(error.classification().code, "internal.target_resolution");
    }

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
    fn policy_authorizer_applies_the_aggregate_dns_socket_budget() {
        let policy = crate::policy::Policy {
            max_packets_per_operation: 2,
            ..crate::policy::Policy::default()
        };
        let dns = Operation::Dns(
            DnsOperation::new(WireBudget::new(1, 40), SocketBudget::new(1, 1, 22)).unwrap(),
        );
        let error = PolicyAuthorizer::for_packets(&policy)
            .authorize_operation(dns)
            .expect_err("UDP plus TCP connection/message units exceed the policy");
        assert_eq!(error.classification().code, "policy.traffic_unit_limit");
    }

    #[test]
    fn the_policy_authorizer_rejects_replay_requests_explicitly() {
        let policy = crate::policy::Policy::default();
        let frame = Frame::new(std::time::UNIX_EPOCH, LinkType::RAW, vec![0x45_u8; 20])
            .expect("fixture frame");

        let error = PolicyAuthorizer::for_packets(&policy)
            .authorize_operation(Operation::Replay(ReplayFrame::new(
                WireBudget::new(1, 20),
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
    fn budget_rejection_precedes_destination_and_permissive_checks() {
        let policy = crate::policy::Policy {
            max_packets_per_operation: 1,
            max_bytes_per_operation: 10,
            ..crate::policy::Policy::default()
        };
        let packet = documentation_packet();
        let packets = [&packet];
        let public = std::net::IpAddr::V4(std::net::Ipv4Addr::new(224, 0, 0, 251));
        let mut authorizer = PolicyAuthorizer::for_packets(&policy);

        let packet_error = authorizer
            .authorize_operation(Operation::Declared(DeclaredPackets::new(
                WireBudget::new(2, 1),
                &packets,
                Some(public),
                PermissiveLive::Required { allowed: false },
            )))
            .expect_err("packet budget fails first");
        assert_eq!(packet_error.classification().code, "policy.packet_limit");

        let byte_error = authorizer
            .authorize_operation(Operation::Declared(DeclaredPackets::new(
                WireBudget::new(1, 11),
                &packets,
                Some(public),
                PermissiveLive::Required { allowed: false },
            )))
            .expect_err("byte budget fails before the destination gate");
        assert_eq!(byte_error.classification().code, "policy.byte_limit");

        let budget_only = authorizer
            .authorize_operation(Operation::Budgeted(WireBudget::new(2, 1)))
            .expect_err("budget-only requests are budgeted too");
        assert_eq!(budget_only.classification().code, "policy.packet_limit");
    }

    #[test]
    fn declared_requests_state_destination_and_permissive_live_explicitly() {
        let policy = crate::policy::Policy::default();
        let packet = documentation_packet();
        let packets = [&packet];
        // Multicast counts as public under the policy and never names a host.
        let public = std::net::IpAddr::V4(std::net::Ipv4Addr::new(224, 0, 0, 251));
        let mut authorizer = PolicyAuthorizer::for_packets(&policy);

        authorizer
            .authorize_operation(Operation::Declared(DeclaredPackets::new(
                WireBudget::new(1, 1),
                &packets,
                None,
                PermissiveLive::NotRequired,
            )))
            .expect("documentation packets with no chosen destination");

        let destination_error = authorizer
            .authorize_operation(Operation::Declared(DeclaredPackets::new(
                WireBudget::new(1, 1),
                &packets,
                Some(public),
                PermissiveLive::NotRequired,
            )))
            .expect_err("a public chosen destination is refused");
        assert_eq!(
            destination_error.classification().code,
            "policy.public_destination"
        );

        let opt_in_error = authorizer
            .authorize_operation(Operation::Declared(DeclaredPackets::new(
                WireBudget::new(1, 1),
                &packets,
                None,
                PermissiveLive::Required { allowed: false },
            )))
            .expect_err("permissive bytes need the per-operation opt-in");
        assert_eq!(
            opt_in_error.classification().code,
            Error::PermissiveLiveOptIn.classification().code
        );

        let policy_error = authorizer
            .authorize_operation(Operation::Declared(DeclaredPackets::new(
                WireBudget::new(1, 1),
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
    fn aggregate_dns_budget_rejects_overflow_in_each_quantity() {
        assert!(
            DnsOperation::new(WireBudget::new(u64::MAX, 0), SocketBudget::new(1, 0, 0)).is_err()
        );
        assert!(
            DnsOperation::new(WireBudget::new(0, 0), SocketBudget::new(u64::MAX, 1, 0)).is_err()
        );
        assert!(
            DnsOperation::new(WireBudget::new(0, u64::MAX), SocketBudget::new(0, 0, 1)).is_err()
        );
        assert_eq!(
            DnsOperation::new(WireBudget::new(u64::MAX, u64::MAX), SocketBudget::none())
                .unwrap()
                .budget(),
            WireBudget::new(u64::MAX, u64::MAX)
        );
    }
}
