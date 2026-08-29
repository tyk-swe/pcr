// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The single authorization seam every live workflow passes through.
//!
//! Scan, DNS, traceroute, fuzz, and replay all ask the same question before
//! they can produce traffic: may this operation run, with these packets, this
//! destination, and this many wire bytes? [`Authorizer`] is that question,
//! [`Operation`] is the complete, shape-specific statement a workflow makes
//! about its operation, and [`PolicyAuthorizer`] is the answer a
//! [`crate::policy::Policy`] gives.

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::{Packet, build::BuiltPacket, decode::Dissector, registry::Registry};
use packetcraftr_netio::{Error as LiveIoError, link::Mode as LinkMode};

use crate::Client;
use crate::Error;
use crate::target::{Authorized, Resolver, Target};

/// The packet and wire-byte budget every live operation must declare before
/// it can produce traffic.
///
/// Both counts are mandatory: there is no default and no constructor that
/// supplies one for the caller, so a workflow that cannot state its budget
/// cannot build a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireBudget {
    packets: u64,
    wire_bytes: u64,
}

impl WireBudget {
    /// Prospective packets that reach the wire and the conservative total of
    /// their wire bytes.
    #[must_use]
    pub const fn new(packets: u64, wire_bytes: u64) -> Self {
        Self {
            packets,
            wire_bytes,
        }
    }

    /// Prospective count of packets that reach the wire.
    #[must_use]
    pub const fn packets(&self) -> u64 {
        self.packets
    }

    /// Prospective wire bytes, counted conservatively.
    #[must_use]
    pub const fn wire_bytes(&self) -> u64 {
        self.wire_bytes
    }
}

/// Whether an operation would put permissively built or malformed bytes on
/// the wire, and if so whether the caller passed the per-operation opt-in.
///
/// A workflow must say one or the other; the permissive case cannot be
/// reached by leaving a flag unset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermissiveLive {
    /// Every packet builds strictly; no opt-in is involved.
    NotRequired,
    /// At least one packet needs the permissive-live opt-in, which the caller
    /// did (`allowed: true`) or did not (`allowed: false`) pass for this run.
    Required {
        /// The caller passed the per-operation opt-in for those bytes.
        allowed: bool,
    },
}

/// A declared-packet operation: the fuzz workflow, which knows every packet it
/// may transmit, the route destination it chose, and whether any case builds
/// permissively.
#[derive(Clone, Copy, Debug)]
pub struct DeclaredPackets<'a> {
    budget: WireBudget,
    packets: &'a [Packet],
    destination: Option<IpAddr>,
    permissive_live: PermissiveLive,
}

impl<'a> DeclaredPackets<'a> {
    /// Every argument is required. `destination` is the route destination
    /// chosen outside the packets themselves, or `None` when the workflow
    /// routes from the packets alone; the caller states that explicitly.
    #[must_use]
    pub const fn new(
        budget: WireBudget,
        packets: &'a [Packet],
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
    pub const fn packets(&self) -> &'a [Packet] {
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

    /// The exact frame that would reach the wire.
    #[must_use]
    pub const fn frame(&self) -> &'a Frame {
        self.frame
    }

    /// The link mode the frame would be transmitted in.
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
/// let _ = packetcraftr::authorization::Operation::default();
/// ```
///
/// Budget fields cannot be left out or filled from a default either:
///
/// ```compile_fail
/// let _ = packetcraftr::authorization::WireBudget { packets: 1, ..Default::default() };
/// ```
///
/// A declared-packet request must state its destination and permissive-live
/// position even when both are "none":
///
/// ```compile_fail,E0061
/// use packetcraftr::authorization::{DeclaredPackets, WireBudget};
/// let packets: Vec<packetcraftr::core::Packet> = Vec::new();
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
    /// A target workflow (scan, DNS, traceroute) whose destinations were
    /// already authorized through [`Authorizer::resolve_and_authorize`]; only
    /// the budget remains to be approved.
    Budgeted(WireBudget),
    /// A workflow that declares the exact packets it may transmit.
    Declared(DeclaredPackets<'a>),
    /// A replay of one exact captured frame.
    Replay(ReplayFrame<'a>),
}

impl Operation<'_> {
    /// The budget every shape carries.
    #[must_use]
    pub const fn budget(&self) -> WireBudget {
        match self {
            Self::Budgeted(budget) => *budget,
            Self::Declared(declared) => declared.budget,
            Self::Replay(replay) => replay.budget,
        }
    }

    /// Stable name of the shape, for authorizers that reject one explicitly.
    #[must_use]
    pub const fn shape(&self) -> &'static str {
        match self {
            Self::Budgeted(_) => "budgeted",
            Self::Declared(_) => "declared-packet",
            Self::Replay(_) => "replay",
        }
    }
}

/// The refusal an authorizer returns for a request shape it does not handle.
///
/// Every authorizer matches [`Operation`] exhaustively; the variants it cannot
/// judge are rejected through this classified internal error rather than
/// approved by ignoring what they carry.
#[must_use]
pub fn unsupported_operation(authorizer: &'static str, request: &Operation<'_>) -> BoundaryError {
    BoundaryError::new(
        format!(
            "{authorizer} does not authorize {} operations",
            request.shape()
        ),
        packetcraftr_core::error::Classification::new(
            "internal.unsupported_operation",
            packetcraftr_core::error::Kind::Internal,
            Some("route this operation through the authorizer built for its workflow"),
        ),
        Vec::new(),
    )
}

/// Policy and resolution seam shared by every live workflow.
///
/// Workflows hold an `Authorizer` rather than a policy so that resolution and
/// approval can be substituted in tests without substituting the traffic rules.
pub trait Authorizer {
    /// Approves the complete operation before it can produce live side effects.
    fn authorize_operation(&mut self, request: Operation<'_>) -> Result<(), BoundaryError>;

    /// Resolves a declared target and authorizes every address it yields.
    ///
    /// Workflows that never take a declared target (fuzz and replay work from
    /// packets and captures) leave this at the fail-closed default.
    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
        let _ = target;
        Err(BoundaryError::new(
            "this authorizer does not resolve declared targets",
            packetcraftr_core::error::Classification::new(
                "internal.target_resolution",
                packetcraftr_core::error::Kind::Internal,
                Some("resolve targets through an authorizer built with a resolver"),
            ),
            Vec::new(),
        ))
    }
}

/// Applies a client traffic policy, and an optional hostname resolver, to an
/// operation without exposing either concern to workflow engines.
pub struct PolicyAuthorizer<'a, R> {
    policy: &'a crate::policy::Policy,
    resolver: &'a R,
}

impl<'a, R> PolicyAuthorizer<'a, R> {
    pub fn new(policy: &'a crate::policy::Policy, resolver: &'a R) -> Self {
        Self { policy, resolver }
    }
}

/// Stand-in resolver for workflows that authorize packets rather than names.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoResolver;

impl Resolver for NoResolver {
    fn resolve(
        &self,
        hostname: &crate::target::Hostname,
        _limit: usize,
    ) -> Result<Vec<IpAddr>, crate::target::Error> {
        Err(crate::target::Error::NoAddresses {
            hostname: hostname.to_string(),
        })
    }
}

impl<'a> PolicyAuthorizer<'a, NoResolver> {
    /// Authorizer for a workflow that never resolves a declared target.
    pub fn for_packets(policy: &'a crate::policy::Policy) -> Self {
        Self {
            policy,
            resolver: &NoResolver,
        }
    }
}

impl<R: Resolver> Authorizer for PolicyAuthorizer<'_, R> {
    fn authorize_operation(&mut self, request: Operation<'_>) -> Result<(), BoundaryError> {
        self.policy.validate().map_err(BoundaryError::from_error)?;
        let budget = request.budget();
        self.policy
            .authorize_operation(budget.packets(), budget.wire_bytes())
            .map_err(BoundaryError::from_error)?;
        match request {
            Operation::Budgeted(_) => Ok(()),
            Operation::Declared(declared) => {
                if let PermissiveLive::Required { allowed } = declared.permissive_live() {
                    authorize_permissive_live(self.policy, allowed)
                        .map_err(BoundaryError::from_error)?;
                }
                if let Some(destination) = declared.destination() {
                    self.policy
                        .authorize_destination(destination)
                        .map_err(BoundaryError::from_error)?;
                }
                for packet in declared.packets() {
                    self.policy
                        .authorize_packet_destinations(packet)
                        .map_err(BoundaryError::from_error)?;
                }
                Ok(())
            }
            // Exact-frame replay needs the decode/rebuild round trip only the
            // replay system authorizer performs; approving the budget alone
            // would silently skip it.
            Operation::Replay(_) => Err(unsupported_operation("the policy authorizer", &request)),
        }
    }

    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
        self.policy
            .resolve_target(target, self.resolver)
            .map_err(BoundaryError::from_error)
    }
}

/// Which of the two permissive-live approvals is missing.
///
/// Callers that phrase the refusal in their own words (replay names the capture
/// bytes and the CLI flag) match on this instead of restating the check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PermissiveLiveDenial {
    /// The caller did not pass the per-operation opt-in for this run.
    OperationOptIn,
    /// The traffic policy does not stand behind permissively built bytes.
    PolicyApproval,
}

/// The two independent approvals permissively built bytes need before they can
/// reach the wire: the per-operation opt-in the caller passes for this run, and
/// the traffic policy's own standing allowance.
pub(crate) fn check_permissive_live(
    policy: &crate::policy::Policy,
    allow_permissive_live: bool,
) -> Result<(), PermissiveLiveDenial> {
    if !allow_permissive_live {
        return Err(PermissiveLiveDenial::OperationOptIn);
    }
    if !policy.allow_permissive_packets {
        return Err(PermissiveLiveDenial::PolicyApproval);
    }
    Ok(())
}

/// [`check_permissive_live`] phrased as the workflow error every caller but
/// replay reports.
pub(crate) fn authorize_permissive_live(
    policy: &crate::policy::Policy,
    allow_permissive_live: bool,
) -> Result<(), Error> {
    check_permissive_live(policy, allow_permissive_live).map_err(|denial| match denial {
        PermissiveLiveDenial::OperationOptIn => Error::PermissiveLiveOptInRequired,
        PermissiveLiveDenial::PolicyApproval => crate::policy::Error::PermissivePacket.into(),
    })
}

impl<R, N, I> Client<R, N, I> {
    pub(crate) fn authorize_built(
        &self,
        built: &BuiltPacket,
        allow_permissive_live: bool,
    ) -> Result<(), Error> {
        self.policy.authorize_packet_destinations(&built.packet)?;
        if built.requires_live_opt_in {
            authorize_permissive_live(&self.policy, allow_permissive_live)?;
        }
        Ok(())
    }

    pub(crate) fn authorize_final_wire(
        &self,
        built: &BuiltPacket,
        route: &packetcraftr_netio::route::Plan,
    ) -> Result<(), Error> {
        let link_type = match route.mode {
            LinkMode::Layer2 => route.decision.link_type,
            LinkMode::Layer3 => LinkType::RAW,
            LinkMode::Auto => return Err(LiveIoError::UnresolvedLinkMode.into()),
        };
        static REGISTRY: OnceLock<Result<Arc<Registry>, String>> = OnceLock::new();
        let registry = REGISTRY
            .get_or_init(|| {
                packetcraftr_core::protocol::builtin::registry()
                    .map(Arc::new)
                    .map_err(|error| error.to_string())
            })
            .as_ref()
            .map_err(|reason| crate::policy::Error::InvalidPacketSemantics {
                reason: reason.clone(),
            })?;
        if registry.root_for_link_type(link_type.0).is_none() {
            return Err(crate::policy::Error::InvalidPacketSemantics {
                reason: format!(
                    "final-wire authorization does not support link type {}",
                    link_type.0
                ),
            }
            .into());
        }
        let frame = Frame::new(
            std::time::SystemTime::UNIX_EPOCH,
            link_type,
            built.bytes.clone(),
        )
        .map_err(|error| crate::policy::Error::InvalidPacketSemantics {
            reason: error.to_string(),
        })?;
        let decoded = Dissector::new(Arc::clone(registry))
            .decode(frame, packetcraftr_core::decode::Options::default())
            .map_err(|error| crate::policy::Error::InvalidPacketSemantics {
                reason: error.to_string(),
            })?;
        self.policy.authorize_packet_destinations(&decoded.packet)?;
        self.policy
            .authorize_packet_sources(&decoded.packet, route)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use packetcraftr_core::error::Classified;

    use super::*;

    /// A workflow authorizer that only approves operations, so the trait's
    /// fail-closed resolution default is what answers a declared target.
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
    fn every_shape_carries_its_budget() {
        let packets = vec![documentation_packet()];
        let frame = Frame::new(std::time::UNIX_EPOCH, LinkType::RAW, vec![0x45_u8; 20])
            .expect("fixture frame");
        let budget = WireBudget::new(3, 40);
        let shapes = [
            Operation::Budgeted(budget),
            Operation::Declared(DeclaredPackets::new(
                budget,
                &packets,
                None,
                PermissiveLive::NotRequired,
            )),
            Operation::Replay(ReplayFrame::new(budget, &frame, LinkMode::Layer3)),
        ];
        for shape in shapes {
            assert_eq!(shape.budget(), budget);
            assert_eq!(shape.budget().packets(), 3);
            assert_eq!(shape.budget().wire_bytes(), 40);
        }
        let Operation::Replay(replay) = shapes[2] else {
            panic!("replay shape")
        };
        assert_eq!(replay.mode(), LinkMode::Layer3);
        assert_eq!(replay.frame().bytes().len(), 20);
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
        let packets = vec![documentation_packet()];
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
        let packets = vec![documentation_packet()];
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
            Error::PermissiveLiveOptInRequired.classification().code
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
    fn the_packet_authorizer_resolves_no_hostname() {
        let policy = crate::policy::Policy::default();

        let error = PolicyAuthorizer::for_packets(&policy)
            .resolve_and_authorize(&hostname_target())
            .expect_err("a packet authorizer has no resolver to answer with");

        assert_eq!(error.classification().code, "policy.hostname_resolution");
        assert!(error.to_string().contains("documentation.invalid"));
    }
}
