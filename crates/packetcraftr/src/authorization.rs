// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The single authorization seam every live workflow passes through.
//!
//! Scan, DNS, traceroute, fuzz, and replay all ask the same question before
//! they can produce traffic: may this operation run, with these packets, this
//! destination, and this many wire bytes? [`Authorizer`] is that question,
//! [`Operation`] is what a workflow can say about its operation, and
//! [`PolicyAuthorizer`] is the answer a [`crate::policy::Policy`] gives.

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::{Packet, build::BuiltPacket, decode::Dissector, registry::Registry};
use packetcraftr_netio::{Error as LiveIoError, link::Mode as LinkMode};

use crate::Client;
use crate::Error;
use crate::target::{Authorized, Resolver, Target};

/// What a workflow declares about the operation it wants to run. Each workflow
/// fills in the fields its operation can produce and leaves the rest at their
/// defaults, so an authorizer never has to guess what was not said.
#[derive(Clone, Copy, Debug, Default)]
pub struct Operation<'a> {
    /// Prospective count of packets that reach the wire.
    pub packets: u64,
    /// Prospective wire bytes, counted conservatively.
    pub wire_bytes: u64,
    /// Packets whose declared destinations must be authorized before a route,
    /// capture, neighbor, or transmission provider can observe them.
    pub declared: &'a [Packet],
    /// A route destination chosen outside the packets themselves.
    pub destination: Option<IpAddr>,
    /// One exact frame, with the link mode it would be transmitted in.
    pub frame: Option<(&'a Frame, LinkMode)>,
    /// The operation would put permissively built or malformed bytes on the wire.
    pub requires_permissive_live: bool,
    /// The caller passed the per-operation opt-in for those bytes.
    pub allow_permissive_live: bool,
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
        self.policy
            .authorize_operation(request.packets, request.wire_bytes)
            .map_err(BoundaryError::from_error)?;
        if request.requires_permissive_live {
            authorize_permissive_live(self.policy, request.allow_permissive_live)
                .map_err(BoundaryError::from_error)?;
        }
        if let Some(destination) = request.destination {
            self.policy
                .authorize_destination(destination)
                .map_err(BoundaryError::from_error)?;
        }
        for packet in request.declared {
            self.policy
                .authorize_packet_destinations(packet)
                .map_err(BoundaryError::from_error)?;
        }
        Ok(())
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
