// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::SystemTime;

use packetcraftr_core::packet::MacAddress;
use packetcraftr_netio::interface;

use super::{Mode, Unresponsive};
use crate::scan::Error;
use crate::scan::Reply;
use crate::target::{ResolvedZone, SelectedAddress};

/// What discovery concluded about a host. Silence is an observation: a host
/// that did not answer is never reported as absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum State {
    /// The request did not ask for discovery.
    NotRequested,
    /// The request explicitly skipped discovery.
    Skipped,
    /// At least one reason shows something answered for the host.
    Responded,
    /// Every discovery probe was silent or answered only by another
    /// responder, so reachability is uncertain.
    NoResponse,
}

/// Whether the scan stage probed the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scan {
    Scanned,
    /// Discovery got no response and no scan probes were sent to the host:
    /// the request skips unresponsive hosts, or its own link address stayed
    /// silent so no frame could be sent to it at all.
    Skipped,
    /// The request ran discovery only.
    NotRequested,
}

/// The observation behind a reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReasonKind {
    /// A correlated reply from the host's own address.
    Reply(Reply),
    /// A fresh ARP or NDP reply for the host's address.
    NeighborReply,
    /// A neighbor cache entry left by an earlier reply.
    NeighborCache,
    /// The operating system completed a TCP handshake.
    Connected,
    /// The operating system reported a reset: closed, but responsive.
    Refused,
}

impl ReasonKind {
    #[must_use]
    pub const fn evidence(self) -> Evidence {
        match self {
            Self::Reply(_) | Self::NeighborReply => Evidence::Wire,
            Self::NeighborCache => Evidence::Cache,
            Self::Connected | Self::Refused => Evidence::Socket,
        }
    }
}

/// Where a reason's observation came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Evidence {
    /// A captured frame.
    Wire,
    /// An ordinary socket result, with no frame behind it.
    Socket,
    /// The neighbor cache, not a reply observed by this request.
    Cache,
}

/// What a reason says about the host itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Basis {
    /// The host's own address answered.
    Direct,
    /// A cached neighbor entry, not a reply in this request.
    Cached,
    /// The link address also answered for another address of the same
    /// family, as a target or as a next hop, which a proxy would explain. No
    /// cause is asserted.
    PossibleProxy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reason {
    pub kind: ReasonKind,
    pub basis: Basis,
    /// The discovery probe whose outcome this is; absent for neighbor
    /// reasons, which the host's [`Neighbor`] record describes.
    pub probe: Option<u64>,
    /// The link address a neighbor reason observed: an observation, never
    /// the host's identity.
    pub link_address: Option<MacAddress>,
    pub observed_at: SystemTime,
}

/// A link-layer address and whether it came from the neighbor cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Link {
    pub address: MacAddress,
    pub cached: bool,
}

/// The gateway a routed host is reached through. Its link address belongs
/// to the gateway, not to the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NextHop {
    pub address: IpAddr,
    /// The cached entry for the next hop, if any. The next hop is not a
    /// selected target, so discovery sends it no request.
    pub link: Option<Link>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NeighborOutcome {
    /// The on-link host's address resolved.
    Resolved(Link),
    /// The host is on-link and no reply arrived.
    Silent,
    /// The host is routed through a next hop, and no request was sent.
    Routed(NextHop),
    /// The route to the host has no link-layer address resolution.
    NotApplicable,
}

/// One neighbor-discovery observation for a host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Neighbor {
    pub outcome: NeighborOutcome,
    /// Requests sent; zero when the cache answered or nothing was sent.
    pub attempts: u32,
    /// When the fresh reply was captured, or when the outcome was settled.
    pub observed_at: SystemTime,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Host {
    pub address: IpAddr,
    pub scope: Option<ResolvedZone>,
    pub state: State,
    /// Neighbor reasons first, then probe reasons in sequence order.
    pub reasons: Vec<Reason>,
    /// Present when the request selected neighbor discovery.
    pub neighbor: Option<Neighbor>,
    pub scan: Scan,
    /// The discovery probes sent to the host, by sequence.
    pub probes: Vec<u64>,
}

/// One discovery probe's outcome as the engine observed it.
#[derive(Clone, Debug)]
pub(in crate::scan) struct Observation {
    pub sequence: u64,
    pub address: IpAddr,
    pub interface: Option<interface::Id>,
    /// The reply or socket result, and who answered when known.
    pub response: Option<(ReasonKind, IpAddr)>,
    pub observed_at: SystemTime,
}

/// Builds one host record per selected target from neighbor and probe
/// observations, then settles the state and scan disposition.
pub(in crate::scan) struct Composer {
    mode: Mode,
    unresponsive: Unresponsive,
    hosts: Vec<Host>,
    indices: HashMap<(IpAddr, Option<interface::Id>), usize>,
}

impl Composer {
    pub(in crate::scan) fn new(
        targets: &[SelectedAddress],
        mode: Mode,
        unresponsive: Unresponsive,
    ) -> Self {
        let state = match mode {
            Mode::Omitted => State::NotRequested,
            Mode::Skipped => State::Skipped,
            Mode::Before | Mode::Only => State::NoResponse,
        };
        let hosts = targets
            .iter()
            .map(|target| Host {
                address: target.address,
                scope: target.scope.clone(),
                state,
                reasons: Vec::new(),
                neighbor: None,
                scan: Scan::Scanned,
                probes: Vec::new(),
            })
            .collect();
        let indices = targets
            .iter()
            .enumerate()
            .map(|(index, target)| {
                let interface = target.scope.as_ref().map(|scope| scope.interface.clone());
                ((target.address, interface), index)
            })
            .collect();
        Self {
            mode,
            unresponsive,
            hosts,
            indices,
        }
    }

    /// Records the neighbor observation for the target at `index` in the
    /// selection order.
    pub(in crate::scan) fn neighbor(&mut self, index: usize, neighbor: Neighbor) {
        if let Some(host) = self.hosts.get_mut(index) {
            host.neighbor = Some(neighbor);
        }
    }

    /// Records one discovery probe outcome. Only a response from the host's
    /// own address is a reason: an error from a router speaks for the path.
    pub(in crate::scan) fn observe(&mut self, observation: Observation) -> bool {
        let Some(&index) = self
            .indices
            .get(&(observation.address, observation.interface))
        else {
            return false;
        };
        let host = &mut self.hosts[index];
        host.probes.push(observation.sequence);
        if let Some((kind, responder)) = observation.response
            && responder == host.address
        {
            host.reasons.push(Reason {
                kind,
                basis: Basis::Direct,
                probe: Some(observation.sequence),
                link_address: None,
                observed_at: observation.observed_at,
            });
        }
        true
    }

    pub(in crate::scan) fn finish(mut self) -> Vec<Host> {
        // Every address each link address answered for, as a target or as a
        // routed target's next hop.
        let mut claims: HashMap<MacAddress, Vec<IpAddr>> = HashMap::new();
        for host in &self.hosts {
            let claim = match host.neighbor.map(|neighbor| neighbor.outcome) {
                Some(NeighborOutcome::Resolved(link)) => Some((link.address, host.address)),
                Some(NeighborOutcome::Routed(NextHop {
                    address,
                    link: Some(link),
                })) => Some((link.address, address)),
                _ => None,
            };
            if let Some((link, address)) = claim {
                claims.entry(link).or_default().push(address);
            }
        }
        for host in &mut self.hosts {
            host.probes.sort_unstable();
            host.reasons.sort_by_key(|reason| reason.probe);
            if let (Some(link), Some(neighbor)) = (resolved(host), host.neighbor) {
                // A dual-stack host answers for each family from one link
                // address, so only another address of the same family counts.
                let shared = claims.get(&link.address).is_some_and(|addresses| {
                    addresses.iter().any(|address| {
                        *address != host.address && address.is_ipv4() == host.address.is_ipv4()
                    })
                });
                let basis = if shared {
                    Basis::PossibleProxy
                } else if link.cached {
                    Basis::Cached
                } else {
                    Basis::Direct
                };
                host.reasons.insert(
                    0,
                    Reason {
                        kind: if link.cached {
                            ReasonKind::NeighborCache
                        } else {
                            ReasonKind::NeighborReply
                        },
                        basis,
                        probe: None,
                        link_address: Some(link.address),
                        observed_at: neighbor.observed_at,
                    },
                );
            }
            if matches!(self.mode, Mode::Before | Mode::Only) && !host.reasons.is_empty() {
                host.state = State::Responded;
            }
            host.scan = match self.mode {
                Mode::Only => Scan::NotRequested,
                Mode::Before
                    if host.state == State::NoResponse
                        && (self.unresponsive == Unresponsive::Skip || unsendable(host)) =>
                {
                    Scan::Skipped
                }
                Mode::Omitted | Mode::Skipped | Mode::Before => Scan::Scanned,
            };
        }
        self.hosts
    }
}

/// An on-link target whose own address never resolved accepts no frame, so
/// the scan stage cannot send it probes whatever the unresponsive policy is.
fn unsendable(host: &Host) -> bool {
    matches!(
        host.neighbor.map(|neighbor| neighbor.outcome),
        Some(NeighborOutcome::Silent)
    )
}

fn resolved(host: &Host) -> Option<Link> {
    match host.neighbor?.outcome {
        NeighborOutcome::Resolved(link) => Some(link),
        NeighborOutcome::Silent | NeighborOutcome::Routed(_) | NeighborOutcome::NotApplicable => {
            None
        }
    }
}

/// Checks that the hosts list exactly the collected discovery outcomes, given
/// in sequence order, so consumers can pair them by sequence.
pub(in crate::scan) fn check_probes(
    hosts: &[Host],
    collected: impl Iterator<Item = u64>,
) -> Result<(), Error> {
    let mut listed: Vec<u64> = hosts
        .iter()
        .flat_map(|host| host.probes.iter().copied())
        .collect();
    listed.sort_unstable();
    if listed.into_iter().eq(collected) {
        Ok(())
    } else {
        Err(Error::IncoherentEvents {
            message: "host records disagree with the collected discovery probes".to_owned(),
        })
    }
}
