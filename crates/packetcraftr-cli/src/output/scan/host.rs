// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Host records: what discovery observed for each selected target, and
//! whether the scan stage probed it.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::Serialize;

use packetcraftr::dns;
use packetcraftr::scan::Reply;
use packetcraftr::scan::discovery;

use super::Scope;
use crate::output::contract::Error;
use crate::output::dns::{Outcome, QuestionStatus};
use crate::output::frame::Timestamp;
use crate::output::network::{InterfaceId, MacAddress};
use crate::output::stream::StreamRecord;

published_enum! {
    pub enum State from discovery::State {
        NotRequested => "not_requested",
        Skipped => "skipped",
        Responded => "responded",
        NoResponse => "no_response",
    }
}

published_enum! {
    pub enum Scan from discovery::Scan {
        Scanned => "scanned",
        Skipped => "skipped",
        NotRequested => "not_requested",
    }
}

published_enum! {
    pub enum Evidence from discovery::Evidence {
        Wire => "wire",
        Socket => "socket",
        Cache => "cache",
    }
}

published_enum! {
    pub enum Basis from discovery::Basis {
        Direct => "direct",
        Cached => "cached",
        PossibleProxy => "possible_proxy",
    }
}

const fn reason_kind(kind: discovery::ReasonKind) -> &'static str {
    use discovery::ReasonKind;
    match kind {
        ReasonKind::Reply(reply) => match reply {
            Reply::TcpSynAck => "tcp_syn_ack",
            Reply::TcpReset => "tcp_reset",
            Reply::TcpOther => "tcp_other",
            Reply::UdpPayload => "udp_payload",
            Reply::IcmpEchoReply => "icmp_echo_reply",
            Reply::IcmpPortUnreachable => "icmp_port_unreachable",
            Reply::IcmpAdministrativelyProhibited => "icmp_administratively_prohibited",
            Reply::IcmpDestinationUnreachable => "icmp_destination_unreachable",
            Reply::IcmpTimeExceeded => "icmp_time_exceeded",
        },
        ReasonKind::NeighborReply => "neighbor_reply",
        ReasonKind::NeighborCache => "neighbor_cache",
        ReasonKind::Connected => "tcp_connected",
        ReasonKind::Refused => "tcp_refused",
    }
}

/// Why a host counts as responded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Reason {
    pub kind: &'static str,
    pub evidence: Evidence,
    pub basis: Basis,
    /// The discovery probe behind the reason; absent for neighbor reasons.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe: Option<u64>,
    /// The link address a neighbor reason observed, never the host's identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_address: Option<MacAddress>,
    pub observed_at: Timestamp,
}

impl TryFrom<discovery::Reason> for Reason {
    type Error = Error;

    fn try_from(reason: discovery::Reason) -> Result<Self, Error> {
        Ok(Self {
            kind: reason_kind(reason.kind),
            evidence: reason.kind.evidence().into(),
            basis: reason.basis.into(),
            probe: reason.probe,
            link_address: reason.link_address.map(Into::into),
            observed_at: reason.observed_at.try_into()?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Entry {
    /// A reply to this request's ARP or NDP.
    Fresh,
    /// A neighbor cache entry left by an earlier reply.
    Cached,
}

impl Entry {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Cached => "cached",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Link {
    pub address: MacAddress,
    pub entry: Entry,
}

impl From<discovery::Link> for Link {
    fn from(link: discovery::Link) -> Self {
        Self {
            address: link.address.into(),
            entry: if link.cached {
                Entry::Cached
            } else {
                Entry::Fresh
            },
        }
    }
}

/// The gateway a routed host is reached through; its link address is the
/// gateway's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct NextHop {
    pub address: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<Link>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Neighbor {
    /// `resolved`, `silent`, `routed`, or `not_applicable`.
    pub outcome: &'static str,
    /// The interface the host's route selected, where any reply was observed.
    pub interface: InterfaceId,
    pub attempts: u32,
    pub observed_at: Timestamp,
    /// The host's own link address; present when `outcome` is `resolved`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<Link>,
    /// Present when `outcome` is `routed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_hop: Option<NextHop>,
}

impl TryFrom<discovery::Neighbor> for Neighbor {
    type Error = Error;

    fn try_from(neighbor: discovery::Neighbor) -> Result<Self, Error> {
        use discovery::NeighborOutcome;
        let (outcome, link, next_hop) = match neighbor.outcome {
            NeighborOutcome::Resolved(link) => ("resolved", Some(link.into()), None),
            NeighborOutcome::Silent => ("silent", None, None),
            NeighborOutcome::Routed(next_hop) => (
                "routed",
                None,
                Some(NextHop {
                    address: next_hop.address,
                    link: next_hop.link.map(Into::into),
                }),
            ),
            NeighborOutcome::NotApplicable => ("not_applicable", None, None),
        };
        Ok(Self {
            outcome,
            interface: neighbor.interface.into(),
            attempts: neighbor.attempts,
            observed_at: neighbor.observed_at.try_into()?,
            link,
            next_hop,
        })
    }
}

/// A PTR lookup's result: what the server answered, never authenticated
/// identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReverseDns {
    pub query_name: String,
    pub status: QuestionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_code: Option<u16>,
    /// Distinct PTR names in answer order, each with its trailing dot.
    pub names: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ReverseDns {
    /// A lookup that ended without a DNS workflow result.
    #[must_use]
    pub fn ended(query_name: String, status: QuestionStatus, error: Option<String>) -> Self {
        Self {
            query_name,
            status,
            outcome: None,
            response_code: None,
            names: Vec::new(),
            error,
        }
    }
}

impl From<dns::batch::Question<dns::Aggregate>> for ReverseDns {
    fn from(question: dns::batch::Question<dns::Aggregate>) -> Self {
        let result = question.result.as_ref();
        Self {
            query_name: question.query_name,
            status: question.status.into(),
            outcome: result.map(|result| result.report().completion.outcome().into()),
            response_code: result
                .and_then(|result| result.report().completion.response())
                .map(|metadata| metadata.response_code),
            names: result
                .and_then(dns::Aggregate::response)
                .map(|response| {
                    dns::ptr_names(&response.answers)
                        .iter()
                        .map(ToString::to_string)
                        .collect()
                })
                .unwrap_or_default(),
            error: question.error.as_ref().map(ToString::to_string),
        }
    }
}

/// One record per selected target. JSON embeds the discovery probes; stream
/// records list their sequence numbers, which `probe` records already carried.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Host<P> {
    pub address: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
    pub discovery: State,
    pub scan: Scan,
    pub reasons: Vec<Reason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub neighbor: Option<Neighbor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverse_dns: Option<ReverseDns>,
    pub probes: Vec<P>,
}

impl<P> Host<P> {
    pub fn publish(
        host: discovery::Host,
        probes: Vec<P>,
        reverse_dns: Option<ReverseDns>,
    ) -> Result<Self, Error> {
        Ok(Self {
            address: host.address,
            scope: host.scope.as_ref().map(Scope::from),
            discovery: host.state.into(),
            scan: host.scan.into(),
            reasons: host
                .reasons
                .into_iter()
                .map(Reason::try_from)
                .collect::<Result<_, _>>()?,
            neighbor: host.neighbor.map(Neighbor::try_from).transpose()?,
            reverse_dns,
            probes,
        })
    }
}

impl Host<u64> {
    /// The stream record, sent after the last endpoint record and before
    /// `complete`.
    pub fn summarize(
        host: discovery::Host,
        reverse_dns: Option<ReverseDns>,
    ) -> Result<Self, Error> {
        let probes = host.probes.clone();
        Self::publish(host, probes, reverse_dns)
    }
}

impl StreamRecord for Host<u64> {
    fn event_name(&self) -> &'static str {
        "host"
    }
}

/// Publishes every host with its discovery probes, which the library
/// guarantees are exactly `discovery`, and with the reverse lookup at its
/// position, if any.
pub(super) fn publish_all<E, P>(
    hosts: Vec<discovery::Host>,
    discovery: Vec<E>,
    sequence: impl Fn(&E) -> u64,
    probe: impl Fn(E) -> Result<P, Error>,
    reverse_dns: Vec<Option<ReverseDns>>,
) -> Result<Vec<Host<P>>, Error> {
    let mut discovery: BTreeMap<u64, E> = discovery
        .into_iter()
        .map(|evidence| (sequence(&evidence), evidence))
        .collect();
    let mut reverse_dns = reverse_dns.into_iter();
    hosts
        .into_iter()
        .map(|host| {
            let probes = host
                .probes
                .iter()
                .filter_map(|sequence| discovery.remove(sequence))
                .map(&probe)
                .collect::<Result<_, _>>()?;
            Host::publish(host, probes, reverse_dns.next().flatten())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use packetcraftr::scan::discovery;
    use packetcraftr_netio::interface;
    use serde_json::json;

    use super::Neighbor;

    #[test]
    fn a_neighbor_publishes_the_interface_its_reply_was_observed_on() {
        let neighbor = discovery::Neighbor {
            outcome: discovery::NeighborOutcome::Silent,
            interface: interface::Id {
                name: "fixture0".into(),
                index: 1,
            },
            attempts: 1,
            observed_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        };
        let published = serde_json::to_value(Neighbor::try_from(neighbor).unwrap()).unwrap();
        assert_eq!(
            published["interface"],
            json!({"name": "fixture0", "index": 1})
        );
    }
}
