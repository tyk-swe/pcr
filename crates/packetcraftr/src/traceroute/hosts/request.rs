// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::time::{Duration, Instant};

use packetcraftr_core::error::BoundaryError;
use packetcraftr_netio::deadline::MAX_WAIT;

use super::selection::Observed;
use crate::execution::limits::{check_limits, duration_violation};
use crate::probe::Transport;
use crate::scan::Reply;
use crate::target::{Family, Selection};
use crate::traceroute::request::{Bounds, check_collection, check_destination_port, tcp_payload};
use crate::traceroute::{Error, Limits, MAX_PROBES};

/// A transport and, for TCP and UDP, the destination port to trace with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Strategy {
    pub transport: Transport,
    /// UDP base destination port or fixed TCP destination port. ICMP
    /// requires this to be absent.
    pub destination_port: Option<u16>,
}

impl Strategy {
    fn validate(&self) -> Result<(), Error> {
        check_destination_port(self.transport, self.destination_port)
    }
}

/// Bounds reuse of one host's hops for another host in the same operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reuse {
    /// How long after its batch was planned a hop may still be reused.
    pub max_age: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub targets: Selection,
    pub max_targets: usize,
    pub address_family: Family,
    /// Probe for hosts no observation covers; `None` leaves them not traced.
    pub strategy: Option<Strategy>,
    /// Responsive probes a scan observed; see [`observed`](super::observed).
    pub observed: Vec<Observed>,
    /// UDP and TCP probes only; ICMP ignores it.
    pub source_port: Option<u16>,
    /// Zero bytes appended to every UDP or ICMP echo probe; TCP probes require 0.
    pub payload_size: u16,
    /// Sets the IPv4 Don't Fragment flag on every probe; an IPv6 host is refused.
    pub dont_fragment: bool,
    /// Differentiated Services code point, `0..=63`.
    pub dscp: u8,
    pub first_hop: u8,
    pub max_hops: u8,
    pub probes_per_hop: u32,
    pub timeout: Duration,
    pub probes_per_second: Option<u32>,
    /// When the operation's previous transmission, such as a scan's last
    /// probe, was sent. The first batch waits what remains of one probe's
    /// rate interval after it; ignored without a rate.
    pub paced_after: Option<Instant>,
    pub reuse: Option<Reuse>,
    /// One budget for every host.
    pub limits: Limits,
    pub route: crate::route::Options,
    /// It must retain at least one response per probe of a hop.
    pub collection: crate::exchange::Collection,
}

impl Request {
    pub fn validate(&self) -> Result<(), Error> {
        Bounds {
            limits: &self.limits,
            first_hop: self.first_hop,
            max_hops: self.max_hops,
            probes_per_hop: self.probes_per_hop,
            timeout: self.timeout,
            probes_per_second: self.probes_per_second,
            payload_size: self.payload_size,
            dscp: self.dscp,
        }
        .validate()?;
        check_limits(
            &[("max_targets", self.max_targets, MAX_PROBES)],
            &[],
            |field, value, reason| Error::InvalidLimit {
                field,
                value,
                reason,
            },
        )?;
        self.targets.validate().map_err(Error::TargetSelection)?;
        if let Some(strategy) = &self.strategy {
            strategy.validate()?;
            if strategy.transport == Transport::Tcp && self.payload_size > 0 {
                return Err(tcp_payload());
            }
        }
        if self.source_port == Some(0) {
            return Err(Error::InvalidSourcePort);
        }
        self.validate_observed()?;
        check_collection(&self.collection, &self.limits, self.probes_per_hop)?;
        self.collection
            .validate()
            .map_err(|source| Error::Collection(BoundaryError::from_error(source)))?;
        if let Some(reuse) = &self.reuse
            && duration_violation(reuse.max_age, MAX_WAIT)
        {
            return Err(if reuse.max_age.is_zero() {
                Error::InvalidLimit {
                    field: "reuse_max_age",
                    value: 0,
                    reason: "must be non-zero".to_owned(),
                }
            } else {
                Error::InvalidDuration {
                    value: reuse.max_age,
                    maximum: MAX_WAIT,
                }
            });
        }
        Ok(())
    }

    fn validate_observed(&self) -> Result<(), Error> {
        let invalid = |message: String| Error::InvalidObservation { message };
        let mut seen = HashSet::new();
        // One observation per scan probe too: the same sequence on two
        // addresses cannot be the distinct replies the plan rests on.
        let mut seen_sequences = HashSet::new();
        for observed in &self.observed {
            if !seen.insert(observed.address) {
                return Err(invalid(format!(
                    "more than one observation for {}",
                    observed.address
                )));
            }
            if !seen_sequences.insert(observed.sequence) {
                return Err(invalid(format!(
                    "the observation for {} repeats scan sequence {}",
                    observed.address, observed.sequence
                )));
            }
            match (
                observed.transport,
                observed.destination_port,
                observed.reply,
            ) {
                (Transport::Tcp, Some(port), Reply::TcpSynAck | Reply::TcpReset) if port != 0 => {}
                (Transport::Icmp, None, Reply::IcmpEchoReply) => {}
                (transport, port, reply) => {
                    return Err(invalid(format!(
                        "{transport} observation for {} with port {port:?} and reply {reply:?} \
                         cannot select a trace; only a TCP SYN/ACK or reset on a non-zero port \
                         and a portless ICMP echo reply can",
                        observed.address
                    )));
                }
            }
        }
        Ok(())
    }

    // `validate` rejects `max_hops < first_hop`, so the u8 subtraction cannot underflow, and a u8
    // widened to usize leaves room for the increment
    pub(super) fn hop_count(&self) -> usize {
        usize::from(self.max_hops - self.first_hop) + 1
    }

    pub(super) fn host_probe_cap(&self) -> Result<usize, Error> {
        self.hop_count()
            .checked_mul(usize::try_from(self.probes_per_hop).unwrap_or(usize::MAX))
            .ok_or(overflow("probes"))
    }
}

pub(super) fn overflow(field: &'static str) -> Error {
    Error::InvalidLimit {
        field,
        value: u64::MAX,
        reason: format!("{field} arithmetic overflowed"),
    }
}
