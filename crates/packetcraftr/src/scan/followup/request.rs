// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::scan;
use crate::target;
use crate::{dns, traceroute};

use super::Error;
use super::reverse::Lookup;
use super::trace::Stage;

/// The trace stage of a scan: every scanned host, traced under one plan with
/// the probes the scan saw it answer. The caller resolves argument defaults,
/// so `strategy` already names its transport and destination port.
#[derive(Clone, Debug)]
pub struct Trace {
    pub strategy: Option<traceroute::hosts::Strategy>,
    pub first_hop: u8,
    pub max_hops: u8,
    pub attempts: u32,
    pub max_probes: usize,
    pub reuse: Option<traceroute::hosts::Reuse>,
    /// The worker runtime the trace stage publishes through. `None` gives it a
    /// fresh runtime of the client's capacity, so workers an earlier stage
    /// timed out cannot hold its permits.
    pub runtime: Option<crate::runtime::Runtime>,
}

impl Trace {
    /// Rejects a trace no host could use before the scan sends anything.
    pub fn validate(&self, scan: &scan::Request) -> Result<(), Error> {
        Stage::new(self, scan).map(drop)
    }
}

/// One DNS server answering a PTR question for every scanned host. The scan's
/// attempts, timeout, rate, and evidence limits bound each question, and its
/// duration limit bounds the lookups together with the scan.
#[derive(Clone, Debug)]
pub struct ReverseDns {
    pub server: target::Target,
    pub server_port: u16,
    pub transport: dns::TransportMode,
}

impl ReverseDns {
    /// Rejects a template no question could use, such as a zero server
    /// port or a scoped server, before the scan sends anything.
    pub fn validate(&self, scan: &scan::Request) -> Result<(), Error> {
        Lookup::new(self, scan).map(drop)
    }
}

/// A packet scan with its optional trace and reverse-DNS follow-ups.
#[derive(Clone, Debug)]
pub struct Request {
    pub scan: scan::Request,
    pub trace: Option<Trace>,
    pub reverse_dns: Option<ReverseDns>,
}

/// A TCP connect scan with its optional reverse-DNS follow-up.
#[derive(Clone, Debug)]
pub struct ConnectRequest {
    pub scan: scan::Request,
    pub reverse_dns: Option<ReverseDns>,
}
