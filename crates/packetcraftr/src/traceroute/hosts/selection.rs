// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::SystemTime;

use super::report::{Basis, NotTraced, Selection};
use super::request::{Request, Strategy};
use crate::probe::{Reply, Stage, Transport};
use crate::target::SelectedAddress;

/// A probe a host answered during a scan, kept with the evidence that makes
/// it a sound choice for tracing that host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observed {
    pub address: IpAddr,
    pub transport: Transport,
    /// The TCP port that answered; `None` for ICMP.
    pub destination_port: Option<u16>,
    pub stage: Stage,
    /// The scan probe's sequence.
    pub sequence: u64,
    pub reply: Reply,
    /// When the scan captured the reply.
    pub observed_at: Option<SystemTime>,
}

pub(super) enum Choice {
    Traced(Selection),
    NotTraced(NotTraced),
}

/// Picks the probe for one selected host: its observation first, then the
/// request's strategy; a host with neither is never guessed at.
pub(super) fn choose(
    request: &Request,
    observations: &HashMap<IpAddr, &Observed>,
    target: &SelectedAddress,
) -> Choice {
    if target.scope.is_some() {
        return Choice::NotTraced(NotTraced::ScopedTarget);
    }
    if let Some(observed) = observations.get(&target.address) {
        return Choice::Traced(Selection {
            strategy: Strategy {
                transport: observed.transport,
                destination_port: observed.destination_port,
            },
            basis: Basis::Observed((*observed).clone()),
        });
    }
    match request.strategy {
        Some(strategy) => Choice::Traced(Selection {
            strategy,
            basis: Basis::Requested,
        }),
        None => Choice::NotTraced(NotTraced::NoResponsiveProbe),
    }
}
