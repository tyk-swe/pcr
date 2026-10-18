// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use packetcraftr_netio::interface;

use crate::target::SelectedAddress;

use super::controller::{CITED_SEQUENCES, ControlResponder, Controller, Host};
use super::work::{Endpoint, Selection, Slot, Work};
use super::{Condition, HostIdentity};

pub(in crate::scan) fn state_charge(
    host_count: usize,
    endpoints_per_host: usize,
    pending_bound: usize,
    scoped_bytes: usize,
    shared_bytes: usize,
) -> usize {
    let host = std::mem::size_of::<Host>()
        .saturating_add(2usize.saturating_mul(std::mem::size_of::<HostIdentity>()))
        .saturating_add(std::mem::size_of::<Condition>())
        .saturating_add(std::mem::size_of::<(IpAddr, Option<interface::Id>)>())
        .saturating_add(std::mem::size_of::<usize>())
        .saturating_add(
            CITED_SEQUENCES
                .saturating_mul(3)
                .saturating_mul(std::mem::size_of::<u64>()),
        );
    // Reserve conservative B-tree node/allocation slack for the mutually
    // exclusive endpoint ready/retry entries and the three per-slot indexes.
    // Replacement removes old entries; retries never leave stale index state.
    let slot = std::mem::size_of::<Slot>()
        .saturating_add(384)
        .saturating_add(
            endpoints_per_host.saturating_mul(std::mem::size_of::<Endpoint>().saturating_add(192)),
        );
    let hosts = host_count
        .saturating_mul(host.saturating_add(slot).saturating_mul(2))
        .saturating_add(
            host_count
                .saturating_mul(endpoints_per_host)
                .saturating_mul(4)
                .saturating_mul(
                    std::mem::size_of::<(IpAddr, ControlResponder)>()
                        .saturating_add(CITED_SEQUENCES.saturating_mul(std::mem::size_of::<u64>())),
                ),
        );
    let live = pending_bound.saturating_mul(2).saturating_mul(
        std::mem::size_of::<u64>()
            .saturating_add(std::mem::size_of::<usize>())
            .saturating_add(std::mem::size_of::<Selection>()),
    );
    std::mem::size_of::<Controller>()
        .saturating_add(std::mem::size_of::<Work>())
        .saturating_add(hosts)
        .saturating_add(live)
        .saturating_add(scoped_bytes.saturating_mul(8))
        .saturating_add(shared_bytes)
}

pub(in crate::scan) fn scoped_bytes(targets: &[SelectedAddress]) -> usize {
    targets.iter().fold(0usize, |bytes, target| {
        bytes.saturating_add(target.scope_bytes())
    })
}
