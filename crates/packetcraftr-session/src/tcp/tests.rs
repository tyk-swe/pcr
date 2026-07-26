// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use super::state::{
    TcpFlowState, append_emitted_history, emitted_history_conflicts, trim_emitted_history,
};
use super::*;

fn flow() -> FlowKey {
    FlowKey {
        source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        source_port: 12345,
        destination: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
        destination_port: 80,
    }
}

fn segment(sequence: u32, payload: &'static [u8]) -> Segment {
    Segment {
        flow: flow(),
        sequence,
        payload: Bytes::from_static(payload),
        syn: false,
        fin: false,
        rst: false,
    }
}

fn emitted_bytes(state: &TcpFlowState) -> Vec<u8> {
    state.emitted_history.iter().copied().collect()
}

mod history_order;
mod lifecycle_fin;
mod limits_atomicity;
