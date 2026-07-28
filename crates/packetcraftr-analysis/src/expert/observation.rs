// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Immutable normalized TCP facts for one matched frame.

use super::{FlowKey, FrameRecord, StreamRef, Tcp, tcp_stream_ref};

#[derive(Clone, Copy)]
pub(super) struct TcpObservation<'a> {
    pub(super) number: u64,
    pub(super) stream: Option<StreamRef>,
    pub(super) flow: &'a FlowKey,
    pub(super) tcp: &'a Tcp,
    pub(super) payload_len: usize,
    pub(super) syn: bool,
    pub(super) fin: bool,
    pub(super) rst: bool,
    pub(super) ack: bool,
}

impl<'a> TcpObservation<'a> {
    pub(super) fn new(
        record: &FrameRecord<'_>,
        flow: &'a FlowKey,
        tcp: &'a Tcp,
        payload_len: usize,
    ) -> Self {
        Self {
            number: record.number,
            stream: record.tcp_stream.map(tcp_stream_ref),
            flow,
            tcp,
            payload_len,
            syn: tcp.flags & Tcp::SYN != 0,
            fin: tcp.flags & Tcp::FIN != 0,
            rst: tcp.flags & Tcp::RST != 0,
            ack: tcp.flags & Tcp::ACK != 0,
        }
    }
}
