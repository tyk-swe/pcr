// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{ScopedFlowKey, StreamRef, Tcp, tcp_stream_ref};

#[derive(Clone, Copy)]
pub(super) struct TcpObservation<'a> {
    pub(super) number: u64,
    pub(super) stream: Option<StreamRef>,
    pub(super) flow: &'a ScopedFlowKey,
    pub(super) tcp: &'a Tcp,
    pub(super) payload_len: usize,
    pub(super) syn: bool,
    pub(super) fin: bool,
    pub(super) rst: bool,
    pub(super) ack: bool,
}

impl<'a> TcpObservation<'a> {
    pub(super) fn new(
        number: u64,
        conversation: crate::analysis::Conversation<'a>,
        view: crate::analysis::TcpView<'a>,
    ) -> Self {
        let tcp = view.header;
        Self {
            number,
            stream: Some(tcp_stream_ref(conversation.index)),
            flow: conversation.flow,
            tcp,
            payload_len: view.payload.len(),
            syn: tcp.flags & Tcp::SYN != 0,
            fin: tcp.flags & Tcp::FIN != 0,
            rst: tcp.flags & Tcp::RST != 0,
            ack: tcp.flags & Tcp::ACK != 0,
        }
    }
}
