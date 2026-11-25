// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Pre-election candidate buffers and post-election client/server directions.

use super::Context;
use crate::analysis::ScopedFlowKey;
use crate::analysis::http2::Error;
use crate::analysis::http2::budget::{self, Charge};
use crate::analysis::http2::buffer::SourceBuffer;
use crate::analysis::http2::model::Startup;
use crate::analysis::http2::settings::DirectionSettings;
use crate::analysis::http2::side::Side;
use crate::analysis::provenance::SourceSet;
use crate::protocol::application::http2::{self as wire, hpack};
use std::collections::HashMap;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectionPhase {
    Prelude,
    Preface,
    Frames,
}

pub(crate) struct Chain {
    pub stream_id: u32,
    pub head: ChainHead,
    pub bytes: bytes::BytesMut,
    pub frames: usize,
    pub sets: Vec<SourceSet>,
    pub charge: Charge,
}

#[derive(Clone, Copy)]
pub(crate) enum ChainHead {
    Headers { end_stream: bool, malformed: bool },
    PushPromise { promised: u32 },
}

pub(crate) struct CandidateDirection {
    pub flow: ScopedFlowKey,
    pub buffer: SourceBuffer,
    pub closed: bool,
    pub received: bool,
    pub garbage: bool,
}

impl CandidateDirection {
    pub(crate) fn new(flow: ScopedFlowKey) -> Self {
        Self {
            flow,
            buffer: SourceBuffer::new(),
            closed: false,
            received: false,
            garbage: false,
        }
    }

    pub(crate) fn into_elected(
        self,
        phase: DirectionPhase,
        decoder: hpack::Decoder,
    ) -> ElectedDirection {
        ElectedDirection {
            flow: self.flow,
            phase,
            buffer: self.buffer,
            decoder: Some(decoder),
            decoder_charge: Charge::default(),
            block_sources: HashMap::new(),
            chain: None,
            closed: self.closed,
            fully_consumed_fin: false,
            saw_frame: false,
            origins_charge: Charge::default(),
        }
    }
}

pub(crate) struct SniffingDirections {
    pub candidates: Vec<CandidateDirection>,
    pub overhead: Charge,
}

impl SniffingDirections {
    pub(crate) fn new() -> Self {
        Self {
            candidates: Vec::new(),
            overhead: Charge::default(),
        }
    }

    pub(crate) fn has_flow(&self, flow: &ScopedFlowKey) -> bool {
        self.candidates.iter().any(|dir| dir.flow == *flow)
    }

    pub(crate) fn find(&self, flow: &ScopedFlowKey) -> Option<&CandidateDirection> {
        self.candidates.iter().find(|dir| dir.flow == *flow)
    }

    pub(crate) fn find_mut(&mut self, flow: &ScopedFlowKey) -> Option<&mut CandidateDirection> {
        self.candidates.iter_mut().find(|dir| dir.flow == *flow)
    }

    pub(crate) fn ensure_candidate(
        &mut self,
        flow: ScopedFlowKey,
        closed: bool,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        if self.has_flow(&flow) || self.candidates.len() >= 2 {
            return Ok(());
        }
        context.charge(&mut self.overhead, budget::DIR_OVERHEAD)?;
        let mut dir = CandidateDirection::new(flow);
        dir.closed = closed;
        self.candidates.push(dir);
        Ok(())
    }

    pub(crate) fn primary_flow(&self, fallback: &ScopedFlowKey) -> ScopedFlowKey {
        self.candidates
            .first()
            .map_or_else(|| fallback.clone(), |dir| dir.flow.clone())
    }

    pub(crate) fn known_flows(&self) -> Vec<ScopedFlowKey> {
        self.candidates.iter().map(|dir| dir.flow.clone()).collect()
    }

    pub(crate) fn buffered_len(&self) -> usize {
        self.candidates.iter().map(|dir| dir.buffer.len()).sum()
    }

    pub(crate) fn elect(
        mut self,
        client_index: usize,
        startup: Startup,
        context: &Context<'_>,
    ) -> Result<(ElectedDirections, bool), Error> {
        let client_phase = match startup {
            Startup::PriorKnowledge => DirectionPhase::Preface,
            Startup::H2c | Startup::Unknown => DirectionPhase::Prelude,
        };
        let server_phase = match startup {
            Startup::PriorKnowledge => DirectionPhase::Frames,
            Startup::H2c | Startup::Unknown => DirectionPhase::Prelude,
        };
        let client_candidate = self.candidates.swap_remove(client_index);
        let client = client_candidate
            .into_elected(client_phase, hpack::Decoder::new(context.limits.hpack())?);
        let mut clean_start = true;
        let mut server = None;
        for candidate in self.candidates {
            if !candidate.buffer.is_empty() {
                clean_start = false;
            }
            server = Some(
                candidate.into_elected(server_phase, hpack::Decoder::new(context.limits.hpack())?),
            );
        }
        Ok((
            ElectedDirections {
                client,
                server,
                overhead: self.overhead,
            },
            clean_start,
        ))
    }

    pub(crate) fn release_buffers(&mut self, context: &mut Context<'_>) -> Result<(), Error> {
        for dir in &mut self.candidates {
            dir.buffer.clear(context)?;
        }
        Ok(())
    }
}

pub(crate) struct ElectedDirection {
    pub flow: ScopedFlowKey,
    pub phase: DirectionPhase,
    pub buffer: SourceBuffer,
    pub decoder: Option<hpack::Decoder>,
    pub decoder_charge: Charge,
    pub block_sources: HashMap<u64, SourceSet>,
    pub chain: Option<Chain>,
    pub closed: bool,
    pub fully_consumed_fin: bool,
    pub saw_frame: bool,
    pub origins_charge: Charge,
}

impl ElectedDirection {
    pub(crate) fn new(
        flow: ScopedFlowKey,
        phase: DirectionPhase,
        decoder: Option<hpack::Decoder>,
    ) -> Self {
        Self {
            flow,
            phase,
            buffer: SourceBuffer::new(),
            decoder,
            decoder_charge: Charge::default(),
            block_sources: HashMap::new(),
            chain: None,
            closed: false,
            fully_consumed_fin: false,
            saw_frame: false,
            origins_charge: Charge::default(),
        }
    }

    pub(crate) fn is_clean_eof(&self) -> bool {
        self.closed && self.buffer.is_empty() && self.chain.is_none()
    }

    pub(crate) fn has_buffered_settings_ack(&self) -> bool {
        let bytes = self.buffer.bytes();
        self.saw_frame
            && self.chain.is_none()
            && bytes.len() >= wire::HEADER_LEN
            && wire::declared_length(bytes) == 0
            && bytes[3] == wire::TYPE_SETTINGS
            && bytes[4] & wire::FLAG_ACK != 0
            && bytes[5] & 0x7f == 0
            && bytes[6..9] == [0, 0, 0]
    }

    pub(crate) fn sync_decoder(&mut self, context: &mut Context<'_>) -> Result<(), Error> {
        let Some(decoder) = self.decoder.as_ref() else {
            return Ok(());
        };
        let now = decoder.buffered_bytes();
        let charged = self.decoder_charge.bytes();
        if now > charged {
            context.charge(&mut self.decoder_charge, now - charged)
        } else {
            context.release(&mut self.decoder_charge, charged - now)
        }
    }

    pub(crate) fn release_all(&mut self, context: &mut Context<'_>) -> Result<(), Error> {
        self.buffer.clear(context)?;
        context.release_all(&mut self.origins_charge)?;
        context.release_all(&mut self.decoder_charge)?;
        if let Some(chain) = self.chain.as_mut() {
            context.release_all(&mut chain.charge)?;
        }
        self.decoder = None;
        self.block_sources.clear();
        self.chain = None;
        Ok(())
    }
}

pub(crate) struct ElectedDirections {
    pub client: ElectedDirection,
    pub server: Option<ElectedDirection>,
    pub overhead: Charge,
}

impl ElectedDirections {
    pub(crate) fn get(&self, side: Side) -> Option<&ElectedDirection> {
        match side {
            Side::Client => Some(&self.client),
            Side::Server => self.server.as_ref(),
        }
    }

    pub(crate) fn get_mut(&mut self, side: Side) -> Option<&mut ElectedDirection> {
        match side {
            Side::Client => Some(&mut self.client),
            Side::Server => self.server.as_mut(),
        }
    }

    pub(crate) fn flow(&self, side: Side) -> ScopedFlowKey {
        self.get(side)
            .map_or_else(|| self.client.flow.clone(), |dir| dir.flow.clone())
    }

    pub(crate) fn primary_flow(&self) -> ScopedFlowKey {
        self.client.flow.clone()
    }

    pub(crate) fn known_flows(&self) -> Vec<ScopedFlowKey> {
        self.iter().map(|dir| dir.flow.clone()).collect()
    }

    pub(crate) fn has_flow(&self, flow: &ScopedFlowKey) -> bool {
        self.side_of(flow).is_some()
    }

    pub(crate) fn side_of(&self, flow: &ScopedFlowKey) -> Option<Side> {
        if self.client.flow == *flow {
            Some(Side::Client)
        } else if self.server.as_ref().is_some_and(|dir| dir.flow == *flow) {
            Some(Side::Server)
        } else {
            None
        }
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &ElectedDirection> {
        std::iter::once(&self.client).chain(self.server.iter())
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut ElectedDirection> {
        std::iter::once(&mut self.client).chain(self.server.iter_mut())
    }

    pub(crate) fn buffered_len(&self) -> usize {
        self.iter().map(|dir| dir.buffer.len()).sum()
    }

    pub(crate) fn ensure_server(
        &mut self,
        flow: ScopedFlowKey,
        phase: DirectionPhase,
        closed: bool,
        client_settings: &DirectionSettings,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        if self.server.is_some() || self.client.flow == flow {
            return Ok(());
        }
        let decoder = if closed {
            None
        } else {
            let mut decoder = hpack::Decoder::new(context.limits.hpack())?;
            decoder.permit_table_size(client_settings.advertised.header_table_size);
            for pending in &client_settings.pending {
                decoder.permit_table_size(pending.final_values.header_table_size);
            }
            Some(decoder)
        };
        context.charge(&mut self.overhead, budget::DIR_OVERHEAD)?;
        let mut dir = ElectedDirection::new(flow, phase, decoder);
        dir.closed = closed;
        self.server = Some(dir);
        Ok(())
    }

    pub(crate) fn release_live(&mut self, context: &mut Context<'_>) -> Result<(), Error> {
        for dir in self.iter_mut() {
            dir.release_all(context)?;
        }
        Ok(())
    }
}
