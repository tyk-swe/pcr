// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Per-direction byte buffers and the election of client and server flows.

use super::Context;
use crate::analysis::http2::Error;
use crate::analysis::http2::budget::Charge;
use crate::analysis::http2::buffer::SourceBuffer;
use crate::analysis::http2::side::Side;
use crate::analysis::provenance::SourceSet;
use crate::analysis::reassembly::tcp::ScopedFlowKey;
use crate::protocol::application::http2::hpack;
use std::collections::HashMap;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectionPhase {
    Sniff,
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

pub(crate) struct DirectionState {
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
    pub received: bool,
    pub garbage: bool,
    pub charge: Charge,
}
impl DirectionState {
    pub(crate) fn new(flow: ScopedFlowKey) -> Self {
        Self {
            flow,
            phase: DirectionPhase::Sniff,
            buffer: SourceBuffer::new(),
            decoder: None,
            decoder_charge: Charge::default(),
            block_sources: HashMap::new(),
            chain: None,
            closed: false,
            fully_consumed_fin: false,
            saw_frame: false,
            received: false,
            garbage: false,
            charge: Charge::default(),
        }
    }

    pub(crate) fn release_consumed(
        &mut self,
        bytes: usize,
        dropped: Vec<SourceSet>,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        context.release(&mut self.charge, bytes)?;
        dropped
            .iter()
            .try_for_each(|set| context.untrack(&mut self.charge, set))
    }

    pub(crate) fn release_all(&mut self, context: &mut Context<'_>) -> Result<(), Error> {
        context.release_all(&mut self.charge)?;
        context.release_all(&mut self.decoder_charge)?;
        self.chain
            .as_mut()
            .map_or(Ok(()), |chain| context.release_all(&mut chain.charge))
    }
}

pub(crate) enum Directions {
    Candidates(Vec<DirectionState>),
    Elected(Box<Elected>),
}

pub(crate) struct Elected {
    pub client: DirectionState,
    pub server: Option<DirectionState>,
}

impl Directions {
    pub(crate) fn get(&self, side: Side) -> Option<&DirectionState> {
        match (self, side) {
            (Self::Elected(elected), Side::Client) => Some(&elected.client),
            (Self::Elected(elected), Side::Server) => elected.server.as_ref(),
            (Self::Candidates(_), _) => None,
        }
    }

    pub(crate) fn get_mut(&mut self, side: Side) -> Option<&mut DirectionState> {
        match (self, side) {
            (Self::Elected(elected), Side::Client) => Some(&mut elected.client),
            (Self::Elected(elected), Side::Server) => elected.server.as_mut(),
            (Self::Candidates(_), _) => None,
        }
    }

    pub(crate) fn is_elected(&self) -> bool {
        matches!(self, Self::Elected(_))
    }

    pub(crate) fn candidates(&self) -> &[DirectionState] {
        match self {
            Self::Candidates(candidates) => candidates,
            Self::Elected(_) => &[],
        }
    }

    pub(crate) fn candidates_mut(&mut self) -> &mut [DirectionState] {
        match self {
            Self::Candidates(candidates) => candidates,
            Self::Elected(_) => &mut [],
        }
    }

    pub(crate) fn elected(&self) -> impl Iterator<Item = &DirectionState> {
        Side::BOTH.into_iter().filter_map(|side| self.get(side))
    }

    pub(crate) fn elected_mut(&mut self) -> impl Iterator<Item = &mut DirectionState> {
        let (client, server) = match self {
            Self::Elected(elected) => (Some(&mut elected.client), elected.server.as_mut()),
            Self::Candidates(_) => (None, None),
        };
        client.into_iter().chain(server)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &DirectionState> {
        self.candidates().iter().chain(self.elected())
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut DirectionState> {
        let (candidates, client, server) = match self {
            Self::Candidates(candidates) => (candidates.as_mut_slice(), None, None),
            Self::Elected(elected) => (
                &mut [][..],
                Some(&mut elected.client),
                elected.server.as_mut(),
            ),
        };
        candidates.iter_mut().chain(client).chain(server)
    }

    pub(crate) fn find(&self, flow: &ScopedFlowKey) -> Option<&DirectionState> {
        self.iter().find(|dir| dir.flow == *flow)
    }

    pub(crate) fn find_mut(&mut self, flow: &ScopedFlowKey) -> Option<&mut DirectionState> {
        self.iter_mut().find(|dir| dir.flow == *flow)
    }

    pub(crate) fn side_of(&self, flow: &ScopedFlowKey) -> Option<Side> {
        Side::BOTH
            .into_iter()
            .find(|side| self.get(*side).is_some_and(|dir| dir.flow == *flow))
    }

    pub(crate) fn add_candidate(&mut self, dir: DirectionState) -> Result<(), Error> {
        match self {
            Self::Candidates(candidates) => {
                candidates.push(dir);
                Ok(())
            }
            Self::Elected(_) => Err(Error::Invariant("candidate after election")),
        }
    }

    pub(crate) fn place(&mut self, side: Side, dir: DirectionState) -> Result<(), Error> {
        match (self, side) {
            (Self::Elected(elected), Side::Client) => elected.client = dir,
            (Self::Elected(elected), Side::Server) => elected.server = Some(dir),
            (Self::Candidates(_), _) => return Err(Error::Invariant("placement before election")),
        }
        Ok(())
    }
}
