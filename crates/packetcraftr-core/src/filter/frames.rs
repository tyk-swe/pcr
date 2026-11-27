// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::{cell::OnceCell, sync::Arc};

use crate::decode::{self, DecodedPacket, Dissector};
use crate::frame::Frame;
use crate::registry::Registry;

use super::eval::Evaluation;
use super::{Context, Error, Filter, Projection, Requirements};
use crate::field::Value;

impl<'a> Context<'a> {
    /// For callers that assign no derived packets or conversation indexes.
    pub fn frame(decoded: &'a DecodedPacket, number: u64) -> Self {
        Self {
            decoded,
            derived: &[],
            number,
            tcp_stream: None,
            udp_stream: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct FrameDecoder {
    dissector: Dissector,
    filter: Option<Filter>,
    max_frame_bytes: usize,
}

impl FrameDecoder {
    pub fn new(
        registry: Arc<Registry>,
        filter: Option<Filter>,
        max_frame_bytes: usize,
    ) -> Result<Self, Error> {
        if filter
            .as_ref()
            .is_some_and(|filter| filter.requirements().stream_index)
        {
            return Err(Error::StreamIndexUnavailable);
        }
        Ok(Self {
            dissector: Dissector::new(registry),
            filter,
            max_frame_bytes,
        })
    }

    pub fn decode(&self, frame: &Frame) -> Result<DecodedPacket, decode::Error> {
        self.dissector.decode(
            frame.clone(),
            decode::Options {
                limits: crate::packet::Limits {
                    max_packet_size: self.max_frame_bytes,
                    ..crate::packet::Limits::default()
                },
            },
        )
    }

    pub fn evaluate<'a>(&'a self, number: u64, frame: &'a Frame) -> FrameEvaluation<'a> {
        FrameEvaluation {
            decoder: self,
            frame,
            number,
            decoded: OnceCell::new(),
        }
    }

    pub fn keep(&self, number: u64, frame: &Frame) -> Result<bool, Error> {
        self.evaluate(number, frame).selected()
    }

    pub fn decode_selected(
        &self,
        number: u64,
        frame: &Frame,
    ) -> Result<Option<DecodedPacket>, Error> {
        let evaluation = self.evaluate(number, frame);
        if !evaluation.selected()? {
            return Ok(None);
        }
        match evaluation.decoded.into_inner() {
            Some(decoded) => Ok(Some(decoded)),
            None => self.decode(frame).map(Some).map_err(Error::from),
        }
    }
}

/// Evaluates filters and projections against one original frame and shares dissection when needed.
pub struct FrameEvaluation<'a> {
    decoder: &'a FrameDecoder,
    frame: &'a Frame,
    number: u64,
    decoded: OnceCell<DecodedPacket>,
}

impl FrameEvaluation<'_> {
    pub fn selected(&self) -> Result<bool, Error> {
        match &self.decoder.filter {
            Some(filter) => self.matches(filter),
            None => self.check_size().map(|()| true),
        }
    }

    pub fn matches(&self, filter: &Filter) -> Result<bool, Error> {
        filter.evaluate(&self.context(filter.requirements())?)
    }

    pub fn values(
        &self,
        projection: &Projection,
        max_bytes: usize,
    ) -> Result<Vec<Option<Value>>, Error> {
        let mut remaining = max_bytes;
        projection.evaluate(&self.context(projection.requirements())?, &mut remaining)
    }

    fn context(&self, requirements: Requirements) -> Result<Evaluation<'_>, Error> {
        if requirements.stream_index {
            return Err(Error::StreamIndexUnavailable);
        }
        self.check_size()?;
        if !requirements.layers {
            return Ok(Evaluation::frame(self.frame, self.number));
        }
        let decoded = match self.decoded.get() {
            Some(decoded) => decoded,
            None => {
                let decoded = self.decoder.decode(self.frame)?;
                self.decoded.get_or_init(|| decoded)
            }
        };
        Ok(Evaluation::from(&Context::frame(decoded, self.number)))
    }

    fn check_size(&self) -> Result<(), Error> {
        let actual = self.frame.bytes().len();
        let limit = self.decoder.max_frame_bytes;
        if actual > limit {
            return Err(decode::Error::PacketSizeLimit { actual, limit }.into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct FrameSelector(FrameDecoder);

impl FrameSelector {
    pub fn new(
        registry: Arc<Registry>,
        filter: Filter,
        max_frame_bytes: usize,
    ) -> Result<Self, Error> {
        FrameDecoder::new(registry, Some(filter), max_frame_bytes).map(Self)
    }

    /// Whether the one-based frame `number` is kept.
    pub fn keep(&self, number: u64, frame: &Frame) -> Result<bool, Error> {
        self.0.keep(number, frame)
    }
}
