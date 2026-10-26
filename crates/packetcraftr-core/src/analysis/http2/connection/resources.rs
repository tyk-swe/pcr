// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Resource limits, charging, source tracking, and decoder accounting.

use super::super::model::{Event, Status, Summary};
use super::super::{Error, Limits};
use super::{ConnectionState, DirectionState};
use crate::analysis::application;
use crate::analysis::http2::side::Side;
use crate::analysis::provenance::SourceSet;
use crate::budget::Deadline;

pub(crate) const EVENT_OVERHEAD: usize = 256;
pub(crate) const ISSUE_OVERHEAD: usize = 192;
pub(crate) const MESSAGE_OVERHEAD: usize = 512;
pub(crate) const HEADER_OVERHEAD: usize = 48;
pub(crate) const STREAM_OVERHEAD: usize = 512;
pub(crate) const CLOSED_STREAM_OVERHEAD: usize = 96;
pub(crate) const DIR_OVERHEAD: usize = 1024;
pub(crate) const SET_OVERHEAD: usize = 64;
pub(crate) const SPAN_OVERHEAD: usize = 24;
pub(crate) const ORIGIN_ENTRY_OVERHEAD: usize = 96;
pub(crate) const PENDING_OVERHEAD: usize = 160;
pub(crate) const OFFER_OVERHEAD: usize = 384;
pub(crate) const PRELUDE_HEADER_OVERHEAD: usize =
    crate::protocol::application::http::MAX_HEADERS * HEADER_OVERHEAD * 4;
pub(crate) const PRELUDE_BODY_RESERVE: usize = 4
    * (crate::protocol::application::http::MAX_HEADER_BYTES
        + crate::protocol::application::http::MAX_START_LINE)
    + crate::protocol::application::http::MAX_HEADERS * HEADER_OVERHEAD * 2;

pub(crate) struct Context<'a> {
    pub limits: &'a Limits,
    pub app: &'a application::Limits,
    pub deadline: Option<&'a Deadline>,
    pub buffered: &'a mut usize,
    pub retained: &'a mut usize,
    pub spans: &'a mut usize,
    pub frames: &'a mut u64,
    pub streams: &'a mut u64,
    pub messages: &'a mut u64,
    pub summary: &'a mut Summary,
    pub out: &'a mut Vec<Event>,
}

impl Context<'_> {
    pub(crate) fn check_deadline(&self) -> Result<(), Error> {
        if let Some(deadline) = self.deadline {
            deadline.enforce()?;
        }
        Ok(())
    }
    pub(crate) fn charge_live(&mut self, bytes: usize) -> Result<(), Error> {
        let next = self.buffered.checked_add(bytes).ok_or(Error::Application(
            application::Error::Limit {
                field: "max_buffer_bytes",
                limit: self.app.max_buffer_bytes,
            },
        ))?;
        self.app.check_buffer(next)?;
        *self.buffered = next;
        Ok(())
    }
    pub(crate) fn release_live(&mut self, bytes: usize) -> Result<(), Error> {
        *self.buffered = self
            .buffered
            .checked_sub(bytes)
            .ok_or(Error::Invariant("live accounting underflow"))?;
        Ok(())
    }
    pub(crate) fn charge_retained(&mut self, bytes: usize) -> Result<(), Error> {
        let next = self
            .retained
            .checked_add(application::Limits::decoded_charge(bytes))
            .ok_or(Error::Application(application::Error::Limit {
                field: "max_retained_bytes",
                limit: self.app.max_retained_bytes,
            }))?;
        self.app.check_retained(next)?;
        *self.retained = next;
        Ok(())
    }
    pub(crate) fn charge_sources(&mut self, set: &SourceSet) -> Result<(), Error> {
        let frames = set.frames().len();
        let previous = *self.spans;
        self.charge_spans(frames)?;
        if let Err(error) = self.charge_live(SET_OVERHEAD + frames * SPAN_OVERHEAD) {
            *self.spans = previous;
            return Err(error);
        }
        Ok(())
    }
    pub(crate) fn charge_spans(&mut self, frames: usize) -> Result<(), Error> {
        let next = self.spans.checked_add(frames).ok_or(Error::Application(
            application::Error::Limit {
                field: "max_source_spans",
                limit: self.app.max_source_spans,
            },
        ))?;
        self.app.check_source_spans(next)?;
        *self.spans = next;
        Ok(())
    }
    pub(crate) fn release_sources(&mut self, set: &SourceSet) -> Result<(), Error> {
        let frames = set.frames().len();
        *self.spans = self
            .spans
            .checked_sub(frames)
            .ok_or(Error::Invariant("span underflow"))?;
        self.release_live(SET_OVERHEAD + frames * SPAN_OVERHEAD)?;
        Ok(())
    }
    pub(crate) fn check_frames(&mut self) -> Result<(), Error> {
        if *self.frames >= self.limits.max_frames {
            return Err(application::Error::Limit {
                field: "max_frames",
                limit: self.limits.max_frames as usize,
            }
            .into());
        }
        *self.frames += 1;
        self.summary.frames += 1;
        Ok(())
    }
    pub(crate) fn check_streams(&mut self) -> Result<(), Error> {
        if *self.streams >= self.limits.max_streams as u64 {
            return Err(application::Error::Limit {
                field: "max_streams",
                limit: self.limits.max_streams,
            }
            .into());
        }
        *self.streams += 1;
        self.summary.streams += 1;
        Ok(())
    }
    pub(crate) fn check_messages(&mut self) -> Result<u64, Error> {
        self.app.check_messages(*self.messages as usize)?;
        *self.messages += 1;
        Ok(*self.messages)
    }
    pub(crate) fn message(&mut self, message: super::super::model::Message) {
        self.summary.messages += 1;
        match message.status {
            Status::Complete => self.summary.complete_messages += 1,
            Status::Malformed => self.summary.malformed_messages += 1,
            Status::Limit => self.summary.limited_messages += 1,
            _ => self.summary.incomplete_messages += 1,
        }
        self.out.push(Event::Message(Box::new(message)));
    }
    pub(crate) fn frame(&mut self, frame: super::super::model::Frame) {
        self.out.push(Event::Frame(Box::new(frame)));
    }
    pub(crate) fn issue(&mut self, issue: super::super::model::Issue) {
        self.summary.issues += 1;
        self.out.push(Event::Issue(issue));
    }
    pub(crate) fn connection(&mut self, connection: super::super::model::Connection) {
        self.out.push(Event::Connection(Box::new(connection)));
    }
}

// Two historical directional debts, stream key, and map-node overhead.
pub(crate) const CLOSED_CREDIT_OVERHEAD: usize = 160;

impl ConnectionState {
    pub(crate) fn charge_conn(
        &mut self,
        context: &mut Context<'_>,
        bytes: usize,
    ) -> Result<(), Error> {
        context.charge_live(bytes)?;
        self.live = self
            .live
            .checked_add(bytes)
            .ok_or(Error::Invariant("conn charge"))?;
        Ok(())
    }

    pub(crate) fn release_conn(
        &mut self,
        context: &mut Context<'_>,
        bytes: usize,
    ) -> Result<(), Error> {
        context.release_live(bytes)?;
        self.live = self
            .live
            .checked_sub(bytes)
            .ok_or(Error::Invariant("conn release"))?;
        Ok(())
    }

    pub(crate) fn charge_dir(
        dir: &mut DirectionState,
        context: &mut Context<'_>,
        bytes: usize,
    ) -> Result<(), Error> {
        context.charge_live(bytes)?;
        dir.charged = dir
            .charged
            .checked_add(bytes)
            .ok_or(Error::Invariant("dir charge"))?;
        Ok(())
    }

    pub(crate) fn release_dir(
        dir: &mut DirectionState,
        context: &mut Context<'_>,
        bytes: usize,
    ) -> Result<(), Error> {
        context.release_live(bytes)?;
        dir.charged = dir
            .charged
            .checked_sub(bytes)
            .ok_or(Error::Invariant("dir release"))?;
        Ok(())
    }

    pub(crate) fn track_sources(
        dir: &mut DirectionState,
        context: &mut Context<'_>,
        set: &SourceSet,
    ) -> Result<(), Error> {
        context.charge_sources(set)?;
        dir.charged_spans += set.frames().len();
        dir.charged += SET_OVERHEAD + set.frames().len() * SPAN_OVERHEAD;
        Ok(())
    }

    pub(crate) fn release_dropped(
        dir: &mut DirectionState,
        dropped: Vec<SourceSet>,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        for set in dropped {
            let frames = set.frames().len();
            context.release_sources(&set)?;
            dir.charged_spans -= frames;
            dir.charged -= SET_OVERHEAD + frames * SPAN_OVERHEAD;
        }
        Ok(())
    }

    pub(crate) fn decoder_sync(
        &mut self,
        side: Side,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let dir = self.dirs[side]
            .as_mut()
            .ok_or(Error::Invariant("direction not found"))?;
        if let Some(decoder) = dir.decoder.as_ref() {
            let now = decoder.buffered_bytes();
            if now > dir.decoder_charge {
                Self::charge_dir(dir, context, now - dir.decoder_charge)?;
            } else if now < dir.decoder_charge {
                Self::release_dir(dir, context, dir.decoder_charge - now)?;
            }
            dir.decoder_charge = now;
        }
        Ok(())
    }
}
