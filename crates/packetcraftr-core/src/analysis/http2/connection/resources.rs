// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::model::{Event, Status, Summary};
use super::super::{Error, Limits};
use crate::analysis::application;
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

pub(crate) struct Cx<'a> {
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

impl Cx<'_> {
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
    pub(crate) fn release_live(&mut self, bytes: usize) {
        *self.buffered = self
            .buffered
            .checked_sub(bytes)
            .expect("live accounting underflow");
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
    pub(crate) fn release_sources(&mut self, set: &SourceSet) {
        let frames = set.frames().len();
        *self.spans = self.spans.checked_sub(frames).expect("span underflow");
        self.release_live(SET_OVERHEAD + frames * SPAN_OVERHEAD);
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
