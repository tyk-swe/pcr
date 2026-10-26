// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Collector-wide resource counters and the per-call context that enforces them.

use super::model::{Connection, Event, Frame, Issue, Message, Startup, Status, Summary};
use super::{Error, Limits};
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
// Two historical directional debts, stream key, and map-node overhead.
pub(crate) const CLOSED_CREDIT_OVERHEAD: usize = 160;
pub(crate) const PRELUDE_HEADER_OVERHEAD: usize =
    crate::protocol::application::http::MAX_HEADERS * HEADER_OVERHEAD * 4;
pub(crate) const PRELUDE_BODY_RESERVE: usize = 4
    * (crate::protocol::application::http::MAX_HEADER_BYTES
        + crate::protocol::application::http::MAX_START_LINE)
    + crate::protocol::application::http::MAX_HEADERS * HEADER_OVERHEAD * 2;

#[derive(Default)]
pub(crate) struct Budget {
    live: usize,
    retained: usize,
    spans: usize,
    frames: u64,
    streams: u64,
    messages: u64,
    summary: Summary,
}

impl Budget {
    pub(crate) fn into_summary(self) -> Summary {
        self.summary
    }

    #[cfg(test)]
    pub(crate) fn outstanding(&self) -> (usize, usize) {
        (self.live, self.spans)
    }
}

pub(crate) struct Context<'a> {
    pub limits: &'a Limits,
    pub app: &'a application::Limits,
    pub deadline: Option<&'a Deadline>,
    pub budget: &'a mut Budget,
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
        let next = self
            .budget
            .live
            .checked_add(bytes)
            .ok_or(Error::Application(application::Error::Limit {
                field: "max_buffer_bytes",
                limit: self.app.max_buffer_bytes,
            }))?;
        self.app.check_buffer(next)?;
        self.budget.live = next;
        Ok(())
    }

    pub(crate) fn release_live(&mut self, bytes: usize) -> Result<(), Error> {
        self.budget.live = self
            .budget
            .live
            .checked_sub(bytes)
            .ok_or(Error::Invariant("live accounting underflow"))?;
        Ok(())
    }

    pub(crate) fn charge_retained(&mut self, bytes: usize) -> Result<(), Error> {
        let next = self
            .budget
            .retained
            .checked_add(application::Limits::decoded_charge(bytes))
            .ok_or(Error::Application(application::Error::Limit {
                field: "max_retained_bytes",
                limit: self.app.max_retained_bytes,
            }))?;
        self.app.check_retained(next)?;
        self.budget.retained = next;
        Ok(())
    }

    pub(crate) fn charge_sources(&mut self, set: &SourceSet) -> Result<(), Error> {
        let frames = set.frames().len();
        let previous = self.budget.spans;
        self.charge_spans(frames)?;
        if let Err(error) = self.charge_live(SET_OVERHEAD + frames * SPAN_OVERHEAD) {
            self.budget.spans = previous;
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn charge_spans(&mut self, frames: usize) -> Result<(), Error> {
        let next = self
            .budget
            .spans
            .checked_add(frames)
            .ok_or(Error::Application(application::Error::Limit {
                field: "max_source_spans",
                limit: self.app.max_source_spans,
            }))?;
        self.app.check_source_spans(next)?;
        self.budget.spans = next;
        Ok(())
    }

    pub(crate) fn release_spans(&mut self, frames: usize) -> Result<(), Error> {
        self.budget.spans = self
            .budget
            .spans
            .checked_sub(frames)
            .ok_or(Error::Invariant("span underflow"))?;
        Ok(())
    }

    pub(crate) fn release_sources(&mut self, set: &SourceSet) -> Result<(), Error> {
        let frames = set.frames().len();
        self.release_spans(frames)?;
        self.release_live(SET_OVERHEAD + frames * SPAN_OVERHEAD)
    }

    pub(crate) fn check_frames(&mut self) -> Result<(), Error> {
        if self.budget.frames >= self.limits.max_frames {
            return Err(application::Error::Limit {
                field: "max_frames",
                limit: self.limits.max_frames as usize,
            }
            .into());
        }
        self.budget.frames += 1;
        self.budget.summary.frames += 1;
        Ok(())
    }

    pub(crate) fn check_streams(&mut self) -> Result<(), Error> {
        if self.budget.streams >= self.limits.max_streams as u64 {
            return Err(application::Error::Limit {
                field: "max_streams",
                limit: self.limits.max_streams,
            }
            .into());
        }
        self.budget.streams += 1;
        self.budget.summary.streams += 1;
        Ok(())
    }

    pub(crate) fn check_messages(&mut self) -> Result<u64, Error> {
        self.app.check_messages(self.budget.messages as usize)?;
        self.budget.messages += 1;
        Ok(self.budget.messages)
    }

    pub(crate) fn message(&mut self, message: Message) {
        let summary = &mut self.budget.summary;
        summary.messages += 1;
        match message.status {
            Status::Complete => summary.complete_messages += 1,
            Status::Malformed => summary.malformed_messages += 1,
            Status::Limit => summary.limited_messages += 1,
            _ => summary.incomplete_messages += 1,
        }
        self.out.push(Event::Message(Box::new(message)));
    }

    pub(crate) fn frame(&mut self, frame: Frame) {
        self.out.push(Event::Frame(Box::new(frame)));
    }

    pub(crate) fn issue(&mut self, issue: Issue) {
        self.budget.summary.issues += 1;
        self.out.push(Event::Issue(issue));
    }

    pub(crate) fn connection(&mut self, connection: Connection) {
        let summary = &mut self.budget.summary;
        summary.connections += 1;
        match connection.startup {
            Startup::PriorKnowledge => summary.prior_knowledge_connections += 1,
            Startup::H2c => summary.upgraded_connections += 1,
            Startup::Unknown => summary.unsupported_connections += 1,
        }
        self.out.push(Event::Connection(Box::new(connection)));
    }
}
