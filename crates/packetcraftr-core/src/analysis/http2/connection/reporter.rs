// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Connection metadata, fault construction, event emission, and typed step aborts.

use super::Context;
use crate::analysis::ScopedFlowKey;
use crate::analysis::http2::budget::{self, Charge};
use crate::analysis::http2::model::{
    Certainty, Connection, Frame, FrameBody, Issue, IssueScope, PeerSettings, Startup, Status,
};
use crate::analysis::http2::{Error, IssueCode};
use crate::analysis::provenance::SourceSet;
use crate::protocol::application::http;
use crate::protocol::application::http2 as wire;
use bytes::Bytes;
use std::borrow::Cow;

pub(crate) enum StepAbort {
    ConnectionFailed(Status),
    Fatal(Error),
}

pub(crate) type StepResult<T = ()> = Result<T, StepAbort>;

impl From<Error> for StepAbort {
    fn from(error: Error) -> Self {
        Self::Fatal(error)
    }
}

impl From<crate::analysis::application::Error> for StepAbort {
    fn from(error: crate::analysis::application::Error) -> Self {
        Self::Fatal(error.into())
    }
}

impl From<crate::analysis::provenance::Error> for StepAbort {
    fn from(error: crate::analysis::provenance::Error) -> Self {
        Self::Fatal(error.into())
    }
}

impl From<wire::Error> for StepAbort {
    fn from(error: wire::Error) -> Self {
        Self::Fatal(error.into())
    }
}

impl From<http::Error> for StepAbort {
    fn from(error: http::Error) -> Self {
        Self::Fatal(error.into())
    }
}

#[derive(Clone, Default)]
pub(crate) struct Evidence {
    pub wire: Bytes,
    pub sources: Option<SourceSet>,
}

impl Evidence {
    pub(crate) fn new(wire: Bytes, sources: Option<SourceSet>) -> Self {
        Self { wire, sources }
    }
}

pub(crate) struct Fault {
    pub(crate) flow: ScopedFlowKey,
    pub(crate) http2_stream_id: Option<u32>,
    pub(crate) scope: IssueScope,
    pub(crate) certainty: Certainty,
    pub(crate) status: Status,
    pub(crate) code: IssueCode,
    pub(crate) detail: Cow<'static, str>,
    pub(crate) wire: Bytes,
    pub(crate) sources: Option<SourceSet>,
}

impl Fault {
    pub(crate) fn new(
        flow: ScopedFlowKey,
        scope: IssueScope,
        status: Status,
        code: IssueCode,
        detail: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            flow,
            http2_stream_id: None,
            scope,
            certainty: Certainty::Confirmed,
            status,
            code,
            detail: detail.into(),
            wire: Bytes::new(),
            sources: None,
        }
    }

    pub(crate) fn connection(
        flow: ScopedFlowKey,
        status: Status,
        code: IssueCode,
        detail: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self::new(flow, IssueScope::Connection, status, code, detail)
    }

    pub(crate) fn stream(
        flow: ScopedFlowKey,
        stream_id: u32,
        status: Status,
        code: IssueCode,
        detail: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self::new(flow, IssueScope::Stream, status, code, detail).with_stream(Some(stream_id))
    }

    pub(crate) fn compression(
        flow: ScopedFlowKey,
        stream_id: u32,
        status: Status,
        code: IssueCode,
        detail: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self::new(flow, IssueScope::Compression, status, code, detail).with_stream(Some(stream_id))
    }

    pub(crate) fn capture(
        flow: ScopedFlowKey,
        status: Status,
        code: IssueCode,
        detail: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self::new(flow, IssueScope::Capture, status, code, detail)
    }

    pub(crate) fn with_stream(mut self, http2_stream_id: Option<u32>) -> Self {
        self.http2_stream_id = http2_stream_id;
        self
    }

    pub(crate) fn with_certainty(mut self, certainty: Certainty) -> Self {
        self.certainty = certainty;
        self
    }

    pub(crate) fn with_evidence(mut self, wire: Bytes, sources: Option<SourceSet>) -> Self {
        self.wire = wire;
        self.sources = sources;
        self
    }

    pub(crate) fn with_evidence_ref(self, evidence: &Evidence) -> Self {
        self.with_evidence(evidence.wire.clone(), evidence.sources.clone())
    }
}

pub(crate) struct ConnectionSnapshot {
    pub flow: ScopedFlowKey,
    pub client_settings: PeerSettings,
    pub server_settings: PeerSettings,
    pub client_window: i64,
    pub server_window: i64,
    pub streams: u64,
    pub pending_settings: u64,
    pub pending_pings: u64,
    pub upgrade_response: Option<http::Head>,
    pub upgrade_sources: Option<SourceSet>,
    pub upgrade_charge: Charge,
}

pub(crate) struct Reporter {
    pub stream: u64,
    pub generation: u64,
    pub first_flow: ScopedFlowKey,
    pub startup: Startup,
    pub status: Status,
    pub frames: u64,
    pub issues: u64,
    pub number: u64,
    emitted: bool,
}

impl Reporter {
    pub(crate) fn new(stream: u64, generation: u64, first_flow: ScopedFlowKey) -> Self {
        Self {
            stream,
            generation,
            first_flow,
            startup: Startup::Unknown,
            status: Status::Complete,
            frames: 0,
            issues: 0,
            number: 0,
            emitted: false,
        }
    }

    pub(crate) fn worst(&mut self, status: Status) {
        if status_severity(status) > status_severity(self.status) {
            self.status = status;
        }
    }

    pub(crate) fn issue(&mut self, context: &mut Context<'_>, fault: Fault) -> Result<(), Error> {
        let charge =
            fault.wire.len() + fault.detail.len() + budget::ISSUE_OVERHEAD + budget::EVENT_OVERHEAD;
        context.charge_retained(charge)?;
        if let Some(sources) = &fault.sources {
            context.charge_retained(budget::set_cost(sources))?;
        }
        self.issues += 1;
        let number = fault
            .sources
            .as_ref()
            .and_then(|set| set.frames().last().map(|frame| frame.number))
            .unwrap_or(self.number);
        context.issue(Issue {
            number,
            stream: self.stream,
            generation: self.generation,
            http2_stream_id: fault.http2_stream_id,
            flow: fault.flow,
            code: fault.code,
            scope: fault.scope,
            certainty: fault.certainty,
            status: fault.status,
            detail: fault.detail.into_owned(),
            wire: fault.wire,
            sources: fault.sources,
        });
        if fault.certainty == Certainty::Confirmed || fault.scope == IssueScope::Capture {
            self.worst(fault.status);
        } else {
            self.worst(Status::Incomplete);
        }
        Ok(())
    }

    pub(crate) fn reject<T>(&mut self, context: &mut Context<'_>, fault: Fault) -> StepResult<T> {
        let status = fault.status;
        self.issue(context, fault)?;
        Err(StepAbort::ConnectionFailed(status))
    }

    pub(crate) fn emit_frame(
        &mut self,
        flow: ScopedFlowKey,
        frame: &wire::Frame,
        wire_bytes: &Bytes,
        sources: Option<SourceSet>,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let body = match &frame.payload {
            wire::Payload::Data { data, padding } => FrameBody::Data {
                data_bytes: data.len() as u64,
                padding_bytes: padding.len(),
            },
            wire::Payload::Control(control) => FrameBody::Control {
                control: control.clone(),
                payload_wire: wire_bytes.slice(wire::HEADER_LEN..),
            },
        };
        let mut header_wire = [0u8; wire::HEADER_LEN];
        header_wire.copy_from_slice(&wire_bytes[..wire::HEADER_LEN]);
        let retained = match &body {
            FrameBody::Data { .. } => wire::HEADER_LEN,
            FrameBody::Control {
                control: wire::Control::Settings(values),
                ..
            } => wire_bytes.len() + values.capacity() * size_of::<wire::Setting>(),
            FrameBody::Control { .. } => wire_bytes.len(),
        };
        let sources = sources.ok_or(Error::Invariant("frame sources missing"))?;
        context.charge_retained(retained + budget::EVENT_OVERHEAD + budget::set_cost(&sources))?;
        context.frame(Frame {
            index: self.frames,
            stream: self.stream,
            generation: self.generation,
            flow,
            header: frame.header.clone(),
            header_wire,
            body,
            sources,
        });
        Ok(())
    }

    pub(crate) fn emit_connection(
        &mut self,
        mut snapshot: ConnectionSnapshot,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        if self.emitted {
            return context.release_all(&mut snapshot.upgrade_charge);
        }
        self.emitted = true;
        let charge = budget::EVENT_OVERHEAD
            + budget::MESSAGE_OVERHEAD
            + snapshot
                .upgrade_response
                .as_ref()
                .map_or(0, |head| head.wire().len())
            + snapshot
                .upgrade_sources
                .as_ref()
                .map_or(0, budget::set_cost);
        context.charge_retained(charge)?;
        context.connection(Connection {
            stream: self.stream,
            generation: self.generation,
            flow: snapshot.flow,
            startup: self.startup,
            status: self.status,
            client_settings: snapshot.client_settings,
            server_settings: snapshot.server_settings,
            client_window: snapshot.client_window,
            server_window: snapshot.server_window,
            streams: snapshot.streams,
            frames: self.frames,
            issues: self.issues,
            pending_settings: snapshot.pending_settings,
            pending_pings: snapshot.pending_pings,
            upgrade_response: snapshot.upgrade_response,
            upgrade_sources: snapshot.upgrade_sources,
        });
        context.release_all(&mut snapshot.upgrade_charge)
    }
}

const fn status_severity(status: Status) -> u8 {
    match status {
        Status::Complete => 0,
        Status::Incomplete | Status::Unprocessed => 1,
        Status::Unsupported => 2,
        Status::Gap | Status::Conflict | Status::Evicted | Status::Reset => 3,
        Status::Limit | Status::Malformed => 4,
    }
}
