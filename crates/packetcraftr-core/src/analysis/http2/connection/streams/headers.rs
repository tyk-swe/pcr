// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Request, response, and trailer semantics for decoded stream headers.

use super::super::{
    ActiveState, ChainHead, Context, Evidence, Fault, Head, Reporter, StepAbort, StepResult,
};
use crate::analysis::http_headers::{final_status_forbids_content, final_status_forbids_trailers};
use crate::analysis::http2::IssueCode;
use crate::analysis::http2::headers::{FieldRole, Meta, recover, validate};
use crate::analysis::http2::model::{Certainty, Header, Status};
use crate::analysis::http2::side::Side;
use crate::analysis::http2::stream::{
    Decoded, EarlyResponse, HeadKind, HeaderSection, Phase as StreamPhase,
};

const RESPONSE_AFTER_GOAWAY: &str =
    "the server responded on a client stream above its own GOAWAY last_stream_id";

#[derive(Clone, Copy)]
enum HeaderAction {
    StartMessage(HeadKind),
    Trailers,
}

impl HeaderAction {
    const fn field_role(self) -> FieldRole {
        match self {
            Self::StartMessage(kind) => kind.field_role(),
            Self::Trailers => FieldRole::Trailer,
        }
    }
}

#[derive(Clone, Copy)]
struct HeaderFlags {
    side: Side,
    stream_id: u32,
    end_stream: bool,
    malformed: bool,
}

impl ActiveState {
    pub(crate) fn headers_block(
        &mut self,
        side: Side,
        stream_id: u32,
        head: ChainHead,
        decoded: Decoded,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        match head {
            ChainHead::Headers {
                end_stream,
                malformed,
            } => {
                let flags = HeaderFlags {
                    side,
                    stream_id,
                    end_stream,
                    malformed,
                };
                self.stream_headers(flags, decoded, reporter, context)?;
                if malformed && self.streams.is_open(stream_id) {
                    self.close_stream(stream_id, Status::Malformed, None, reporter, context)?;
                }
                Ok(())
            }
            ChainHead::PushPromise { promised } => {
                self.push_promise(side, stream_id, promised, decoded, reporter, context)
            }
        }
    }

    fn stream_headers(
        &mut self,
        flags: HeaderFlags,
        decoded: Decoded,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        let evidence = Evidence::new(decoded.block.clone(), decoded.sources.clone());
        if flags.side == Side::Server
            && let Some(early) = self.streams.early_response_for(flags.stream_id)
            && self.early_response_followup(
                flags,
                early,
                &decoded.headers,
                &evidence,
                reporter,
                context,
            )?
        {
            return Ok(());
        }
        if !self.ensure_open_stream_for_headers(
            flags,
            &decoded.headers,
            &evidence,
            reporter,
            context,
        )? {
            return Ok(());
        }
        let Some(action) = self.determine_header_action(
            flags.side,
            flags.stream_id,
            &evidence,
            reporter,
            context,
        )?
        else {
            return Ok(());
        };
        let (meta, mut failure) = self.validate_stream_headers(
            flags,
            action,
            &decoded.headers,
            &evidence,
            reporter,
            context,
        )?;
        match action {
            HeaderAction::StartMessage(kind) => {
                self.start_message(
                    flags.side,
                    flags.stream_id,
                    Head {
                        kind,
                        meta,
                        flawed: failure.is_some(),
                    },
                    decoded,
                    reporter,
                    context,
                )?;
                if let Some(status) = failure
                    && let Some(stream) = self.streams.open_mut(flags.stream_id)
                    && let Some(msg) = stream.msgs[flags.side].as_mut()
                {
                    msg.failure = Some(status);
                }
            }
            HeaderAction::Trailers => {
                self.attach_trailers(flags, decoded, &evidence, &mut failure, reporter, context)?;
            }
        }
        if failure == Some(Status::Malformed) {
            // Preserve the decoded field section before applying its stream error.
            self.close_stream(flags.stream_id, Status::Malformed, None, reporter, context)?;
        } else if flags.end_stream {
            self.end_side(
                flags.side,
                flags.stream_id,
                Status::Complete,
                reporter,
                context,
            )?;
        }
        Ok(())
    }

    /// Ensures `flags.stream_id` is present in `self.streams.open` for normal
    /// header processing. Returns `Ok(false)` when the block was already
    /// disposed of (in-flight reset, closed stream, or capture-delayed opener).
    fn ensure_open_stream_for_headers(
        &mut self,
        flags: HeaderFlags,
        headers: &[Header],
        evidence: &Evidence,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult<bool> {
        if self.streams.is_open(flags.stream_id) {
            return Ok(true);
        }
        if self
            .streams
            .is_peer_reset_in_flight(flags.side, flags.stream_id)
        {
            // The peer's HEADERS may have been in flight when we observed the
            // reset. HPACK has already been decoded to preserve table state.
            return Ok(false);
        }
        if self.streams.is_closed_or_implicit(flags.stream_id) {
            reporter.issue(
                context,
                Fault::stream(
                    self.directions.flow(flags.side),
                    flags.stream_id,
                    Status::Malformed,
                    IssueCode::ClosedStreamHeaders,
                    "HEADERS arrived on a fully closed stream",
                )
                .with_evidence_ref(evidence),
            )?;
            return Ok(false);
        }
        let client_initiated = Side::initiator_of(flags.stream_id) == Side::Client;
        if flags.side == Side::Client && client_initiated {
            self.begin_stream(
                flags.side,
                flags.stream_id,
                Some(evidence),
                reporter,
                context,
            )?;
            return Ok(true);
        }
        self.handle_unopened_stream_headers(
            flags,
            client_initiated,
            headers,
            evidence,
            reporter,
            context,
        )?;
        Ok(false)
    }

    fn handle_unopened_stream_headers(
        &mut self,
        flags: HeaderFlags,
        client_initiated: bool,
        headers: &[Header],
        evidence: &Evidence,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult {
        let (code, detail) = if flags.side == Side::Server && client_initiated {
            (
                IssueCode::ResponseWithoutStream,
                "the server sent HEADERS on a stream the client never opened",
            )
        } else {
            (
                IssueCode::UnpromisedStream,
                "HEADERS opened a stream the endpoint did not initiate",
            )
        };
        let delayed_opener = flags.side == Side::Server
            && client_initiated
            && !self.opener_exhausted(Side::Client)
            && (!self.clean_start || flags.stream_id > self.streams.max_initiated(Side::Client));
        let (status, certainty) = if delayed_opener {
            (Status::Incomplete, Certainty::Indeterminate)
        } else {
            (Status::Malformed, Certainty::Confirmed)
        };
        reporter.issue(
            context,
            Fault::connection(self.directions.flow(flags.side), status, code, detail)
                .with_stream(Some(flags.stream_id))
                .with_certainty(certainty)
                .with_evidence_ref(evidence),
        )?;
        // Keep the bounded, sourced header-block evidence without inventing
        // request correlation. A delayed client opener can still be admitted.
        if !delayed_opener {
            return Err(StepAbort::ConnectionFailed(Status::Malformed));
        }
        self.streams
            .retain_pending_opener(flags.stream_id, code, context)?;
        self.record_early_server_response(flags, headers, evidence, reporter, context)?;
        Ok(())
    }

    fn record_early_server_response(
        &mut self,
        flags: HeaderFlags,
        headers: &[Header],
        evidence: &Evidence,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> Result<(), crate::analysis::http2::Error> {
        let early = self
            .streams
            .ensure_early_response(flags.stream_id, context)?;
        // The server's own ordered bytes place this response after
        // its GOAWAY, which promised the stream was not processed.
        let above_goaway =
            self.control.goaway[Side::Server].is_some_and(|last| flags.stream_id > last);
        let validation = validate(FieldRole::Response, headers)
            .map_err(|detail| (IssueCode::HeaderSemantics, detail))
            .and_then(|meta| {
                if flags.end_stream
                    && meta
                        .status
                        .is_some_and(|status| (100..200).contains(&status))
                {
                    Err((
                        IssueCode::HeaderSemantics,
                        "a 1xx response must not end the stream",
                    ))
                } else if above_goaway {
                    Err((IssueCode::ResponseAfterGoaway, RESPONSE_AFTER_GOAWAY))
                } else {
                    Ok(meta)
                }
            });
        match validation {
            Ok(meta) => {
                early.final_seen = meta
                    .status
                    .is_none_or(|status| !(100..200).contains(&status));
                early.forbids_trailers = meta.status.is_some_and(final_status_forbids_trailers);
                early.bodyless = meta.status.is_some_and(final_status_forbids_content);
                early.ended = flags.end_stream || flags.malformed;
            }
            Err((code, detail)) => {
                // Reject further response activity while retaining the
                // capture-delayed request's admission and evidence.
                early.ended = true;
                reporter.issue(
                    context,
                    Fault::stream(
                        self.directions.flow(flags.side),
                        flags.stream_id,
                        Status::Malformed,
                        code,
                        detail,
                    )
                    .with_evidence_ref(evidence),
                )?;
            }
        }
        Ok(())
    }

    fn determine_header_action(
        &mut self,
        side: Side,
        stream_id: u32,
        evidence: &Evidence,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult<Option<HeaderAction>> {
        let Some(stream) = self.streams.open_get(stream_id) else {
            return Ok(None);
        };
        if stream.phase != StreamPhase::Reserved && stream.ended[side] {
            reporter.issue(
                context,
                Fault::stream(
                    self.directions.flow(side),
                    stream_id,
                    Status::Malformed,
                    IssueCode::HeadersAfterEnd,
                    "HEADERS arrived after the sender already ended the stream",
                )
                .with_evidence_ref(evidence),
            )?;
            self.close_stream(stream_id, Status::Malformed, None, reporter, context)?;
            return Ok(None);
        }
        match stream.phase {
            StreamPhase::Reserved => {
                if side != Side::Server {
                    return reporter.reject(
                        context,
                        Fault::connection(
                            self.directions.flow(side),
                            Status::Malformed,
                            IssueCode::ReservedStreamHeaders,
                            "a client sent HEADERS on a reserved stream",
                        )
                        .with_stream(Some(stream_id))
                        .with_evidence_ref(evidence),
                    );
                }
                self.streams.promote_reserved(stream_id);
                if self.enforce_concurrency(
                    Side::Server,
                    stream_id,
                    Some(evidence),
                    reporter,
                    context,
                )? {
                    return Ok(None);
                }
                Ok(Some(HeaderAction::StartMessage(HeadKind::Response)))
            }
            StreamPhase::Open | StreamPhase::Closed => {
                if stream.msgs[side].is_none() && !stream.ended[side] {
                    let kind = match side {
                        Side::Client => HeadKind::Request,
                        Side::Server => HeadKind::Response,
                    };
                    Ok(Some(HeaderAction::StartMessage(kind)))
                } else {
                    Ok(Some(HeaderAction::Trailers))
                }
            }
        }
    }

    fn validate_stream_headers(
        &self,
        flags: HeaderFlags,
        action: HeaderAction,
        headers: &[Header],
        evidence: &Evidence,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> Result<(Meta, Option<Status>), crate::analysis::http2::Error> {
        let HeaderFlags {
            side,
            stream_id,
            end_stream,
            malformed,
        } = flags;
        let flow = self.directions.flow(side);
        let role = action.field_role();
        let mut failure = malformed.then_some(Status::Malformed);
        let meta = match validate(role, headers) {
            Ok(meta) => meta,
            Err(detail) => {
                reporter.issue(
                    context,
                    Fault::stream(
                        flow.clone(),
                        stream_id,
                        Status::Malformed,
                        IssueCode::HeaderSemantics,
                        detail,
                    )
                    .with_evidence_ref(evidence),
                )?;
                failure = Some(Status::Malformed);
                recover(role, headers)
            }
        };
        let client_initiated = Side::initiator_of(stream_id) == Side::Client;
        if side == Side::Server
            && role == FieldRole::Response
            && client_initiated
            && self.control.goaway[Side::Server].is_some_and(|last| stream_id > last)
        {
            reporter.issue(
                context,
                Fault::stream(
                    flow.clone(),
                    stream_id,
                    Status::Malformed,
                    IssueCode::ResponseAfterGoaway,
                    RESPONSE_AFTER_GOAWAY,
                )
                .with_evidence_ref(evidence),
            )?;
            failure = Some(Status::Malformed);
        }
        if role == FieldRole::Trailer
            && self
                .streams
                .open_get(stream_id)
                .and_then(|stream| stream.msgs[side].as_ref())
                .is_some_and(|msg| msg.status_code.is_some_and(final_status_forbids_trailers))
        {
            reporter.issue(
                context,
                Fault::stream(
                    flow.clone(),
                    stream_id,
                    Status::Malformed,
                    IssueCode::HeaderSemantics,
                    "204 and 304 responses cannot contain trailers",
                )
                .with_evidence_ref(evidence),
            )?;
            failure = Some(Status::Malformed);
        }
        if role == FieldRole::Trailer && !end_stream {
            reporter.issue(
                context,
                Fault::stream(
                    flow.clone(),
                    stream_id,
                    Status::Malformed,
                    IssueCode::TrailerWithoutEndStream,
                    "a trailer block must terminate the stream",
                )
                .with_evidence_ref(evidence),
            )?;
            failure = failure.or(Some(Status::Malformed));
        }
        if let Some(status) = meta.status
            && (100..200).contains(&status)
            && end_stream
        {
            reporter.issue(
                context,
                Fault::stream(
                    flow.clone(),
                    stream_id,
                    Status::Malformed,
                    IssueCode::InformationalEndStream,
                    "a 1xx response must not end the stream",
                )
                .with_evidence_ref(evidence),
            )?;
            failure = failure.or(Some(Status::Malformed));
        }
        if meta.protocol {
            reporter.issue(
                context,
                Fault::stream(
                    flow,
                    stream_id,
                    Status::Unsupported,
                    IssueCode::ExtendedConnect,
                    ":protocol extended CONNECT is outside this analyzer's semantics",
                )
                .with_evidence_ref(evidence),
            )?;
            failure = failure.or(Some(Status::Unsupported));
        }
        Ok((meta, failure))
    }

    fn attach_trailers(
        &mut self,
        flags: HeaderFlags,
        decoded: Decoded,
        evidence: &Evidence,
        failure: &mut Option<Status>,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> Result<(), crate::analysis::http2::Error> {
        let HeaderFlags {
            side, stream_id, ..
        } = flags;
        let flow = self.directions.flow(side);
        let Some(stream) = self.streams.open_mut(stream_id) else {
            return Ok(());
        };
        let Some(msg) = stream.msgs[side].as_mut() else {
            *failure = Some(Status::Malformed);
            return reporter.issue(
                context,
                Fault::stream(
                    flow,
                    stream_id,
                    Status::Malformed,
                    IssueCode::HeadersAfterEnd,
                    "HEADERS arrived after the sender already ended the stream",
                )
                .with_evidence(decoded.block, decoded.sources),
            );
        };
        if msg.trailers_seen {
            reporter.issue(
                context,
                Fault::stream(
                    flow,
                    stream_id,
                    Status::Malformed,
                    IssueCode::SecondTrailerBlock,
                    "a third header block follows completed trailers",
                )
                .with_evidence_ref(evidence),
            )?;
            *failure = Some(Status::Malformed);
        }
        if failure.is_some() {
            msg.failure = Some(Status::Malformed);
        }
        msg.trailers_seen = true;
        msg.retain_headers(HeaderSection::Trailers, decoded, context)
    }

    fn early_response_followup(
        &mut self,
        flags: HeaderFlags,
        early: EarlyResponse,
        headers: &[Header],
        evidence: &Evidence,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult<bool> {
        if !early.final_seen && !early.ended {
            return Ok(false);
        }
        let id = flags.stream_id;
        let invalid = early.ended
            || early.forbids_trailers
            || !flags.end_stream
            || validate(FieldRole::Trailer, headers).is_err();
        let (status, certainty) = if invalid {
            (Status::Malformed, Certainty::Confirmed)
        } else {
            (Status::Incomplete, Certainty::Indeterminate)
        };
        let code = if early.ended {
            IssueCode::HeadersAfterEnd
        } else if invalid {
            IssueCode::HeaderSemantics
        } else {
            IssueCode::EarlyResponseTrailers
        };
        reporter.issue(
            context,
            Fault::stream(
                self.directions.flow(Side::Server),
                id,
                status,
                code,
                "HEADERS follow a previously observed final response whose opener was capture-delayed",
            )
            .with_certainty(certainty)
            .with_evidence_ref(evidence),
        )?;
        if self.streams.is_open(id) {
            // The provisional response has no message builder to emit. Its
            // error must not terminate the independently captured request.
            self.end_side(Side::Server, id, status, reporter, context)?;
        } else if let Some(state) = self.streams.early_response_mut(id) {
            state.ended = true;
        }
        Ok(true)
    }
}
