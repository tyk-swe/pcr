// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    Code, Field, HeaderSection, Issue, Limits, SectionKind, Side, Work, conflicting, frame,
    has_gap, prefix,
};
use crate::analysis::http_headers::{
    self, FieldRole, final_status_forbids_content, final_status_forbids_trailers,
};
use crate::analysis::quic::{Direction, Stream};
use crate::error::BoundaryError;
use crate::protocol::application::{qpack, quic::Reader};

const SECTION_CHARGE: usize = 64;
const MAX_ISSUES: usize = 64;

enum Stage {
    Initial,
    Informational,
    Body {
        content_forbidden: bool,
        trailers_forbidden: bool,
    },
    AwaitConnectResponse,
    Tunnel,
    Trailers,
    Unknown,
}

struct DeclaredLength {
    bytes: u64,
    offset: u64,
    status: Option<u16>,
}

enum ReadUntil<'a> {
    End(Option<&'a str>),
    ConnectResponseHead,
}

#[derive(PartialEq, Eq)]
enum Progress {
    Paused,
    Finished,
}

pub(super) fn read_pair(
    [request, response]: [Option<&Stream>; 2],
    [client, server]: [&qpack::History; 2],
    limits: Limits,
    connect_enabled: Option<bool>,
    work: &mut Work<'_>,
) -> Result<[Option<Side>; 2], BoundaryError> {
    let mut remaining = limits.max_exchange_bytes;
    let mut read = |message: &mut Message<'_>, history: &qpack::History, until: ReadUntil<'_>| {
        message.read(
            history,
            limits,
            until,
            connect_enabled,
            &mut remaining,
            work,
        )
    };
    let mut request = request.map(Message::new);
    let mut response = response.map(Message::new);
    if let Some(request) = &mut request {
        read(request, client, ReadUntil::End(None))?;
    }
    if let Some(request) = &mut request
        && matches!(request.stage, Stage::AwaitConnectResponse)
    {
        let progress = match &mut response {
            Some(response) => read(response, server, ReadUntil::ConnectResponseHead)?,
            None => Progress::Finished,
        };
        request.stage = if response
            .as_ref()
            .is_some_and(|message| matches!(message.stage, Stage::Tunnel))
        {
            Stage::Tunnel
        } else {
            Stage::Body {
                content_forbidden: false,
                trailers_forbidden: false,
            }
        };
        read(request, client, ReadUntil::End(None))?;
        if let Some(response) = &mut response
            && progress == Progress::Paused
        {
            read(response, server, ReadUntil::End(Some("CONNECT")))?;
        }
    } else if let Some(response) = &mut response {
        let request_method = request
            .as_ref()
            .and_then(|message| message.side.header_sections.first())
            .and_then(|section| section.method.as_deref());
        read(response, server, ReadUntil::End(request_method))?;
    }
    Ok([
        request.map(|message| message.side),
        response.map(|message| message.side),
    ])
}

struct Message<'a> {
    stream: &'a Stream,
    reader: Reader<'a>,
    side: Side,
    stage: Stage,
    declared_length: Option<DeclaredLength>,
}

impl<'a> Message<'a> {
    fn new(stream: &'a Stream) -> Self {
        let mut side = Side {
            reset_error: stream.reset_error,
            ..Side::default()
        };
        if conflicting(stream) {
            side.issue(Code::ConflictingStream, None);
            return Self {
                stream,
                reader: Reader::new(&[]),
                side,
                stage: Stage::Unknown,
                declared_length: None,
            };
        }
        let prefix = prefix(stream);
        side.prefix_bytes = prefix.len() as u64;
        if has_gap(stream, prefix) {
            side.issue(Code::StreamGap, Some(side.prefix_bytes));
        }
        if stream.reset_error.is_some() {
            side.issue(Code::StreamReset, None);
        }
        if stream.omitted_bytes > 0 {
            side.issue(Code::OmittedStreamBytes, None);
        }
        Self {
            stream,
            reader: Reader::new(prefix),
            side,
            stage: Stage::Initial,
            declared_length: None,
        }
    }

    fn read(
        &mut self,
        history: &qpack::History,
        limits: Limits,
        until: ReadUntil<'_>,
        connect_enabled: Option<bool>,
        remaining: &mut usize,
        work: &mut Work<'_>,
    ) -> Result<Progress, BoundaryError> {
        let request_method = match until {
            ReadUntil::End(method) => method,
            ReadUntil::ConnectResponseHead => Some("CONNECT"),
        };
        let Self {
            stream,
            reader,
            side,
            stage,
            declared_length,
        } = self;
        while reader.left() > 0 {
            let offset = reader.position as u64;
            match work.step(1) {
                Ok(()) => {}
                Err(qpack::Failure::Interrupted(error)) => return Err(error),
                Err(_) => {
                    side.issue(Code::Limit, Some(offset));
                    return Ok(Progress::Finished);
                }
            }
            let Ok(frame) = frame(reader) else {
                let code = if stream.complete {
                    Code::InvalidFrame
                } else {
                    Code::TruncatedFrame
                };
                side.issue(code, Some(offset));
                return Ok(Progress::Finished);
            };
            match frame.kind {
                0 => {
                    side.data_frames += 1;
                    side.data_bytes += frame.data.len() as u64;
                    side.first_data_offset.get_or_insert(offset);
                    if matches!(
                        stage,
                        Stage::Initial | Stage::Informational | Stage::Trailers
                    ) {
                        side.issue(Code::InvalidFramePlacement, Some(offset));
                    } else if matches!(
                        stage,
                        Stage::Body {
                            content_forbidden: true,
                            ..
                        }
                    ) && !frame.data.is_empty()
                    {
                        side.issue(Code::UnexpectedResponseContent, Some(offset));
                    }
                }
                1 if matches!(
                    stage,
                    Stage::Tunnel
                        | Stage::Body {
                            trailers_forbidden: true,
                            ..
                        }
                ) =>
                {
                    side.issue(Code::InvalidFramePlacement, Some(offset));
                }
                1 => {
                    let Some(bytes) = remaining.checked_sub(SECTION_CHARGE) else {
                        side.issue(Code::Limit, Some(offset));
                        return Ok(Progress::Finished);
                    };
                    *remaining = bytes;
                    let maximum = bytes.min(limits.max_header_section_bytes);
                    let mut section = HeaderSection {
                        kind: SectionKind::Unclassified,
                        offset,
                        encoded_bytes: frame.data.len() as u64,
                        required_insert_count: None,
                        method: None,
                        status: None,
                        fields: Vec::new(),
                    };
                    if matches!(stage, Stage::Trailers) {
                        side.issue(Code::InvalidFramePlacement, Some(offset));
                    }
                    match qpack::decode(frame.data, history, maximum, &mut |cost| work.step(cost)) {
                        Ok(decoded) => {
                            *remaining -= decoded.size;
                            section.required_insert_count = Some(decoded.required_insert_count);
                            match work.step(decoded.size) {
                                Ok(()) => {
                                    section.fields = decoded
                                        .fields
                                        .into_iter()
                                        .map(|field| Field {
                                            name: field.name,
                                            value: field.value,
                                        })
                                        .collect();
                                    match classify(
                                        &mut section,
                                        stage,
                                        stream.direction,
                                        request_method,
                                        connect_enabled,
                                    ) {
                                        Ok(Some(length)) => *declared_length = Some(length),
                                        Ok(None) => {}
                                        Err(code) => side.issue(code, Some(offset)),
                                    }
                                }
                                Err(qpack::Failure::Interrupted(error)) => return Err(error),
                                Err(_) => {
                                    section.required_insert_count = None;
                                    side.issue(Code::Limit, Some(offset));
                                    side.header_sections.push(section);
                                    return Ok(Progress::Finished);
                                }
                            }
                        }
                        Err(qpack::Failure::Interrupted(error)) => return Err(error),
                        Err(error) => {
                            side.issue(qpack_code(error), Some(offset));
                            if matches!(stage, Stage::Initial)
                                && stream.direction == Direction::Client
                            {
                                section.kind = SectionKind::Request;
                            }
                            *stage = after_unreadable_headers(stage, stream.direction);
                        }
                    }
                    side.header_sections.push(section);
                    if matches!(stage, Stage::AwaitConnectResponse)
                        || (matches!(until, ReadUntil::ConnectResponseHead)
                            && matches!(stage, Stage::Tunnel | Stage::Body { .. }))
                    {
                        return Ok(Progress::Paused);
                    }
                }
                2..=4 | 6..=9 | 13 => side.issue(Code::InvalidFramePlacement, Some(offset)),
                5 if stream.direction == Direction::Client || matches!(stage, Stage::Tunnel) => {
                    side.issue(Code::InvalidFramePlacement, Some(offset));
                }
                _ => {}
            }
        }
        if stream.complete {
            match stage {
                Stage::Initial => side.issue(Code::MissingInitialHeaders, None),
                Stage::Informational => side.issue(Code::MissingFinalResponse, None),
                _ => {}
            }
        }
        if let Some(length) = declared_length {
            let successful_connect = request_method == Some("CONNECT")
                && length
                    .status
                    .is_some_and(|status| (200..300).contains(&status));
            let body_length_applies = length.status.is_none()
                || (length.status != Some(304)
                    && request_method != Some("HEAD")
                    && (request_method.is_some() || side.data_bytes > 0));
            let content_bytes = if matches!(stage, Stage::Tunnel) {
                0
            } else {
                side.data_bytes
            };
            if successful_connect {
                side.issue(Code::InvalidHeaders, Some(length.offset));
            } else if stream.complete && body_length_applies && content_bytes != length.bytes {
                side.issue(Code::ContentLengthMismatch, Some(length.offset));
            }
        }
        side.complete = stream.complete
            && matches!(stage, Stage::Body { .. } | Stage::Tunnel | Stage::Trailers)
            && side.issues.is_empty();
        Ok(Progress::Finished)
    }
}

impl Side {
    fn issue(&mut self, code: Code, offset: Option<u64>) {
        if self.issues.len() < MAX_ISSUES {
            self.issues.push(Issue { code, offset });
        } else {
            self.issues_omitted += 1;
        }
    }
}

fn qpack_code(error: qpack::Failure) -> Code {
    match error {
        qpack::Failure::Unavailable => Code::QpackUnavailable,
        qpack::Failure::Ambiguous => Code::QpackAmbiguous,
        qpack::Failure::Limit => Code::Limit,
        _ => Code::QpackInvalid,
    }
}

fn after_unreadable_headers(stage: &Stage, direction: Direction) -> Stage {
    match stage {
        Stage::Initial if direction == Direction::Client => Stage::Body {
            content_forbidden: false,
            trailers_forbidden: false,
        },
        Stage::Body { .. } | Stage::Trailers => Stage::Trailers,
        _ => Stage::Unknown,
    }
}

fn classify(
    section: &mut HeaderSection,
    stage: &mut Stage,
    direction: Direction,
    request_method: Option<&str>,
    connect_enabled: Option<bool>,
) -> Result<Option<DeclaredLength>, Code> {
    let fields = section
        .fields
        .iter()
        .map(|field| (&field.name, &field.value));
    let role = match stage {
        Stage::Unknown => {
            if direction == Direction::Server {
                section.status =
                    http_headers::response_status(fields).filter(|status| *status != 101);
            }
            return Ok(None);
        }
        Stage::Trailers | Stage::AwaitConnectResponse | Stage::Tunnel => {
            return Err(Code::InvalidHeaders);
        }
        Stage::Body { .. } => {
            *stage = Stage::Trailers;
            FieldRole::Trailer
        }
        Stage::Initial if direction == Direction::Client => FieldRole::Request,
        Stage::Initial | Stage::Informational => FieldRole::Response,
    };
    let meta = match http_headers::validate(role, fields) {
        Ok(meta) if meta.status != Some(101) => meta,
        _ => {
            *stage = after_unreadable_headers(stage, direction);
            return Err(Code::InvalidHeaders);
        }
    };
    section.status = meta.status;
    section.kind = match (role, meta.status) {
        (FieldRole::Trailer, _) => SectionKind::Trailers,
        (FieldRole::Response, Some(100..=199)) => {
            *stage = Stage::Informational;
            SectionKind::Informational
        }
        (FieldRole::Response, status) => {
            *stage = if request_method == Some("CONNECT") && matches!(status, Some(200..=299)) {
                Stage::Tunnel
            } else {
                Stage::Body {
                    content_forbidden: request_method == Some("HEAD")
                        || status.is_some_and(final_status_forbids_content),
                    trailers_forbidden: status.is_some_and(final_status_forbids_trailers),
                }
            };
            SectionKind::Response
        }
        (FieldRole::Request, _) => {
            section.method = meta
                .method
                .as_deref()
                .and_then(|method| std::str::from_utf8(method).ok())
                .map(str::to_owned);
            *stage = if section.method.as_deref() == Some("CONNECT") {
                Stage::AwaitConnectResponse
            } else {
                Stage::Body {
                    content_forbidden: false,
                    trailers_forbidden: false,
                }
            };
            SectionKind::Request
        }
    };
    if meta.protocol {
        match connect_enabled {
            Some(true) => {}
            Some(false) => return Err(Code::ExtendedConnectDisabled),
            None => return Err(Code::ExtendedConnectSettingsUnavailable),
        }
    }
    Ok(meta.content_length.map(|bytes| DeclaredLength {
        bytes,
        offset: section.offset,
        status: section.status,
    }))
}
