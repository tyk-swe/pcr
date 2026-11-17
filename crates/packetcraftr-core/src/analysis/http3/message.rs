// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    Code, Field, HeaderSection, Issue, Limits, SectionKind, Side, Work, conflicting, frame,
    has_gap, prefix,
};
use crate::analysis::http_headers::{self, FieldRole};
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
    Tunnel,
    Trailers,
    Unknown,
}

struct DeclaredLength {
    bytes: u64,
    offset: u64,
    status: Option<u16>,
}

pub(super) fn read(
    stream: &Stream,
    history: &qpack::History,
    limits: Limits,
    request_method: Option<&str>,
    connect_enabled: Option<bool>,
    remaining: &mut usize,
    work: &mut Work<'_>,
) -> Result<Side, BoundaryError> {
    let mut side = Side {
        reset_error: stream.reset_error,
        ..Side::default()
    };
    if conflicting(stream) {
        side.issue(Code::ConflictingStream, None);
        return Ok(side);
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
    let mut reader = Reader::new(prefix);
    let mut stage = Stage::Initial;
    let mut declared_length = None;
    while reader.left() > 0 {
        let offset = reader.position as u64;
        match work.step(1) {
            Ok(()) => {}
            Err(qpack::Failure::Interrupted(error)) => return Err(error),
            Err(_) => {
                side.issue(Code::Limit, Some(offset));
                return Ok(side);
            }
        }
        let Ok(frame) = frame(&mut reader) else {
            let code = if stream.complete {
                Code::InvalidFrame
            } else {
                Code::TruncatedFrame
            };
            side.issue(code, Some(offset));
            return Ok(side);
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
                    return Ok(side);
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
                                    &mut stage,
                                    stream.direction,
                                    request_method,
                                    connect_enabled,
                                ) {
                                    Ok(Some(length)) => declared_length = Some(length),
                                    Ok(None) => {}
                                    Err(code) => side.issue(code, Some(offset)),
                                }
                            }
                            Err(qpack::Failure::Interrupted(error)) => return Err(error),
                            Err(_) => {
                                section.required_insert_count = None;
                                side.issue(Code::Limit, Some(offset));
                                side.header_sections.push(section);
                                return Ok(side);
                            }
                        }
                    }
                    Err(qpack::Failure::Interrupted(error)) => return Err(error),
                    Err(error) => {
                        side.issue(qpack_code(error), Some(offset));
                        if matches!(stage, Stage::Initial) && stream.direction == Direction::Client
                        {
                            section.kind = SectionKind::Request;
                        }
                        stage = after_unreadable_headers(&stage, stream.direction);
                    }
                }
                side.header_sections.push(section);
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
        if successful_connect {
            side.issue(Code::InvalidHeaders, Some(length.offset));
        } else if stream.complete && body_length_applies && side.data_bytes != length.bytes {
            side.issue(Code::ContentLengthMismatch, Some(length.offset));
        }
    }
    side.complete = stream.complete
        && matches!(stage, Stage::Body { .. } | Stage::Tunnel | Stage::Trailers)
        && side.issues.is_empty();
    Ok(side)
}

impl Side {
    pub(super) fn check_connect_request(&mut self, response: &Self) {
        let successful = response.header_sections.iter().any(|section| {
            section.kind == SectionKind::Response && matches!(section.status, Some(200..=299))
        });
        if !successful {
            return;
        }
        if let Some(trailer) = self.header_sections.get_mut(1) {
            trailer.kind = SectionKind::Unclassified;
            let offset = trailer.offset;
            self.issue(Code::InvalidFramePlacement, Some(offset));
            self.complete = false;
        }
    }

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
        Stage::Trailers | Stage::Tunnel => return Err(Code::InvalidHeaders),
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
                        || matches!(status, Some(204 | 205 | 304)),
                    trailers_forbidden: matches!(status, Some(204 | 304)),
                }
            };
            SectionKind::Response
        }
        (FieldRole::Request, _) => {
            *stage = Stage::Body {
                content_forbidden: false,
                trailers_forbidden: false,
            };
            section.method = meta
                .method
                .as_deref()
                .and_then(|method| std::str::from_utf8(method).ok())
                .map(str::to_owned);
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
