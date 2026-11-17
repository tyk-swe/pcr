// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;

use super::{Code, CriticalStreams, Issue, Limits, Work, conflicting, frame, has_gap, prefix};
use crate::analysis::quic::Stream;
use crate::error::BoundaryError;
use crate::protocol::application::{qpack, quic::Reader};

#[derive(Default)]
pub(super) struct Streams<'a> {
    control: Option<(&'a Stream, usize)>,
    encoder: Option<(&'a Stream, usize)>,
    duplicate_control: bool,
    duplicate_encoder: bool,
}

impl<'a> Streams<'a> {
    pub(super) fn observe(&mut self, stream: &'a Stream) {
        let mut reader = Reader::new(prefix(stream));
        match reader.varint() {
            Ok(0) if self.control.is_some() => self.duplicate_control = true,
            Ok(0) => self.control = Some((stream, reader.position)),
            Ok(2) if self.encoder.is_some() => self.duplicate_encoder = true,
            Ok(2) => self.encoder = Some((stream, reader.position)),
            _ => {}
        }
    }

    pub(super) fn settings(self, work: &mut Work<'_>) -> Result<Context<'a>, BoundaryError> {
        let mut report = CriticalStreams {
            control_stream: self.control.map(|(stream, _)| stream.id),
            encoder_stream: self.encoder.map(|(stream, _)| stream.id),
            ..CriticalStreams::default()
        };
        if let Some((stream, _)) = self.control
            && (stream.final_size.is_some() || stream.reset_error.is_some())
        {
            report.issues.push(Issue {
                code: Code::ClosedControlStream,
                offset: None,
            });
        }
        let result = match self.control {
            _ if self.duplicate_control => Err(Code::DuplicateCriticalStream),
            None => Err(Code::MissingControlStream),
            Some((stream, _)) if conflicting(stream) => Err(Code::ConflictingStream),
            Some((stream, offset)) => match settings(&prefix(stream)[offset..], work) {
                Ok(capacity) => Ok(capacity),
                Err(qpack::Failure::Interrupted(error)) => return Err(error),
                Err(qpack::Failure::Limit) => Err(Code::Limit),
                Err(qpack::Failure::Truncated) if !stream.complete => Err(Code::MissingSettings),
                Err(_) => Err(Code::InvalidSettings),
            },
        };
        match result {
            Ok((capacity, blocked_streams)) => {
                report.max_table_capacity = Some(capacity);
                report.qpack_blocked_streams = Some(blocked_streams);
            }
            Err(code) => report.issues.push(Issue { code, offset: None }),
        }
        Ok(Context {
            report,
            streams: self,
        })
    }
}

pub(super) struct Context<'a> {
    pub(super) report: CriticalStreams,
    streams: Streams<'a>,
}

impl Context<'_> {
    pub(super) fn history(
        &mut self,
        peer_capacity: Option<u64>,
        limits: Limits,
        work: &mut Work<'_>,
    ) -> Result<qpack::History, BoundaryError> {
        let mut history = qpack::History::new(peer_capacity, limits.max_qpack_history_bytes);
        if self.streams.duplicate_encoder {
            self.report.issues.push(Issue {
                code: Code::DuplicateCriticalStream,
                offset: None,
            });
            return Ok(history);
        }
        let Some((stream, offset)) = self.streams.encoder else {
            return Ok(history);
        };
        let prefix = prefix(stream);
        let gap =
            has_gap(stream, prefix) || stream.reset_error.is_some() || stream.omitted_bytes > 0;
        let issue = if conflicting(stream) {
            Some(Code::ConflictingStream)
        } else {
            match history.replay(&prefix[offset..], &mut |charge| work.step(charge)) {
                Ok(()) => gap.then_some(Code::EncoderStreamGap),
                Err(qpack::Failure::Interrupted(error)) => return Err(error),
                Err(qpack::Failure::Limit) => Some(Code::Limit),
                Err(qpack::Failure::Truncated) if !stream.complete => Some(Code::EncoderStreamGap),
                Err(qpack::Failure::Unavailable) => Some(Code::QpackUnavailable),
                Err(_) => Some(Code::QpackEncoderError),
            }
        };
        if let Some(code) = issue {
            history.mark_incomplete();
            self.report.issues.push(Issue { code, offset: None });
        }
        self.report.encoder_inserts = history.insert_count();
        Ok(history)
    }
}

pub(super) fn normally_open(stream: &Stream) -> bool {
    matches!(stream.id % 4, 2 | 3)
        && stream.final_size.is_none()
        && stream.reset_error.is_none()
        && stream.omitted_bytes == 0
        && !stream.early_data
        && !has_gap(stream, prefix(stream))
        && matches!(Reader::new(prefix(stream)).varint(), Ok(0 | 2 | 3))
}

fn settings(input: &[u8], work: &mut Work<'_>) -> Result<(u64, u64), qpack::Failure> {
    let mut control = Reader::new(input);
    let settings = frame(&mut control).map_err(|_| qpack::Failure::Truncated)?;
    if settings.kind != 4 {
        return Err(qpack::Failure::Invalid);
    }
    let mut capacity = 0;
    let mut blocked_streams = 0;
    let mut seen = BTreeSet::new();
    let mut reader = Reader::new(settings.data);
    while reader.left() > 0 {
        work.step(1)?;
        let id = reader.varint().map_err(|_| qpack::Failure::Invalid)?;
        let value = reader.varint().map_err(|_| qpack::Failure::Invalid)?;
        if matches!(id, 2..=5) || !seen.insert(id) {
            return Err(qpack::Failure::Invalid);
        }
        match id {
            1 => capacity = value,
            7 => blocked_streams = value,
            _ => {}
        }
    }
    while control.left() > 0 {
        work.step(1)?;
        let Ok(frame) = frame(&mut control) else {
            break;
        };
        if matches!(frame.kind, 0..=2 | 4..=6 | 8 | 9) {
            return Err(qpack::Failure::Invalid);
        }
    }
    Ok((capacity, blocked_streams))
}
