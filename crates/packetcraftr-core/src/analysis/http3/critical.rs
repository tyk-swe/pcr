// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;

use super::{Code, CriticalStreams, Issue, Limits, Work, conflicting, frame, has_gap, prefix};
use crate::analysis::quic::Stream;
use crate::error::BoundaryError;
use crate::protocol::application::{qpack, quic::Reader};

#[derive(Default)]
struct CriticalStream<'a> {
    first: Option<(&'a Stream, usize)>,
    duplicate: bool,
    closed: bool,
}

impl<'a> CriticalStream<'a> {
    fn observe(&mut self, stream: &'a Stream, offset: usize) {
        self.duplicate |= self.first.is_some();
        self.closed |= stream.final_size.is_some() || stream.reset_error.is_some();
        self.first.get_or_insert((stream, offset));
    }

    fn issues(&self, closure: Code) -> impl Iterator<Item = Issue> {
        [
            self.closed.then_some(closure),
            self.duplicate.then_some(Code::DuplicateCriticalStream),
        ]
        .into_iter()
        .flatten()
        .map(|code| Issue { code, offset: None })
    }
}

#[derive(Default)]
pub(super) struct Streams<'a> {
    control: CriticalStream<'a>,
    encoder: CriticalStream<'a>,
    decoder: CriticalStream<'a>,
}

impl<'a> Streams<'a> {
    pub(super) fn observe(&mut self, stream: &'a Stream) {
        let mut reader = Reader::new(prefix(stream));
        let tracked = match reader.varint() {
            Ok(0) => &mut self.control,
            Ok(2) => &mut self.encoder,
            Ok(3) => &mut self.decoder,
            _ => return,
        };
        tracked.observe(stream, reader.position);
    }

    pub(super) fn settings(self, work: &mut Work<'_>) -> Result<Context<'a>, BoundaryError> {
        let mut report = CriticalStreams {
            control_stream: self.control.first.map(|(stream, _)| stream.id),
            encoder_stream: self.encoder.first.map(|(stream, _)| stream.id),
            issues: self
                .control
                .issues(Code::ClosedControlStream)
                .chain(self.encoder.issues(Code::ClosedQpackEncoderStream))
                .chain(self.decoder.issues(Code::ClosedQpackDecoderStream))
                .collect(),
            ..CriticalStreams::default()
        };
        let (settings, issue) = match self.control.first {
            _ if self.control.duplicate => (None, None),
            None => (None, Some(Code::MissingControlStream)),
            Some((stream, _)) if conflicting(stream) => (None, Some(Code::ConflictingStream)),
            Some((stream, offset)) => read_control(stream, offset, work)?,
        };
        if let Some(code) = issue {
            report.issues.push(Issue { code, offset: None });
        }
        let connect_enabled = settings.map(|settings| {
            report.max_table_capacity = Some(settings.capacity);
            report.qpack_blocked_streams = Some(settings.blocked_streams);
            settings.connect_enabled
        });
        Ok(Context {
            report,
            connect_enabled,
            streams: self,
        })
    }
}

pub(super) struct Context<'a> {
    pub(super) report: CriticalStreams,
    pub(super) connect_enabled: Option<bool>,
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
        if self.streams.encoder.duplicate {
            return Ok(history);
        }
        let Some((stream, offset)) = self.streams.encoder.first else {
            return Ok(history);
        };
        let prefix = prefix(stream);
        let gap = has_gap(stream, prefix) || stream.omitted_bytes > 0;
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

#[derive(Default)]
struct Settings {
    capacity: u64,
    blocked_streams: u64,
    connect_enabled: bool,
}

fn read_control(
    stream: &Stream,
    offset: usize,
    work: &mut Work<'_>,
) -> Result<(Option<Settings>, Option<Code>), BoundaryError> {
    let mut control = Reader::new(&prefix(stream)[offset..]);
    let (settings, error) = match settings(&mut control, work) {
        Ok(settings) => (Some(settings), check_control_tail(&mut control, work).err()),
        Err(error) => (None, Some(error)),
    };
    let issue = match error {
        None => None,
        Some(qpack::Failure::Interrupted(error)) => return Err(error),
        Some(qpack::Failure::Limit) => Some(Code::Limit),
        Some(qpack::Failure::Truncated) if !stream.complete => Some(Code::MissingSettings),
        Some(_) => Some(Code::InvalidSettings),
    };
    Ok((settings, issue))
}

fn settings(control: &mut Reader<'_>, work: &mut Work<'_>) -> Result<Settings, qpack::Failure> {
    let settings_frame = frame(control).map_err(|_| qpack::Failure::Truncated)?;
    if settings_frame.kind != 4 {
        return Err(qpack::Failure::Invalid);
    }
    let mut settings = Settings::default();
    let mut seen = BTreeSet::new();
    let mut reader = Reader::new(settings_frame.data);
    while reader.left() > 0 {
        work.step(1)?;
        let id = reader.varint().map_err(|_| qpack::Failure::Invalid)?;
        let value = reader.varint().map_err(|_| qpack::Failure::Invalid)?;
        if matches!(id, 2..=5) || !seen.insert(id) {
            return Err(qpack::Failure::Invalid);
        }
        match id {
            1 => settings.capacity = value,
            7 => settings.blocked_streams = value,
            8 if value <= 1 => settings.connect_enabled = value == 1,
            8 => return Err(qpack::Failure::Invalid),
            _ => {}
        }
    }
    Ok(settings)
}

fn check_control_tail(control: &mut Reader<'_>, work: &mut Work<'_>) -> Result<(), qpack::Failure> {
    while control.left() > 0 {
        work.step(1)?;
        let Ok(frame) = frame(control) else {
            break;
        };
        if matches!(frame.kind, 0..=2 | 4..=6 | 8 | 9) {
            return Err(qpack::Failure::Invalid);
        }
    }
    Ok(())
}
