// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Startup protocol sniffing, direction election, and client preface parsing.

use super::super::Error;
use super::super::buffer::union_balanced;
use super::super::model::{Startup, Status};
use super::super::upgrade::Prelude;
use super::{
    ActiveState, ConnectionState, Context, DirectionPhase, Fault, PREFACE_LEN, Phase, Reporter,
    SniffingState, StepResult,
};
use crate::analysis::http2::IssueCode;
use crate::analysis::http2::side::Side;
use crate::protocol::application::http;
use crate::protocol::application::http2 as wire;

pub(crate) enum Verdict {
    Wait,
    Prior,
    Prelude,
    Tls,
    Garbage,
}

pub(crate) enum Election {
    Pending,
    Unsupported,
    Elected { index: usize, startup: Startup },
}

pub(crate) fn tls_like(bytes: &[u8]) -> bool {
    bytes.len() >= 3 && bytes[0] == 0x16 && bytes[1] == 0x03 && bytes[2] <= 0x04
}

fn first_line(bytes: &[u8]) -> Option<&[u8]> {
    bytes
        .iter()
        .position(|b| *b == b'\n')
        .map(|end| bytes[..end].strip_suffix(b"\r").unwrap_or(&bytes[..end]))
}

fn request_line(line: &[u8]) -> Option<()> {
    let mut parts = line.split(|b| *b == b' ');
    let method = parts.next()?;
    if method.is_empty() || !method.iter().all(|b| http::token(*b)) {
        return None;
    }
    let target = parts.next()?;
    if target.is_empty() || target.iter().any(u8::is_ascii_whitespace) {
        return None;
    }
    let version = parts.next()?;
    if parts.next().is_some() || !version.starts_with(b"HTTP/1.") {
        return None;
    }
    let minor = version.strip_prefix(b"HTTP/1.")?;
    if minor.len() != 1 || !minor[0].is_ascii_digit() {
        return None;
    }
    Some(())
}

pub(crate) fn classify(bytes: &[u8]) -> Verdict {
    let have = bytes.len().min(PREFACE_LEN);
    if bytes[..have] == wire::CLIENT_PREFACE[..have] {
        return if have == PREFACE_LEN {
            Verdict::Prior
        } else {
            Verdict::Wait
        };
    }
    let divergence = bytes
        .iter()
        .zip(wire::CLIENT_PREFACE.iter())
        .position(|(got, want)| got != want);
    if matches!(divergence, Some(position) if position >= 18) {
        return Verdict::Prior;
    }
    if tls_like(bytes) {
        return Verdict::Tls;
    }
    match first_line(bytes) {
        Some(line) if request_line(line).is_some() => Verdict::Prelude,
        Some(_) => Verdict::Garbage,
        None if bytes.len() > http::MAX_START_LINE => Verdict::Garbage,
        None => Verdict::Wait,
    }
}

impl SniffingState {
    pub(crate) fn classify_candidates(&mut self) -> Election {
        for index in 0..self.directions.candidates.len() {
            match classify(self.directions.candidates[index].buffer.bytes()) {
                Verdict::Wait => continue,
                Verdict::Tls => return Election::Unsupported,
                Verdict::Garbage => {
                    self.directions.candidates[index].garbage = true;
                }
                Verdict::Prior => {
                    return Election::Elected {
                        index,
                        startup: Startup::PriorKnowledge,
                    };
                }
                Verdict::Prelude => {
                    return Election::Elected {
                        index,
                        startup: Startup::Unknown,
                    };
                }
            }
        }
        Election::Pending
    }
}

impl ConnectionState {
    pub(crate) fn promote_sniffing(
        &mut self,
        client_index: usize,
        startup: Startup,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let prelude = match startup {
            Startup::PriorKnowledge => None,
            Startup::H2c | Startup::Unknown => Some(Prelude::new(context)?),
        };
        let placeholder = Phase::Sniffing(SniffingState {
            directions: super::SniffingDirections::new(),
        });
        let Phase::Sniffing(sniff) = std::mem::replace(&mut self.phase, placeholder) else {
            return Err(Error::Invariant("election outside sniffing phase"));
        };
        let (directions, clean_start) = match sniff.directions.elect(client_index, startup, context)
        {
            Ok(elected) => elected,
            Err(error) => {
                if let Some(prelude) = prelude {
                    let _ = prelude.release_all(context);
                }
                return Err(error);
            }
        };
        self.reporter.startup = startup;
        self.phase = Phase::Active(Box::new(ActiveState::new(directions, prelude, clean_start)));
        Ok(())
    }
}

impl ActiveState {
    pub(crate) fn preface_step(
        &mut self,
        side: Side,
        reporter: &mut Reporter,
        context: &mut Context<'_>,
    ) -> StepResult<bool> {
        let Some(dir) = self.directions.get_mut(side) else {
            return Ok(false);
        };
        let have = dir.buffer.len().min(PREFACE_LEN);
        if dir.buffer.bytes()[..have] != wire::CLIENT_PREFACE[..have] {
            let flow = dir.flow.clone();
            let take = dir.buffer.len();
            let (wire, sets) = dir.buffer.take(take, context)?;
            let sources = union_balanced(sets)?;
            return reporter.reject(
                context,
                Fault::connection(
                    flow,
                    Status::Malformed,
                    IssueCode::BadPreface,
                    "client connection preface does not match the HTTP/2 magic",
                )
                .with_evidence(wire, sources),
            );
        }
        if dir.buffer.len() < PREFACE_LEN {
            return Ok(false);
        }
        dir.buffer.discard(PREFACE_LEN, context)?;
        dir.phase = DirectionPhase::Frames;
        Ok(true)
    }
}
