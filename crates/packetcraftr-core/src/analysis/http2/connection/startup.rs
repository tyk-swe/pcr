// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::Error;
use super::super::buffer::union_balanced;
use super::super::model::{IssueScope, Startup, Status};
use super::super::upgrade::Prelude;
use super::directions::Elected;
use super::{ConnectionState, Context, DirectionPhase, Directions, Fault, PREFACE_LEN, Phase};
use crate::analysis::http2::IssueCode;
use crate::analysis::http2::budget;
use crate::analysis::http2::side::Side;
use crate::protocol::application::http;
use crate::protocol::application::http2 as wire;
use crate::protocol::application::http2::hpack;

pub(crate) enum Verdict {
    Wait,
    Prior,
    Prelude,
    Tls,
    Garbage,
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

impl ConnectionState {
    pub(crate) fn elect(&mut self, context: &mut Context<'_>) -> Result<(), Error> {
        for index in 0..self.directions.candidates().len() {
            match classify(self.directions.candidates()[index].buffer.bytes()) {
                Verdict::Wait => continue,
                Verdict::Tls => {
                    self.status = Status::Unsupported;
                    self.fail(context, Status::Unsupported)?;
                    return Ok(());
                }
                Verdict::Garbage => {
                    self.directions.candidates_mut()[index].garbage = true;
                    continue;
                }
                Verdict::Prior => {
                    self.elect_client(index, Startup::PriorKnowledge, context)?;
                    if let Some(dir) = self.directions.get_mut(Side::Client) {
                        dir.phase = DirectionPhase::Preface;
                    }
                    self.phase = Phase::H2;
                    return Ok(());
                }
                Verdict::Prelude => {
                    self.elect_client(index, Startup::Unknown, context)?;
                    if let Some(dir) = self.directions.get_mut(Side::Client) {
                        dir.phase = DirectionPhase::Prelude;
                    }
                    if let Some(dir) = self.directions.get_mut(Side::Server) {
                        dir.phase = DirectionPhase::Prelude;
                    }
                    self.upgrade.prelude = Some(Prelude::new());
                    context.charge(&mut self.charge, budget::DIR_OVERHEAD)?;
                    self.phase = Phase::Prelude;
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    fn elect_client(
        &mut self,
        index: usize,
        startup: Startup,
        context: &mut Context<'_>,
    ) -> Result<(), Error> {
        let Directions::Candidates(mut candidates) =
            std::mem::replace(&mut self.directions, Directions::Candidates(Vec::new()))
        else {
            return Err(Error::Invariant("election after election"));
        };
        let mut client = candidates.swap_remove(index);
        client.decoder = Some(hpack::Decoder::new(context.limits.hpack())?);
        self.startup = startup;
        let mut server = None;
        for mut dir in candidates {
            if !dir.buffer.is_empty() {
                self.clean_start = false;
            }
            dir.decoder = Some(hpack::Decoder::new(context.limits.hpack())?);
            dir.phase = match startup {
                Startup::PriorKnowledge => DirectionPhase::Frames,
                _ => DirectionPhase::Prelude,
            };
            server = Some(dir);
        }
        self.directions = Directions::Elected(Box::new(Elected { client, server }));
        Ok(())
    }

    pub(crate) fn preface_step(
        &mut self,
        side: Side,
        context: &mut Context<'_>,
    ) -> Result<bool, Error> {
        let dir = self
            .directions
            .get_mut(side)
            .ok_or(Error::Invariant("direction not found"))?;
        let have = dir.buffer.len().min(PREFACE_LEN);
        if dir.buffer.bytes()[..have] != wire::CLIENT_PREFACE[..have] {
            let flow = dir.flow.clone();
            let take = dir.buffer.len();
            let sets = dir.buffer.contributors(take);
            let (wire, dropped) = dir.buffer.take(take);
            let sources = union_balanced(sets)?;
            dir.release_consumed(take, dropped, context)?;
            self.reject(
                context,
                Fault::new(
                    flow,
                    IssueScope::Connection,
                    Status::Malformed,
                    IssueCode::BadPreface,
                    "client connection preface does not match the HTTP/2 magic",
                )
                .evidence(wire, sources),
            )?;
            return Ok(true);
        }
        if dir.buffer.len() < PREFACE_LEN {
            return Ok(false);
        }
        let dropped = dir.buffer.consume(PREFACE_LEN);
        dir.release_consumed(PREFACE_LEN, dropped, context)?;
        if let Some(dir) = self.directions.get_mut(side) {
            dir.phase = DirectionPhase::Frames;
        }
        Ok(true)
    }
}
