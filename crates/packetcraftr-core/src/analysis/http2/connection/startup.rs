// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::Error;
use super::super::buffer::union_balanced;
use super::super::model::{Certainty, IssueScope, Startup, Status};
use super::super::upgrade::Prelude;
use super::{CLIENT, Conn, Cx, DirPhase, Fault, PREFACE_LEN, Phase, SERVER};
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

impl Conn {
    pub(crate) fn elect(&mut self, cx: &mut Cx<'_>) -> Result<(), Error> {
        for index in 0..self.pending.len() {
            match classify(self.pending[index].buffer.bytes()) {
                Verdict::Wait => continue,
                Verdict::Tls => {
                    self.status = Status::Unsupported;
                    self.fail(cx, Status::Unsupported)?;
                    return Ok(());
                }
                Verdict::Garbage => {
                    self.pending[index].garbage = true;
                    continue;
                }
                Verdict::Prior => {
                    self.elect_client(index, Startup::PriorKnowledge, cx)?;
                    if let Some(dir) = self.dirs[CLIENT].as_mut() {
                        dir.phase = DirPhase::Preface;
                    }
                    self.phase = Phase::H2;
                    return Ok(());
                }
                Verdict::Prelude => {
                    self.elect_client(index, Startup::Unknown, cx)?;
                    if let Some(dir) = self.dirs[CLIENT].as_mut() {
                        dir.phase = DirPhase::Prelude;
                    }
                    for dir in self.dirs[SERVER].iter_mut() {
                        dir.phase = DirPhase::Prelude;
                    }
                    self.prelude = Some(Prelude::new());
                    self.charge_conn(cx, super::resources::DIR_OVERHEAD)?;
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
        cx: &mut Cx<'_>,
    ) -> Result<(), Error> {
        let mut pending = std::mem::take(&mut self.pending);
        let mut client = pending.swap_remove(index);
        client.decoder = Some(hpack::Decoder::new(cx.limits.hpack())?);
        self.startup = startup;
        self.dirs[CLIENT] = Some(client);
        for mut dir in pending {
            if !dir.buffer.is_empty() {
                self.clean_start = false;
            }
            dir.decoder = Some(hpack::Decoder::new(cx.limits.hpack())?);
            dir.phase = match startup {
                Startup::PriorKnowledge => DirPhase::Frames,
                _ => DirPhase::Prelude,
            };
            self.dirs[SERVER] = Some(dir);
        }
        Ok(())
    }

    pub(crate) fn preface_step(&mut self, side: usize, cx: &mut Cx<'_>) -> Result<bool, Error> {
        let dir = self.dirs[side].as_mut().ok_or(Error::Application(
            crate::analysis::application::Error::Sources {
                number: self.number,
            },
        ))?;
        let have = dir.buffer.len().min(PREFACE_LEN);
        if dir.buffer.bytes()[..have] != wire::CLIENT_PREFACE[..have] {
            let flow = dir.flow.clone();
            let take = dir.buffer.len();
            let sets = dir.buffer.contributors(take);
            let (wire, dropped) = dir.buffer.take(take);
            let sources = union_balanced(sets)?;
            Self::release_dir(dir, cx, take);
            Self::release_dropped(dir, dropped, cx);
            self.issue(
                cx,
                Fault {
                    flow,
                    http2_stream_id: None,
                    scope: IssueScope::Connection,
                    certainty: Certainty::Confirmed,
                    status: Status::Malformed,
                    code: "bad_preface",
                    detail: "client connection preface does not match the HTTP/2 magic".into(),
                    wire,
                    sources,
                },
            )?;
            self.fail(cx, Status::Malformed)?;
            return Ok(true);
        }
        if dir.buffer.len() < PREFACE_LEN {
            return Ok(false);
        }
        let dropped = dir.buffer.discard(PREFACE_LEN);
        Self::release_dir(dir, cx, PREFACE_LEN);
        Self::release_dropped(dir, dropped, cx);
        if let Some(dir) = self.dirs[side].as_mut() {
            dir.phase = DirPhase::Frames;
        }
        Ok(true)
    }
}
