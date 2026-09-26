// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::{Body, Error, Header, MAX_HEADER_BYTES, MAX_START_LINE};
use super::parse_headers;
use bytes::Bytes;

#[derive(Clone, Debug)]
enum State {
    Done,
    Length(u64),
    Close,
    ChunkLine,
    Chunk(u64),
    ChunkCr,
    ChunkLf,
    Trailers,
}
/// Incremental HTTP/1 body framing. Entity bytes are counted and discarded;
/// compression and representation decoding are outside this parser.
#[derive(Clone, Debug)]
pub struct BodyDecoder {
    state: State,
    line: Vec<u8>,
    trailer_lines: Vec<u8>,
    trailers: Vec<Header>,
    bytes: u64,
    maximum: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    pub consumed: usize,
    pub complete: bool,
}
impl BodyDecoder {
    pub fn new(body: Body, max_body_bytes: u64) -> Self {
        Self {
            state: match body {
                Body::None | Body::Tunnel | Body::Length(0) => State::Done,
                Body::Length(n) => State::Length(n),
                Body::Close => State::Close,
                Body::Chunked => State::ChunkLine,
            },
            line: Vec::new(),
            trailer_lines: Vec::new(),
            trailers: Vec::new(),
            bytes: 0,
            maximum: max_body_bytes,
        }
    }
    pub fn body_bytes(&self) -> u64 {
        self.bytes
    }
    pub fn buffered_bytes(&self) -> usize {
        self.line.len()
            + self.trailer_lines.len()
            + self
                .trailers
                .iter()
                .map(|h| h.name.len() + h.value.len())
                .sum::<usize>()
    }
    pub(crate) fn additional_buffer_bound(&self, input: usize) -> usize {
        if matches!(self.state, State::Done | State::Length(_) | State::Close) {
            0
        } else {
            input.min(MAX_HEADER_BYTES + MAX_START_LINE)
        }
    }
    pub fn trailers(&self) -> &[Header] {
        &self.trailers
    }
    pub fn complete(&self) -> bool {
        matches!(self.state, State::Done)
    }
    /// A clean TCP FIN completes a close-delimited body; reset/EOF do not.
    pub fn close(&mut self) -> bool {
        if matches!(self.state, State::Close) {
            self.state = State::Done;
        }
        self.complete()
    }
    pub fn consume(&mut self, input: &[u8]) -> Result<Progress, Error> {
        let mut offset = 0;
        while offset < input.len() && !self.complete() {
            match self.state {
                State::Done => break,
                State::Length(remaining) | State::Chunk(remaining) => {
                    let take = usize::try_from(remaining)
                        .unwrap_or(usize::MAX)
                        .min(input.len() - offset);
                    self.add(take)?;
                    offset += take;
                    let remaining = remaining - take as u64;
                    self.state = match self.state {
                        State::Length(_) => {
                            if remaining == 0 {
                                State::Done
                            } else {
                                State::Length(remaining)
                            }
                        }
                        _ => {
                            if remaining == 0 {
                                State::ChunkCr
                            } else {
                                State::Chunk(remaining)
                            }
                        }
                    };
                }
                State::Close => {
                    let take = input.len() - offset;
                    self.add(take)?;
                    offset += take;
                }
                State::ChunkCr => {
                    if input[offset] != b'\r' {
                        return Err(Error::Invalid("chunk data lacks CRLF"));
                    }
                    offset += 1;
                    self.state = State::ChunkLf;
                }
                State::ChunkLf => {
                    if input[offset] != b'\n' {
                        return Err(Error::Invalid("chunk data lacks CRLF"));
                    }
                    offset += 1;
                    self.state = State::ChunkLine;
                }
                State::ChunkLine | State::Trailers => {
                    let byte = input[offset];
                    offset += 1;
                    if self.line.len() >= MAX_START_LINE {
                        return Err(Error::Limit("chunk or trailer line"));
                    }
                    if self.line.last() == Some(&b'\r') && byte != b'\n'
                        || byte == b'\n' && self.line.last() != Some(&b'\r')
                    {
                        return Err(Error::Invalid("chunk or trailer line uses bare CR/LF"));
                    }
                    self.line.push(byte);
                    if self.line.ends_with(b"\r\n") {
                        if matches!(self.state, State::ChunkLine) {
                            let length = parse_size(&self.line[..self.line.len() - 2])?;
                            self.line.clear();
                            self.state = if length == 0 {
                                State::Trailers
                            } else {
                                State::Chunk(length)
                            };
                            if length > self.maximum.saturating_sub(self.bytes) {
                                return Err(Error::Limit("body bytes"));
                            }
                        } else if self.line.len() == 2 {
                            self.trailers =
                                parse_headers(&Bytes::copy_from_slice(&self.trailer_lines))?;
                            if self.trailers.iter().any(|h| {
                                ["content-length", "transfer-encoding", "host"]
                                    .iter()
                                    .any(|name| h.name.eq_ignore_ascii_case(name))
                            }) {
                                return Err(Error::Invalid("trailer changes framing or routing"));
                            }
                            self.line.clear();
                            self.trailer_lines.clear();
                            self.state = State::Done;
                        } else {
                            if self.trailer_lines.len().saturating_add(self.line.len())
                                > MAX_HEADER_BYTES
                            {
                                return Err(Error::Limit("trailer bytes"));
                            }
                            self.trailer_lines.append(&mut self.line);
                        }
                    }
                }
            }
        }
        Ok(Progress {
            consumed: offset,
            complete: self.complete(),
        })
    }
    fn add(&mut self, bytes: usize) -> Result<(), Error> {
        self.bytes = self
            .bytes
            .checked_add(bytes as u64)
            .filter(|n| *n <= self.maximum)
            .ok_or(Error::Limit("body bytes"))?;
        Ok(())
    }
}
fn parse_size(input: &[u8]) -> Result<u64, Error> {
    let (size, extension) = match input.iter().position(|b| *b == b';') {
        // Whitespace between the size and the extension delimiter is
        // recipient-tolerated; whitespace inside the digits still fails.
        Some(i) => {
            let size = &input[..i];
            let end = size
                .iter()
                .rposition(|b| !matches!(b, b' ' | b'\t'))
                .map_or(0, |i| i + 1);
            (&size[..end], &input[i + 1..])
        }
        None => (input, &[][..]),
    };
    if size.is_empty() || size.len() > 16 || !size.iter().all(u8::is_ascii_hexdigit) {
        return Err(Error::Invalid("chunk size is not bounded hexadecimal"));
    }
    // Extensions are opaque but must have balanced quotes and no control bytes.
    let (mut quoted, mut escaped) = (false, false);
    for byte in extension {
        if (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f {
            return Err(Error::Invalid("chunk extension contains a control byte"));
        }
        if escaped {
            escaped = false;
            continue;
        }
        if quoted && *byte == b'\\' {
            escaped = true;
        } else if *byte == b'"' {
            quoted = !quoted;
        }
    }
    if quoted || escaped {
        return Err(Error::Invalid("chunk extension has an unterminated quote"));
    }
    size.iter()
        .try_fold(0u64, |n, b| {
            n.checked_mul(16)?.checked_add(u64::from(match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                _ => b - b'A' + 10,
            }))
        })
        .ok_or(Error::Invalid("chunk size overflows"))
}
