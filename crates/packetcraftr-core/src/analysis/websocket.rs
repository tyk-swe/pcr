// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded RFC 6455 messages from one reassembled TCP stream. Negotiated
//! compression is deliberately refused; payload bytes remain exact.
use super::{
    FrameRecord, StreamRef, StreamTransport, Summary as RunSummary,
    follow::{self, PeerDirection},
    session::{self, CollectorNeeds},
};
use crate::error::{BoundaryError, Classification, Kind};
use bytes::Bytes;

const INTERRUPTED: &str = "TCP gap or stream reuse interrupted WebSocket framing";
const HEADER_LIMIT: &str = "HTTP upgrade header limit exceeded";
const INCOMPLETE: &str = "capture ended inside a WebSocket frame or message";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_message_bytes: usize,
    pub max_buffered_bytes: usize,
    pub max_messages: usize,
    pub max_retained_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_message_bytes: 16 * 1024 * 1024,
            max_buffered_bytes: 32 * 1024 * 1024,
            max_messages: 4096,
            max_retained_bytes: 64 * 1024 * 1024,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Message {
        number: u64,
        direction: PeerDirection,
        index: u64,
        opcode: u8,
        bytes: Bytes,
    },
    Control {
        number: u64,
        direction: PeerDirection,
        opcode: u8,
        bytes: Bytes,
    },
    Issue {
        number: u64,
        direction: PeerDirection,
        reason: String,
    },
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub messages: u64,
    pub control_frames: u64,
    pub incomplete_messages: u64,
    pub malformed_frames: u64,
    pub follow: follow::Summary,
}
#[derive(Debug, Default)]
struct Direction {
    buffer: Vec<u8>,
    message: Vec<u8>,
    opcode: Option<u8>,
    ready: bool,
    disabled: bool,
    generation: Option<u64>,
    expected_mask: Option<bool>,
    number: u64,
}
#[derive(Debug)]
pub struct Collector {
    follow: follow::Collector,
    limits: Limits,
    explicit_decode_as: bool,
    directions: [Direction; 2],
    summary: Summary,
    retained_bytes: usize,
}
impl Collector {
    pub fn new(
        selector: StreamRef,
        limits: Limits,
        explicit_decode_as: bool,
    ) -> Result<Self, BoundaryError> {
        if selector.transport != StreamTransport::Tcp
            || limits.max_message_bytes == 0
            || limits.max_message_bytes > 16 * 1024 * 1024
            || limits.max_buffered_bytes == 0
            || limits.max_buffered_bytes > 32 * 1024 * 1024
            || limits.max_messages == 0
            || limits.max_messages > 100_000
            || limits.max_retained_bytes == 0
            || limits.max_retained_bytes > 256 * 1024 * 1024
        {
            return Err(failure(
                "WebSocket requires a TCP stream and finite application limits",
            ));
        }
        let mut directions = [Direction::default(), Direction::default()];
        for direction in &mut directions {
            direction.ready = explicit_decode_as;
        }
        Ok(Self {
            follow: follow::Collector::new(selector),
            limits,
            explicit_decode_as,
            directions,
            summary: Summary::default(),
            retained_bytes: 0,
        })
    }
    pub fn observe(&mut self, record: &FrameRecord<'_>) -> Result<Vec<Event>, BoundaryError> {
        let mut events = Vec::new();
        for chunk in self.follow.observe(record) {
            let index = match chunk.direction {
                PeerDirection::ClientToServer => 0,
                PeerDirection::ServerToClient => 1,
            };
            let changed = self.directions[index]
                .generation
                .is_some_and(|generation| generation != chunk.direction_generation);
            if changed {
                for reset_index in [index, 1 - index] {
                    if reset_index != index
                        && self.directions[reset_index].generation
                            == Some(chunk.direction_generation)
                    {
                        continue;
                    }
                    let state = &mut self.directions[reset_index];
                    if !state.buffer.is_empty() || state.opcode.is_some() {
                        charge_event(self.limits, &mut self.retained_bytes, INTERRUPTED.len())?;
                        events.push(Event::Issue {
                            number: chunk.number,
                            direction: if reset_index == 0 {
                                PeerDirection::ClientToServer
                            } else {
                                PeerDirection::ServerToClient
                            },
                            reason: INTERRUPTED.into(),
                        });
                        self.summary.incomplete_messages += 1;
                    }
                    state.buffer.clear();
                    state.message.clear();
                    state.opcode = None;
                    state.ready = self.explicit_decode_as;
                    state.disabled = false;
                    state.expected_mask = None;
                }
            }
            let buffered = self
                .directions
                .iter()
                .map(|state| state.buffer.len().saturating_add(state.message.len()))
                .sum::<usize>();
            if buffered.saturating_add(chunk.bytes.len()) > self.limits.max_buffered_bytes {
                return Err(failure("WebSocket aggregate buffer limit exceeded"));
            }
            let state = &mut self.directions[index];
            state.number = chunk.number;
            state.generation = Some(chunk.direction_generation);
            if state.disabled {
                continue;
            }
            state.buffer.extend_from_slice(&chunk.bytes);
            if !state.ready {
                let end = state
                    .buffer
                    .windows(4)
                    .position(|bytes| bytes == b"\r\n\r\n");
                if end.map_or(state.buffer.len(), |end| end + 4)
                    > crate::protocol::application::http::MAX_HEADER_BYTES
                {
                    state.disabled = true;
                    charge_event(self.limits, &mut self.retained_bytes, HEADER_LIMIT.len())?;
                    events.push(Event::Issue {
                        number: chunk.number,
                        direction: chunk.direction,
                        reason: HEADER_LIMIT.into(),
                    });
                    self.summary.malformed_frames += 1;
                    continue;
                }
                let Some(end) = end else {
                    continue;
                };
                let head = crate::protocol::application::http::parse_head(&Bytes::copy_from_slice(
                    &state.buffer[..end + 4],
                ))
                .map_err(BoundaryError::from_error)?;
                let Some((head, _)) = head else {
                    continue;
                };
                let upgrade = head.headers.iter().any(|header| {
                    header.name.eq_ignore_ascii_case("upgrade")
                        && header.value.eq_ignore_ascii_case(b"websocket")
                });
                let connection = head.headers.iter().any(|header| {
                    header.name.eq_ignore_ascii_case("connection")
                        && header
                            .value
                            .split(|byte| *byte == b',')
                            .any(|token| token.trim_ascii().eq_ignore_ascii_case(b"upgrade"))
                });
                let start = head.method() == Some("GET") || head.status() == Some(101);
                if !upgrade || !connection || !start {
                    state.disabled = true;
                    continue;
                }
                state.ready = true;
                state.expected_mask = Some(head.method().is_some());
                state.buffer.drain(..end + 4);
            }
            if !self.explicit_decode_as && !self.directions.iter().all(|direction| direction.ready)
            {
                continue;
            }
            if !self.explicit_decode_as
                && self.directions[0].expected_mask == self.directions[1].expected_mask
            {
                Self::reject(
                    &mut self.directions[index],
                    chunk.direction,
                    "WebSocket upgrade needs one request and one response",
                    &mut events,
                    &mut self.summary,
                    self.limits,
                    &mut self.retained_bytes,
                )?;
                continue;
            }
            // Once both upgrade headers have arrived, buffered frames from either
            // peer can be delivered without losing messages sent before the response.
            for parse_index in [index, 1 - index] {
                let peer = if parse_index == 0 {
                    PeerDirection::ClientToServer
                } else {
                    PeerDirection::ServerToClient
                };
                let state = &mut self.directions[parse_index];
                if state.disabled {
                    continue;
                }
                loop {
                    if state.buffer.len() >= 2
                        && state
                            .expected_mask
                            .is_some_and(|masked| masked != (state.buffer[1] & 128 != 0))
                    {
                        Self::reject(
                            state,
                            peer,
                            "WebSocket mask does not match the HTTP upgrade role",
                            &mut events,
                            &mut self.summary,
                            self.limits,
                            &mut self.retained_bytes,
                        )?;
                        break;
                    }
                    match frame(&state.buffer, self.limits.max_message_bytes) {
                        Ok(Some((consumed, fin, opcode, payload))) => {
                            state.buffer.drain(..consumed);
                            if opcode & 8 != 0 {
                                check_messages(self.limits, &self.summary)?;
                                charge_event(self.limits, &mut self.retained_bytes, payload.len())?;
                                events.push(Event::Control {
                                    number: chunk.number,
                                    direction: peer,
                                    opcode,
                                    bytes: payload,
                                });
                                self.summary.control_frames += 1;
                                continue;
                            }
                            if opcode == 0 {
                                if state.opcode.is_none() {
                                    Self::reject(
                                        state,
                                        peer,
                                        "continuation without a message",
                                        &mut events,
                                        &mut self.summary,
                                        self.limits,
                                        &mut self.retained_bytes,
                                    )?;
                                    break;
                                }
                            } else {
                                if state.opcode.is_some() {
                                    Self::reject(
                                        state,
                                        peer,
                                        "new message before final continuation",
                                        &mut events,
                                        &mut self.summary,
                                        self.limits,
                                        &mut self.retained_bytes,
                                    )?;
                                    break;
                                }
                                state.opcode = Some(opcode);
                            }
                            if state.message.len().saturating_add(payload.len())
                                > self.limits.max_message_bytes
                            {
                                return Err(failure("WebSocket message limit exceeded"));
                            }
                            state.message.extend_from_slice(&payload);
                            if fin {
                                let opcode = state.opcode.take().expect("data frame sets opcode");
                                if opcode == 1 && std::str::from_utf8(&state.message).is_err() {
                                    Self::reject(
                                        state,
                                        peer,
                                        "text message is not UTF-8",
                                        &mut events,
                                        &mut self.summary,
                                        self.limits,
                                        &mut self.retained_bytes,
                                    )?;
                                    break;
                                }
                                check_messages(self.limits, &self.summary)?;
                                charge_event(
                                    self.limits,
                                    &mut self.retained_bytes,
                                    state.message.len(),
                                )?;
                                let bytes = Bytes::from(std::mem::take(&mut state.message));
                                events.push(Event::Message {
                                    number: chunk.number,
                                    direction: peer,
                                    index: self.summary.messages,
                                    opcode,
                                    bytes,
                                });
                                self.summary.messages += 1;
                            }
                        }
                        Ok(None) => break,
                        Err(reason) => {
                            Self::reject(
                                state,
                                peer,
                                reason,
                                &mut events,
                                &mut self.summary,
                                self.limits,
                                &mut self.retained_bytes,
                            )?;
                            break;
                        }
                    }
                }
            }
        }
        Ok(events)
    }
    fn reject(
        state: &mut Direction,
        direction: PeerDirection,
        reason: &str,
        events: &mut Vec<Event>,
        summary: &mut Summary,
        limits: Limits,
        retained_bytes: &mut usize,
    ) -> Result<(), BoundaryError> {
        charge_event(limits, retained_bytes, reason.len())?;
        state.disabled = true;
        state.buffer.clear();
        state.message.clear();
        state.opcode = None;
        summary.malformed_frames += 1;
        events.push(Event::Issue {
            number: state.number,
            direction,
            reason: reason.into(),
        });
        Ok(())
    }
    pub fn finish(mut self, run: &RunSummary) -> Result<(Vec<Event>, Summary), BoundaryError> {
        let mut events = Vec::new();
        for (index, state) in self.directions.into_iter().enumerate() {
            if !state.disabled && (!state.buffer.is_empty() || state.opcode.is_some()) {
                charge_event(self.limits, &mut self.retained_bytes, INCOMPLETE.len())?;
                self.summary.incomplete_messages += 1;
                events.push(Event::Issue {
                    number: state.number,
                    direction: if index == 0 {
                        PeerDirection::ClientToServer
                    } else {
                        PeerDirection::ServerToClient
                    },
                    reason: INCOMPLETE.into(),
                });
            }
        }
        self.summary.follow = self.follow.finish(run);
        Ok((events, self.summary))
    }
}
fn check_messages(limits: Limits, summary: &Summary) -> Result<(), BoundaryError> {
    if summary.messages.saturating_add(summary.control_frames) >= limits.max_messages as u64 {
        return Err(failure(
            "WebSocket application message count limit exceeded",
        ));
    }
    Ok(())
}
fn charge_event(limits: Limits, retained: &mut usize, bytes: usize) -> Result<(), BoundaryError> {
    let total = retained
        .saturating_add(std::mem::size_of::<Event>())
        .saturating_add(bytes);
    if total > limits.max_retained_bytes {
        return Err(failure("WebSocket retained evidence limit exceeded"));
    }
    *retained = total;
    Ok(())
}
fn failure(reason: &str) -> BoundaryError {
    BoundaryError::new(
        reason,
        Classification::new("policy.websocket_limit", Kind::Policy, None),
        Vec::new(),
    )
}
fn frame(bytes: &[u8], maximum: usize) -> Result<Option<(usize, bool, u8, Bytes)>, &'static str> {
    if bytes.len() < 2 {
        return Ok(None);
    }
    let fin = bytes[0] & 0x80 != 0;
    let opcode = bytes[0] & 15;
    if bytes[0] & 0x70 != 0 {
        return Err("WebSocket extensions or compression are unsupported");
    }
    if !matches!(opcode, 0 | 1 | 2 | 8 | 9 | 10) {
        return Err("unknown WebSocket opcode");
    }
    let mut offset = 2;
    let length = match bytes[1] & 127 {
        126 => {
            let Some(value) = bytes.get(2..4) else {
                return Ok(None);
            };
            offset = 4;
            let length = usize::from(u16::from_be_bytes([value[0], value[1]]));
            if length < 126 {
                return Err("nonminimal WebSocket length");
            }
            length
        }
        127 => {
            let Some(value) = bytes.get(2..10) else {
                return Ok(None);
            };
            offset = 10;
            let value = u64::from_be_bytes(value.try_into().expect("eight bytes"));
            if value >> 63 != 0 || value < 65536 {
                return Err("invalid WebSocket length");
            }
            usize::try_from(value).map_err(|_| "WebSocket length exceeds platform size")?
        }
        n => usize::from(n),
    };
    if length > maximum {
        return Err("WebSocket frame length exceeds message limit");
    }
    if opcode & 8 != 0 && (!fin || length > 125 || opcode == 8 && length == 1) {
        return Err("invalid WebSocket control frame");
    }
    let mask = if bytes[1] & 128 != 0 {
        let Some(mask) = bytes.get(offset..offset + 4) else {
            return Ok(None);
        };
        offset += 4;
        Some(mask)
    } else {
        None
    };
    let Some(payload) = bytes.get(offset..offset + length) else {
        return Ok(None);
    };
    let bytes = if let Some(mask) = mask {
        Bytes::from(
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask[index % 4])
                .collect::<Vec<_>>(),
        )
    } else {
        Bytes::copy_from_slice(payload)
    };
    Ok(Some((offset + length, fin, opcode, bytes)))
}
impl session::Collector for Collector {
    type Event = Event;
    type Summary = Summary;
    fn needs(&self) -> CollectorNeeds {
        CollectorNeeds {
            tcp_stream: true,
            tcp_events: true,
            ..CollectorNeeds::default()
        }
    }
    fn observe(&mut self, record: &FrameRecord<'_>) -> Result<Vec<Event>, BoundaryError> {
        Self::observe(self, record)
    }
    fn finish(self, run: &RunSummary) -> Result<(Vec<Event>, Summary), BoundaryError> {
        Self::finish(self, run)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unmasks_exact_payload_and_checks_control_and_lengths() {
        let packet = [0x81, 0x83, 1, 2, 3, 4, b'a' ^ 1, b'b' ^ 2, b'c' ^ 3];
        let (_, fin, opcode, bytes) = frame(&packet, 100).unwrap().unwrap();
        assert!(fin);
        assert_eq!(opcode, 1);
        assert_eq!(bytes.as_ref(), b"abc");
        for length in 0..packet.len() {
            assert!(frame(&packet[..length], 100).unwrap().is_none());
        }
        assert!(frame(&[0x09, 0], 100).is_err());
        assert!(frame(&[0x81, 126, 0, 1, 0], 100).is_err());
        assert!(frame(&[0xc1, 0], 100).is_err());
    }
}
