// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;

use super::{Error, Frame, FrameHeader, Limit, Payload, Priority, Setting};

const HEADER_LEN: usize = 9;

const TYPE_DATA: u8 = 0x0;
const TYPE_HEADERS: u8 = 0x1;
const TYPE_PRIORITY: u8 = 0x2;
const TYPE_RESET: u8 = 0x3;
const TYPE_SETTINGS: u8 = 0x4;
const TYPE_PUSH_PROMISE: u8 = 0x5;
const TYPE_PING: u8 = 0x6;
const TYPE_GOAWAY: u8 = 0x7;
const TYPE_WINDOW_UPDATE: u8 = 0x8;
const TYPE_CONTINUATION: u8 = 0x9;

const FLAG_ACK: u8 = 0x1;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;

pub fn parse_frame(input: &Bytes, max_frame_bytes: usize) -> Result<Option<(Frame, usize)>, Error> {
    parse_frame_inner(input, max_frame_bytes, false)
}

pub(crate) fn parse_frame_for_analysis(
    input: &Bytes,
    max_frame_bytes: usize,
) -> Result<Option<(Frame, usize)>, Error> {
    parse_frame_inner(input, max_frame_bytes, true)
}

fn parse_frame_inner(
    input: &Bytes,
    max_frame_bytes: usize,
    allow_stream_errors: bool,
) -> Result<Option<(Frame, usize)>, Error> {
    if input.len() < HEADER_LEN {
        return Ok(None);
    }
    let header = FrameHeader {
        length: u32::from_be_bytes([0, input[0], input[1], input[2]]),
        frame_type: input[3],
        flags: input[4],
        reserved: input[5] & 0x80 != 0,
        stream_id: u32::from_be_bytes([input[5] & 0x7f, input[6], input[7], input[8]]),
    };
    if header.length as usize > max_frame_bytes {
        return Err(Error::Limit(Limit::FrameBytes));
    }
    check_header(&header)?;
    let total = HEADER_LEN + header.length as usize;
    if input.len() < total {
        return Ok(None);
    }
    let payload = input.slice(HEADER_LEN..total);
    let payload = parse_payload(&header, &payload, allow_stream_errors)?;
    Ok(Some((
        Frame {
            header,
            payload,
            wire: input.slice(..total),
        },
        total,
    )))
}

fn check_header(header: &FrameHeader) -> Result<(), Error> {
    if matches!(
        header.frame_type,
        TYPE_DATA
            | TYPE_HEADERS
            | TYPE_PRIORITY
            | TYPE_RESET
            | TYPE_PUSH_PROMISE
            | TYPE_CONTINUATION
    ) && header.stream_id == 0
    {
        return Err(Error::Invalid("frame requires a nonzero stream"));
    }
    if matches!(header.frame_type, TYPE_SETTINGS | TYPE_PING | TYPE_GOAWAY) && header.stream_id != 0
    {
        return Err(Error::Invalid("frame requires stream zero"));
    }
    let fixed = match header.frame_type {
        TYPE_PRIORITY => Some(5),
        TYPE_RESET | TYPE_WINDOW_UPDATE => Some(4),
        TYPE_PING => Some(8),
        _ => None,
    };
    if fixed.is_some_and(|fixed| header.length != fixed) {
        return Err(Error::Invalid("frame has an invalid fixed length"));
    }
    let padded = header.flags & FLAG_PADDED != 0;
    let minimum = match header.frame_type {
        TYPE_DATA => u32::from(padded),
        TYPE_HEADERS => {
            u32::from(padded)
                + if header.flags & FLAG_PRIORITY != 0 {
                    5
                } else {
                    0
                }
        }
        TYPE_PUSH_PROMISE => u32::from(padded) + 4,
        TYPE_GOAWAY => 8,
        _ => 0,
    };
    if header.length < minimum {
        return Err(Error::Invalid("frame is shorter than its mandatory fields"));
    }
    if header.frame_type == TYPE_SETTINGS {
        if header.flags & FLAG_ACK != 0 && header.length != 0 {
            return Err(Error::Invalid("SETTINGS acknowledgment has a payload"));
        }
        if !header.length.is_multiple_of(6) {
            return Err(Error::Invalid("SETTINGS length is not a multiple of six"));
        }
    }
    Ok(())
}

fn parse_payload(
    header: &FrameHeader,
    payload: &Bytes,
    allow_stream_errors: bool,
) -> Result<Payload, Error> {
    match header.frame_type {
        TYPE_DATA => {
            let (data, padding) = split_padding(header, payload)?;
            Ok(Payload::Data {
                data: payload.slice_ref(data),
                padding: payload.slice_ref(padding),
            })
        }
        TYPE_HEADERS => {
            let (rest, padding) = split_padding(header, payload)?;
            let (priority, fragment) = if header.flags & FLAG_PRIORITY != 0 {
                let Some((fixed, rest)) = rest.split_at_checked(5) else {
                    return Err(Error::Invalid("HEADERS priority is truncated"));
                };
                (
                    Some(priority(fixed, header.stream_id, allow_stream_errors)?),
                    rest,
                )
            } else {
                (None, rest)
            };
            Ok(Payload::Headers {
                fragment: payload.slice_ref(fragment),
                priority,
                padding: payload.slice_ref(padding),
            })
        }
        TYPE_PRIORITY => Ok(Payload::Priority(priority(
            payload,
            header.stream_id,
            allow_stream_errors,
        )?)),
        TYPE_RESET => Ok(Payload::Reset {
            error_code: be32(&payload[..4]),
        }),
        TYPE_SETTINGS => {
            let (chunks, _) = payload.as_chunks::<6>();
            let mut settings = Vec::with_capacity(chunks.len());
            for chunk in chunks {
                settings.push(Setting {
                    id: u16::from_be_bytes([chunk[0], chunk[1]]),
                    value: be32(&chunk[2..]),
                });
            }
            Ok(Payload::Settings(settings))
        }
        TYPE_PUSH_PROMISE => {
            let (rest, padding) = split_padding(header, payload)?;
            let Some((promised, fragment)) = rest.split_at_checked(4) else {
                return Err(Error::Invalid(
                    "PUSH_PROMISE stream identifier is truncated",
                ));
            };
            let promised_stream_id = be32(promised) & 0x7fff_ffff;
            if promised_stream_id == 0 {
                return Err(Error::Invalid("PUSH_PROMISE promises stream zero"));
            }
            Ok(Payload::PushPromise {
                promised_stream_id,
                fragment: payload.slice_ref(fragment),
                padding: payload.slice_ref(padding),
            })
        }
        TYPE_PING => {
            let mut opaque = [0; 8];
            opaque.copy_from_slice(payload);
            Ok(Payload::Ping(opaque))
        }
        TYPE_GOAWAY => Ok(Payload::Goaway {
            last_stream_id: be32(&payload[..4]) & 0x7fff_ffff,
            error_code: be32(&payload[4..8]),
            debug: payload.slice_ref(&payload[8..]),
        }),
        TYPE_WINDOW_UPDATE => {
            let increment = be32(&payload[..4]) & 0x7fff_ffff;
            if increment == 0 && !allow_stream_errors {
                return Err(Error::Invalid("WINDOW_UPDATE has a zero increment"));
            }
            Ok(Payload::WindowUpdate { increment })
        }
        TYPE_CONTINUATION => Ok(Payload::Continuation(payload.clone())),
        _ => Ok(Payload::Unknown(payload.clone())),
    }
}

fn split_padding<'a>(
    header: &FrameHeader,
    payload: &'a Bytes,
) -> Result<(&'a [u8], &'a [u8]), Error> {
    if header.flags & FLAG_PADDED == 0 {
        return Ok((payload, &[]));
    }
    let Some((&pad_len, rest)) = payload.split_first() else {
        return Err(Error::Invalid("padded frame lacks a pad length"));
    };
    if usize::from(pad_len) > rest.len() {
        return Err(Error::Invalid("padding exceeds the frame payload"));
    }
    Ok(rest.split_at(rest.len() - usize::from(pad_len)))
}

fn priority(bytes: &[u8], stream_id: u32, allow_stream_errors: bool) -> Result<Priority, Error> {
    let raw = be32(&bytes[..4]);
    let dependency = raw & 0x7fff_ffff;
    if dependency == stream_id && !allow_stream_errors {
        return Err(Error::Invalid("priority depends on its own stream"));
    }
    Ok(Priority {
        exclusive: raw & 0x8000_0000 != 0,
        dependency,
        weight: u16::from(bytes[4]) + 1,
    })
}

fn be32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes[..4].try_into().expect("four-octet field"))
}
