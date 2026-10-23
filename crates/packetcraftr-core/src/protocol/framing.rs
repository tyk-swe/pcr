// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Incremental message boundaries; never treats a TCP segment as a message boundary.

use super::common::{invalid, truncated, unsupported};
use crate::codec::Error as CodecError;

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error(transparent)]
    Codec(#[from] CodecError),
    #[error("message exceeds application buffer limit {limit}")]
    BufferLimit { limit: usize },
}

#[derive(Default)]
struct Resp {
    pos: usize,
    scan: usize,
    remaining: Vec<usize>,
    bulk_end: Option<usize>,
    nodes: usize,
}

pub(crate) struct Framer {
    name: &'static str,
    expected: Option<usize>,
    scan: usize,
    resp: Resp,
}

impl Framer {
    pub(crate) fn new(name: &'static str) -> Self {
        Self {
            name,
            expected: None,
            scan: 0,
            resp: Resp::default(),
        }
    }
    pub(crate) fn progress(&mut self, b: &[u8], maximum: usize) -> Result<Option<usize>, Error> {
        let n = self.name;
        if let Some(end) = self.expected {
            return Self::ready(b, end, maximum);
        }
        let len = match n {
            "eap" | "ppp_lcp" | "ppp_ipcp" | "ppp_ipv6cp" => {
                if b.len() < 4 {
                    return Ok(None);
                }
                let len = usize::from(u16::from_be_bytes([b[2], b[3]]));
                if len < 4 {
                    return Err(invalid(n, "short control message").into());
                }
                len
            }
            "lacp" => {
                let Some(&subtype) = b.first() else {
                    return Ok(None);
                };
                if subtype != 1 || b.get(1).is_some_and(|version| *version != 1) {
                    return Err(unsupported(
                        n,
                        "unsupported Slow Protocol subtype or LACP version",
                    )
                    .into());
                }
                110
            }
            "mqtt" => {
                if b.len() < 2 {
                    return Ok(None);
                }
                // Remaining Length is shared by MQTT versions. Packet-type
                // validation belongs to the selected version's decoder.
                let mut length = 0usize;
                let mut end = None;
                for i in 0..4 {
                    let Some(&v) = b.get(i + 1) else {
                        return Ok(None);
                    };
                    length += usize::from(v & 127) << (7 * i);
                    if v & 128 == 0 {
                        if i > 0 && v == 0 {
                            return Err(unsupported(n, "noncanonical remaining length").into());
                        }
                        end = Some(length + i + 2);
                        break;
                    }
                }
                end.ok_or_else(|| invalid(n, "remaining length exceeds four bytes"))?
            }
            "amqp" if b.starts_with(b"AMQP") => 8,
            "amqp" => {
                if b.len() < 7 {
                    return Ok(None);
                }
                usize::try_from(u32::from_be_bytes(b[3..7].try_into().unwrap()))
                    .map_err(|_| invalid(n, "length overflow"))?
                    .checked_add(8)
                    .ok_or_else(|| invalid(n, "length overflow"))?
            }
            "bgp" => {
                if b.len() < 19 {
                    return Ok(None);
                }
                let l = usize::from(u16::from_be_bytes([b[16], b[17]]));
                if !(19..=4096).contains(&l) {
                    return Err(invalid(n, "BGP length outside 19..4096").into());
                }
                l
            }
            "ldap" => match ber_length(b, n)? {
                Some(v) => v,
                None => return Ok(None),
            },
            "resp" => return self.resp.progress(b, maximum),
            "sip" | "rtsp" => {
                if n == "rtsp" && b.first() == Some(&b'$') {
                    if b.len() < 4 {
                        return Ok(None);
                    }
                    4 + usize::from(u16::from_be_bytes([b[2], b[3]]))
                } else {
                    let start = self.scan.saturating_sub(3);
                    let Some(offset) = b[start..].windows(4).position(|s| s == b"\r\n\r\n") else {
                        self.scan = b.len();
                        if b.len() > 65536 {
                            return Err(invalid(n, "header exceeds 65536 bytes").into());
                        }
                        return Ok(None);
                    };
                    let end = start + offset + 4;
                    let length = super::application::text_message::content_length(n, &b[..end])?;
                    // SIP stream messages require an explicit length. RTSP bodies default to empty.
                    if n == "sip" && length.is_none() {
                        return Err(invalid(n, "SIP over TCP requires Content-Length").into());
                    }
                    end.checked_add(length.unwrap_or(0))
                        .ok_or_else(|| invalid(n, "length overflow"))?
                }
            }
            "memcached" => {
                if b.first().is_some_and(|v| !matches!(*v, 0x80 | 0x81)) {
                    return Err(unsupported(n, "not Memcached binary framing").into());
                }
                if b.len() < 24 {
                    return Ok(None);
                }
                if !matches!(b[0], 0x80 | 0x81) {
                    return Err(unsupported(n, "not Memcached binary framing").into());
                }
                (u32::from_be_bytes(b[8..12].try_into().unwrap()) as usize)
                    .checked_add(24)
                    .ok_or_else(|| invalid(n, "length overflow"))?
            }
            "ipfix" => {
                if b.len() < 4 {
                    return Ok(None);
                }
                let l = usize::from(u16::from_be_bytes([b[2], b[3]]));
                if l < 16 {
                    return Err(invalid(n, "short IPFIX header").into());
                }
                l
            }
            "radius" => {
                if b.len() < 4 {
                    return Ok(None);
                }
                let len = usize::from(u16::from_be_bytes([b[2], b[3]]));
                if !(20..=4096).contains(&len) {
                    return Err(invalid(n, "RADIUS length outside 20..4096").into());
                }
                len
            }
            "stun" => {
                if b.len() < 20 {
                    return Ok(None);
                }
                20 + usize::from(u16::from_be_bytes([b[2], b[3]]))
            }
            "modbus_tcp" => {
                if b.len() < 7 {
                    return Ok(None);
                }
                let l = usize::from(u16::from_be_bytes([b[4], b[5]]));
                if !(2..=254).contains(&l) {
                    return Err(invalid(n, "invalid MBAP length").into());
                }
                6 + l
            }
            "dnp3" => {
                if b.len() < 3 {
                    return Ok(None);
                }
                if b[..2] != [5, 100] || b[2] < 5 {
                    return Err(invalid(n, "invalid DNP3 link prefix").into());
                }
                let payload = usize::from(b[2]) - 5;
                10 + payload + payload.div_ceil(16) * 2
            }
            "ethernet_ip" => {
                if b.len() < 24 {
                    return Ok(None);
                }
                24 + usize::from(u16::from_le_bytes([b[2], b[3]]))
            }
            "iec104" => {
                if b.len() < 2 {
                    return Ok(None);
                }
                if b[0] != 0x68 || !(4..=253).contains(&b[1]) {
                    return Err(invalid(n, "invalid APDU length").into());
                }
                2 + usize::from(b[1])
            }
            "opcua_tcp" => {
                if b.len() < 8 {
                    return Ok(None);
                }
                let l = u32::from_le_bytes(b[4..8].try_into().unwrap()) as usize;
                if l < 8 {
                    return Err(invalid(n, "short UACP message").into());
                }
                l
            }
            _ => return Ok(Some(b.len())),
        };
        self.expected = Some(len);
        Self::ready(b, len, maximum)
    }
    fn ready(b: &[u8], len: usize, max: usize) -> Result<Option<usize>, Error> {
        if len > max {
            return Err(Error::BufferLimit { limit: max });
        }
        Ok((b.len() >= len).then_some(len))
    }
}

pub(crate) fn packet_length(
    name: &'static str,
    b: &[u8],
    parent: Option<crate::layer::Id>,
) -> Result<usize, CodecError> {
    if name == "sip" && parent == Some(crate::layer::Id::new("udp")) {
        return super::application::text_message::datagram_length(name, b);
    }
    Framer::new(name)
        .progress(b, usize::MAX)
        .map_err(|error| match error {
            Error::Codec(error) => error,
            Error::BufferLimit { .. } => invalid(name, "message exceeds framing byte budget"),
        })?
        .ok_or_else(|| truncated(name, b.len().saturating_add(1), b.len()))
}

pub(crate) fn ber_length(b: &[u8], name: &'static str) -> Result<Option<usize>, CodecError> {
    if b.len() < 2 {
        return Ok(None);
    }
    if b[0] & 31 == 31 {
        return Err(unsupported(name, "high-tag-number BER is not supported"));
    }
    let (head, len) = if b[1] < 128 {
        (2, usize::from(b[1]))
    } else {
        let count = usize::from(b[1] & 127);
        if count == 0 {
            return Err(unsupported(name, "indefinite BER length"));
        }
        if count > 4 {
            return Err(invalid(name, "BER length is too wide"));
        }
        if b.len() < count + 2 {
            return Ok(None);
        }
        let len = b[2..2 + count]
            .iter()
            .fold(0usize, |n, v| n * 256 + usize::from(*v));
        if b[2] == 0 || len < 128 {
            return Err(unsupported(name, "noncanonical BER length"));
        }
        (count + 2, len)
    };
    head.checked_add(len)
        .map(Some)
        .ok_or_else(|| invalid(name, "BER length overflow"))
}

impl Resp {
    fn done(&mut self) -> bool {
        while let Some(left) = self.remaining.last_mut() {
            *left -= 1;
            if *left != 0 {
                return false;
            }
            self.remaining.pop();
        }
        true
    }
    fn progress(&mut self, b: &[u8], max: usize) -> Result<Option<usize>, Error> {
        loop {
            if let Some(end) = self.bulk_end {
                if end > max {
                    return Err(Error::BufferLimit { limit: max });
                }
                if b.len() < end {
                    return Ok(None);
                }
                if b[end - 2..end] != *b"\r\n" {
                    return Err(invalid("resp", "bulk string lacks CRLF").into());
                }
                self.pos = end;
                self.scan = end;
                self.bulk_end = None;
                if self.done() {
                    return Ok(Some(end));
                }
            }
            let Some(&kind) = b.get(self.pos) else {
                return Ok(None);
            };
            if !matches!(kind, b'+' | b'-' | b':' | b'$' | b'*') {
                return Err(unsupported("resp", "not RESP2 framing").into());
            }
            let start = self.scan.max(self.pos + 1);
            let Some(i) = b[start..].windows(2).position(|s| s == b"\r\n") else {
                self.scan = b.len().saturating_sub(1);
                return Ok(None);
            };
            let end = start + i;
            let value = &b[self.pos + 1..end];
            self.pos = end + 2;
            self.scan = self.pos;
            self.nodes += 1;
            if self.nodes > super::message::MAX_RECORDS {
                return Err(invalid("resp", "too many values").into());
            }
            if matches!(kind, b'$' | b'*') {
                let text =
                    std::str::from_utf8(value).map_err(|_| invalid("resp", "invalid length"))?;
                let count = text
                    .parse::<i64>()
                    .map_err(|_| invalid("resp", "invalid length"))?;
                if count < -1 {
                    return Err(invalid("resp", "invalid negative length").into());
                }
                if count >= 0 && kind == b'$' {
                    self.bulk_end = Some(
                        self.pos
                            .checked_add(count as usize)
                            .and_then(|v| v.checked_add(2))
                            .ok_or_else(|| invalid("resp", "length overflow"))?,
                    );
                    continue;
                }
                if count > 0 && kind == b'*' {
                    if self.remaining.len() >= super::message::MAX_NESTING
                        || count as u64 > super::message::MAX_RECORDS as u64
                    {
                        return Err(invalid("resp", "array exceeds nesting/item limit").into());
                    }
                    self.remaining.push(count as usize);
                    continue;
                }
            } else if kind == b':' {
                std::str::from_utf8(value)
                    .ok()
                    .and_then(|v| v.parse::<i64>().ok())
                    .ok_or_else(|| invalid("resp", "invalid integer"))?;
            }
            if self.done() {
                return Ok(Some(self.pos));
            }
        }
    }
}
