// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! OPC UA TCP connection messages and SecureConversation chunk envelopes (OPC 10000-6). Secure service bodies are opaque.

use crate::codec::{DecodeContext, EncodeContext, Error};
use crate::protocol::common::{invalid, unsupported};
use crate::protocol::message::{Reader, Writer, message_codec};
use bytes::Bytes;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpcuaTcp {
    pub message_type: Bytes,
    pub chunk_type: u8,
    pub protocol_version: u32,
    pub receive_buffer: u32,
    pub send_buffer: u32,
    pub max_message_size: u32,
    pub max_chunk_count: u32,
    pub endpoint_url: Bytes,
    pub endpoint_null: bool,
    pub server_uri: Bytes,
    pub server_uri_null: bool,
    pub status_code: u32,
    pub reason: Bytes,
    pub reason_null: bool,
    pub secure_channel: u32,
    pub data: Bytes,
}
impl Default for OpcuaTcp {
    fn default() -> Self {
        Self {
            message_type: Bytes::from_static(b"HEL"),
            chunk_type: b'F',
            protocol_version: 0,
            receive_buffer: 65536,
            send_buffer: 65536,
            max_message_size: 0,
            max_chunk_count: 0,
            endpoint_url: Bytes::from_static(b"opc.tcp://localhost:4840"),
            endpoint_null: false,
            server_uri: Bytes::new(),
            server_uri_null: false,
            status_code: 0,
            reason: Bytes::new(),
            reason_null: false,
            secure_channel: 0,
            data: Bytes::new(),
        }
    }
}
crate::reflective_layer! {
 fn opcuatcp_schema() => { protocol: crate::protocol::BuiltinProtocol::OpcuaTcp.id(), name: "OpcuaTcp" }
 impl OpcuaTcp {
    "message_type" => { kind: Bytes, derived: false, required: false, description: "message type", reflect: message_type },
    "chunk_type" => { kind: Unsigned, derived: false, required: false, description: "chunk type", reflect: chunk_type },
    "protocol_version" => { kind: Unsigned, derived: false, required: false, description: "protocol version", reflect: protocol_version },
    "receive_buffer" => { kind: Unsigned, derived: false, required: false, description: "receive buffer", reflect: receive_buffer },
    "send_buffer" => { kind: Unsigned, derived: false, required: false, description: "send buffer", reflect: send_buffer },
    "max_message_size" => { kind: Unsigned, derived: false, required: false, description: "max message size", reflect: max_message_size },
    "max_chunk_count" => { kind: Unsigned, derived: false, required: false, description: "max chunk count", reflect: max_chunk_count },
    "endpoint_url" => { kind: Bytes, derived: false, required: false, description: "endpoint url", reflect: endpoint_url },
    "endpoint_null" => { kind: Bool, derived: false, required: false, description: "endpoint null", reflect: endpoint_null },
    "server_uri" => { kind: Bytes, derived: false, required: false, description: "server uri", reflect: server_uri },
    "server_uri_null" => { kind: Bool, derived: false, required: false, description: "server uri null", reflect: server_uri_null },
    "status_code" => { kind: Unsigned, derived: false, required: false, description: "status code", reflect: status_code },
    "reason" => { kind: Bytes, derived: false, required: false, description: "reason", reflect: reason },
    "reason_null" => { kind: Bool, derived: false, required: false, description: "reason null", reflect: reason_null },
    "secure_channel" => { kind: Unsigned, derived: false, required: false, description: "secure channel", reflect: secure_channel },
    "data" => { kind: Bytes, derived: false, required: false, description: "data", reflect: data },
 }
}
message_codec!(OpcuaTcpCodec, OpcuaTcp, opcuatcp_schema);

const NAME: &str = crate::protocol::BuiltinProtocol::OpcuaTcp.as_str();
impl OpcuaTcp {
    fn reject_uncarried_fields(&self) -> Result<(), Error> {
        let message_type = self.message_type.as_ref();
        let negotiation = matches!(message_type, b"HEL" | b"ACK");
        let endpoint = matches!(message_type, b"HEL" | b"RHE");
        let reverse_hello = message_type == b"RHE";
        let error = message_type == b"ERR";
        let secure = matches!(message_type, b"OPN" | b"MSG" | b"CLO");
        let defaults = Self::default();
        let fields = [
            (
                "protocol_version",
                !negotiation && self.protocol_version != 0,
            ),
            (
                "receive_buffer",
                !negotiation && self.receive_buffer != defaults.receive_buffer,
            ),
            (
                "send_buffer",
                !negotiation && self.send_buffer != defaults.send_buffer,
            ),
            (
                "max_message_size",
                !negotiation && self.max_message_size != 0,
            ),
            ("max_chunk_count", !negotiation && self.max_chunk_count != 0),
            (
                "endpoint_url",
                !endpoint && self.endpoint_url != defaults.endpoint_url,
            ),
            ("endpoint_null", !endpoint && self.endpoint_null),
            ("server_uri", !reverse_hello && !self.server_uri.is_empty()),
            ("server_uri_null", !reverse_hello && self.server_uri_null),
            ("status_code", !error && self.status_code != 0),
            ("reason", !error && !self.reason.is_empty()),
            ("reason_null", !error && self.reason_null),
            ("secure_channel", !secure && self.secure_channel != 0),
            ("data", !secure && !self.data.is_empty()),
        ];
        if let Some((field, _)) = fields.into_iter().find(|(_, uncarried)| *uncarried) {
            return Err(invalid(
                NAME,
                format!(
                    "{field} is not part of message type {}",
                    String::from_utf8_lossy(message_type)
                ),
            ));
        }
        Ok(())
    }

    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        if self.message_type.len() != 3 || !matches!(self.chunk_type, b'F' | b'C' | b'A') {
            return Err(invalid(NAME, "invalid UACP header"));
        }
        let mut p = Writer::new(NAME, c.remaining_packet_bytes);
        match self.message_type.as_ref() {
            b"HEL" | b"ACK" => {
                p.le32(self.protocol_version)?;
                p.le32(self.receive_buffer)?;
                p.le32(self.send_buffer)?;
                p.le32(self.max_message_size)?;
                p.le32(self.max_chunk_count)?;
                if self.message_type.as_ref() == b"HEL" {
                    string(&mut p, &self.endpoint_url, self.endpoint_null)?;
                }
            }
            b"ERR" => {
                p.le32(self.status_code)?;
                string(&mut p, &self.reason, self.reason_null)?;
            }
            b"RHE" => {
                string(&mut p, &self.server_uri, self.server_uri_null)?;
                string(&mut p, &self.endpoint_url, self.endpoint_null)?;
            }
            b"OPN" | b"MSG" | b"CLO" => {
                p.le32(self.secure_channel)?;
                p.put(&self.data)?;
            }
            _ => return Err(unsupported(NAME, "unknown UACP message type")),
        }
        self.reject_uncarried_fields()?;
        if !matches!(self.message_type.as_ref(), b"OPN" | b"MSG" | b"CLO")
            && self.chunk_type != b'F'
        {
            return Err(invalid(NAME, "connection message must be final"));
        }
        let mut w = Writer::new(NAME, c.remaining_packet_bytes);
        w.put(&self.message_type)?;
        w.u8(self.chunk_type)?;
        w.le32(u32::try_from(p.bytes.len() + 8).map_err(|_| invalid(NAME, "message too large"))?)?;
        w.put(&p.bytes)?;
        Ok(w.bytes)
    }
    fn parse_wire(
        b: Bytes,
        _: &DecodeContext<'_>,
    ) -> Result<(Self, Vec<crate::layout::FieldLayout>), Error> {
        let mut r = Reader::new(NAME, &b);
        r.mark(0, 0..3);
        r.mark(1, 3..4);
        let message_type = Bytes::copy_from_slice(r.take(3)?);
        let chunk_type = r.u8()?;
        if !matches!(chunk_type, b'F' | b'C' | b'A') {
            return Err(invalid(NAME, "invalid chunk type"));
        }
        if r.le32()? as usize != b.len() {
            return Err(invalid(NAME, "message size mismatch"));
        }
        let mut s = Self {
            message_type,
            chunk_type,
            ..Self::default()
        };
        match s.message_type.as_ref() {
            b"HEL" | b"ACK" => {
                s.protocol_version = r.le32()?;
                s.receive_buffer = r.le32()?;
                s.send_buffer = r.le32()?;
                s.max_message_size = r.le32()?;
                s.max_chunk_count = r.le32()?;
                if s.message_type.as_ref() == b"HEL" {
                    (s.endpoint_url, s.endpoint_null) = read_string(&mut r)?;
                }
            }
            b"ERR" => {
                s.status_code = r.le32()?;
                (s.reason, s.reason_null) = read_string(&mut r)?;
            }
            b"RHE" => {
                (s.server_uri, s.server_uri_null) = read_string(&mut r)?;
                (s.endpoint_url, s.endpoint_null) = read_string(&mut r)?;
            }
            b"OPN" | b"MSG" | b"CLO" => {
                s.secure_channel = r.le32()?;
                s.data = Bytes::copy_from_slice(r.rest());
            }
            _ => return Err(unsupported(NAME, "unknown message type")),
        }
        if !matches!(s.message_type.as_ref(), b"OPN" | b"MSG" | b"CLO") && chunk_type != b'F' {
            return Err(invalid(NAME, "connection message must be final"));
        }
        r.finish()?;
        Ok((s, r.take_layouts()))
    }
}
fn string(w: &mut Writer, b: &[u8], null: bool) -> Result<(), Error> {
    if null {
        if !b.is_empty() {
            return Err(invalid(NAME, "null string contains bytes"));
        }
        w.le32(u32::MAX)?;
    } else {
        if b.len() > i32::MAX as usize {
            return Err(invalid(NAME, "string too long"));
        }
        std::str::from_utf8(b).map_err(|_| invalid(NAME, "invalid string UTF-8"))?;
        w.le32(b.len() as u32)?;
        w.put(b)?;
    }
    Ok(())
}
fn read_string(r: &mut Reader<'_>) -> Result<(Bytes, bool), Error> {
    let n = r.le32()?;
    if n == u32::MAX {
        return Ok((Bytes::new(), true));
    }
    if n > i32::MAX as u32 {
        return Err(invalid(NAME, "invalid string length"));
    }
    let b = r.take(n as usize)?;
    std::str::from_utf8(b).map_err(|_| invalid(NAME, "invalid string UTF-8"))?;
    Ok((Bytes::copy_from_slice(b), false))
}
