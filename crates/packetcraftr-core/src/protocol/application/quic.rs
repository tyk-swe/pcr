// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use bytes::Bytes;

use crate::{
    codec::{Codec, DecodeContext, Decoded, EncodeContext, Encoded},
    diagnostic::Diagnostic,
    field::{self, WireValue},
    layer::{Layer, Raw, reflective_layer},
    layout::{ByteRange, FieldLayout},
};

use crate::protocol::application::byte_string_field;
use crate::protocol::common::{
    ValueExpectation, ensure_encode_budget, invalid, make_layer, out_of_range, protocol,
    resolve_fixed, typed_layer, wrong_type,
};

use crate::protocol::BuiltinProtocol;

const NAME: &str = BuiltinProtocol::Quic.as_str();

/// Version-negotiation supported versions retained before the rest refuse to
/// dissect as QUIC.
pub const MAX_SUPPORTED_VERSIONS: usize = 64;
/// Initial and Retry token bytes accepted on the wire.
pub const MAX_TOKEN_BYTES: usize = 16 * 1024;
/// RFC 9000 section 7.2 caps version-1 connection IDs at 20 bytes; longer IDs
/// still dissect, with a diagnostic, because invariants allow up to 255.
pub const MAX_CONNECTION_ID_BYTES: usize = 20;
/// Every Retry packet ends with a 16-byte integrity tag (RFC 9000 section 17.2.5).
pub const RETRY_INTEGRITY_TAG_BYTES: usize = 16;

/// The long-header packet types and the short-header form, as the first byte
/// and version field determine them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    VersionNegotiation,
    OneRtt,
}

impl PacketType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Initial => "initial",
            Self::ZeroRtt => "zero_rtt",
            Self::Handshake => "handshake",
            Self::Retry => "retry",
            Self::VersionNegotiation => "version_negotiation",
            Self::OneRtt => "one_rtt",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "initial" => Some(Self::Initial),
            "zero_rtt" => Some(Self::ZeroRtt),
            "handshake" => Some(Self::Handshake),
            "retry" => Some(Self::Retry),
            "version_negotiation" => Some(Self::VersionNegotiation),
            "one_rtt" | "1rtt" => Some(Self::OneRtt),
            _ => None,
        }
    }
}

display_via_as_str!(PacketType);

/// One QUIC packet header without decryption. Everything header protection
/// masks or AEAD encrypts stays opaque in [`Quic::payload`], so encoding a
/// decoded packet reproduces the datagram it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Quic {
    pub packet_type: PacketType,
    /// Long-header version; 0 in a version-negotiation packet and never
    /// written for a short header.
    pub version: u32,
    pub dcid: Bytes,
    pub scid: Bytes,
    /// Initial address-validation token, or the Retry token.
    pub token: Bytes,
    /// Retry original destination connection ID.
    pub odcid: Bytes,
    pub supported_versions: Vec<u32>,
    /// Declared packet-number-plus-protected-payload length of the packets
    /// that carry one, resolved from the payload on build.
    pub length: WireValue<u64>,
    /// Short-header spin bit, the one unprotected bit after the fixed bit.
    pub spin: bool,
    /// Raw header-protection-masked bits of the first byte, whose width
    /// depends on the packet type: four for long headers, five for short
    /// headers, six for version negotiation. The values are ciphertext.
    pub protected_bits: u8,
    /// Opaque remainder: the protected packet number and frames (long
    /// headers), the connection ID and everything protected (short headers),
    /// or the Retry integrity tag.
    pub payload: Bytes,
}

impl Default for Quic {
    fn default() -> Self {
        Self {
            packet_type: PacketType::Initial,
            version: 1,
            dcid: Bytes::new(),
            scid: Bytes::new(),
            token: Bytes::new(),
            odcid: Bytes::new(),
            supported_versions: Vec::new(),
            length: WireValue::Auto,
            spin: false,
            protected_bits: 0,
            payload: Bytes::new(),
        }
    }
}

impl Quic {
    fn is_long(&self) -> bool {
        !matches!(self.packet_type, PacketType::OneRtt)
    }

    fn first_byte(&self) -> Result<u8, &'static str> {
        if self.protected_bits > self.protected_mask() {
            return Err("protected_bits exceed the width this packet type carries");
        }
        let type_bits = match self.packet_type {
            PacketType::ZeroRtt => 0x10,
            PacketType::Handshake => 0x20,
            PacketType::Retry => 0x30,
            PacketType::Initial | PacketType::VersionNegotiation => 0x00,
            PacketType::OneRtt => {
                return Ok(0x40 | (u8::from(self.spin) << 5) | self.protected_bits);
            }
        };
        Ok(0xc0 | type_bits | self.protected_bits)
    }

    fn protected_mask(&self) -> u8 {
        match self.packet_type {
            PacketType::VersionNegotiation => 0x3f,
            PacketType::OneRtt => 0x1f,
            _ => 0x0f,
        }
    }

    /// Fields that never belong to this packet type make the packet ambiguous
    /// on the wire, so encoding refuses them instead of silently dropping.
    fn stray_fields(&self) -> Vec<&'static str> {
        let mut stray = Vec::new();
        let long_only = |stray: &mut Vec<&'static str>, present: bool, name: &'static str| {
            if present {
                stray.push(name);
            }
        };
        match self.packet_type {
            PacketType::OneRtt => {
                long_only(&mut stray, !self.dcid.is_empty(), "dcid");
                long_only(&mut stray, !self.scid.is_empty(), "scid");
                long_only(&mut stray, !self.token.is_empty(), "token");
                long_only(&mut stray, !self.odcid.is_empty(), "odcid");
                long_only(
                    &mut stray,
                    !self.supported_versions.is_empty(),
                    "supported_versions",
                );
                if self.length != WireValue::Auto {
                    stray.push("length");
                }
                long_only(&mut stray, self.version != 1, "version");
            }
            PacketType::VersionNegotiation => {
                long_only(&mut stray, !self.token.is_empty(), "token");
                long_only(&mut stray, !self.odcid.is_empty(), "odcid");
                if self.length != WireValue::Auto {
                    stray.push("length");
                }
                long_only(&mut stray, !self.payload.is_empty(), "payload");
                long_only(&mut stray, self.version != 0, "version");
            }
            PacketType::Initial => {
                long_only(&mut stray, !self.odcid.is_empty(), "odcid");
                long_only(
                    &mut stray,
                    !self.supported_versions.is_empty(),
                    "supported_versions",
                );
                long_only(&mut stray, self.version == 0, "version");
            }
            PacketType::Retry => {
                long_only(
                    &mut stray,
                    !self.supported_versions.is_empty(),
                    "supported_versions",
                );
                long_only(&mut stray, self.version == 0, "version");
                if self.length != WireValue::Auto {
                    stray.push("length");
                }
            }
            PacketType::ZeroRtt | PacketType::Handshake => {
                long_only(&mut stray, !self.token.is_empty(), "token");
                long_only(&mut stray, !self.odcid.is_empty(), "odcid");
                long_only(
                    &mut stray,
                    !self.supported_versions.is_empty(),
                    "supported_versions",
                );
                long_only(&mut stray, self.version == 0, "version");
            }
        }
        stray
    }
}

/// What the first bytes say about a datagram offered to the QUIC parser.
#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
    /// One QUIC packet and the datagram bytes its header covers. Coalesced
    /// packets follow outside the covered length.
    Packet(Box<Quic>, usize),
    /// The datagram does not carry the QUIC fixed bit or a whole header, so it
    /// stays raw instead of claiming a protocol it cannot prove.
    NotQuic,
    /// Clearly QUIC, but the wire breaks a rule the parser enforces.
    Malformed(&'static str),
}

/// Parses one QUIC packet header (RFC 9000 sections 7.2 and 17) without
/// removing header protection or decrypting anything.
#[must_use]
pub fn parse(input: &Bytes) -> Parsed {
    let Some(&first) = input.first() else {
        return Parsed::NotQuic;
    };
    // The fixed bit is the only always-clear identifier; without it the
    // datagram cannot be called QUIC.
    if first & 0x40 == 0 {
        return Parsed::NotQuic;
    }
    if first & 0x80 == 0 {
        // Short header: the destination connection ID length is connection
        // state, never on the wire, so the remainder stays opaque. The packet
        // number is mandatory, so a single byte cannot be a real packet.
        if input.len() < 2 {
            return Parsed::NotQuic;
        }
        return Parsed::Packet(
            Box::new(Quic {
                packet_type: PacketType::OneRtt,
                spin: first & 0x20 != 0,
                protected_bits: first & 0x1f,
                payload: input.slice(1..),
                ..Quic::default()
            }),
            input.len(),
        );
    }
    if input.len() < 5 {
        return Parsed::NotQuic;
    }
    let version = u32::from_be_bytes([input[1], input[2], input[3], input[4]]);
    let protected_bits = if version == 0 {
        first & 0x3f
    } else {
        first & 0x0f
    };
    let Some((dcid, scid, cursor)) = connection_ids(input) else {
        return Parsed::Malformed("truncated within the connection IDs");
    };
    if version == 0 {
        return version_negotiation(input, dcid, scid, protected_bits, cursor);
    }
    match (first >> 4) & 3 {
        0 => initial(input, version, dcid, scid, protected_bits, cursor),
        1 | 2 => protected_packet(
            input,
            if (first >> 4) & 3 == 1 {
                PacketType::ZeroRtt
            } else {
                PacketType::Handshake
            },
            version,
            dcid,
            scid,
            protected_bits,
            cursor,
        ),
        _ => retry(input, version, dcid, scid, protected_bits, cursor),
    }
}

/// The two length-prefixed connection IDs and the offset after them.
type ConnectionIds = (Bytes, Bytes, usize);

fn connection_ids(input: &Bytes) -> Option<ConnectionIds> {
    let dcid_len = usize::from(*input.get(5)?);
    let dcid_end = 6 + dcid_len;
    let scid_len = usize::from(*input.get(dcid_end)?);
    let scid_end = dcid_end + 1 + scid_len;
    if input.len() < scid_end {
        return None;
    }
    Some((
        input.slice(6..dcid_end),
        input.slice(dcid_end + 1..scid_end),
        scid_end,
    ))
}

fn version_negotiation(
    input: &Bytes,
    dcid: Bytes,
    scid: Bytes,
    protected_bits: u8,
    cursor: usize,
) -> Parsed {
    let rest = input.len() - cursor;
    if rest == 0 || !rest.is_multiple_of(4) {
        return Parsed::Malformed(
            "version negotiation list is empty or not a multiple of four bytes",
        );
    }
    if rest / 4 > MAX_SUPPORTED_VERSIONS {
        return Parsed::Malformed(
            "version negotiation exceeds the supported-version retention limit",
        );
    }
    let supported_versions = input[cursor..]
        .as_chunks::<4>()
        .0
        .iter()
        .map(|chunk| u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect();
    Parsed::Packet(
        Box::new(Quic {
            packet_type: PacketType::VersionNegotiation,
            version: 0,
            dcid,
            scid,
            supported_versions,
            protected_bits,
            ..Quic::default()
        }),
        input.len(),
    )
}

fn initial(
    input: &Bytes,
    version: u32,
    dcid: Bytes,
    scid: Bytes,
    protected_bits: u8,
    cursor: usize,
) -> Parsed {
    let Some((token_length, token_width)) = read_varint(&input[cursor..]) else {
        return Parsed::Malformed("truncated or non-canonical token length");
    };
    if token_length > u64::try_from(MAX_TOKEN_BYTES).unwrap_or(u64::MAX) {
        return Parsed::Malformed("token exceeds the token byte limit");
    }
    let token_start = cursor + token_width;
    let Some(token_end) =
        token_start.checked_add(usize::try_from(token_length).unwrap_or(usize::MAX))
    else {
        return Parsed::Malformed("token length overflows the datagram");
    };
    if token_end > input.len() {
        return Parsed::Malformed("truncated within the token");
    }
    let Some((length, length_width)) = read_varint(&input[token_end..]) else {
        return Parsed::Malformed("truncated or non-canonical payload length");
    };
    payload_packet(
        input,
        PacketType::Initial,
        version,
        dcid,
        scid,
        input.slice(token_start..token_end),
        protected_bits,
        length,
        token_end + length_width,
    )
}

fn protected_packet(
    input: &Bytes,
    packet_type: PacketType,
    version: u32,
    dcid: Bytes,
    scid: Bytes,
    protected_bits: u8,
    cursor: usize,
) -> Parsed {
    let Some((length, length_bytes)) = read_varint(&input[cursor..]) else {
        return Parsed::Malformed("truncated or non-canonical payload length");
    };
    payload_packet(
        input,
        packet_type,
        version,
        dcid,
        scid,
        Bytes::new(),
        protected_bits,
        length,
        cursor + length_bytes,
    )
}

#[allow(clippy::too_many_arguments)]
fn payload_packet(
    input: &Bytes,
    packet_type: PacketType,
    version: u32,
    dcid: Bytes,
    scid: Bytes,
    token: Bytes,
    protected_bits: u8,
    length: u64,
    payload_start: usize,
) -> Parsed {
    let Some(payload_end) =
        payload_start.checked_add(usize::try_from(length).unwrap_or(usize::MAX))
    else {
        return Parsed::Malformed("payload length overflows the datagram");
    };
    if length == 0 {
        return Parsed::Malformed("packet declares an empty protected payload");
    }
    if payload_end > input.len() {
        return Parsed::Malformed("declared payload length exceeds the datagram");
    }
    Parsed::Packet(
        Box::new(Quic {
            packet_type,
            version,
            dcid,
            scid,
            token,
            length: WireValue::Exact(length),
            protected_bits,
            payload: input.slice(payload_start..payload_end),
            ..Quic::default()
        }),
        payload_end,
    )
}

fn retry(
    input: &Bytes,
    version: u32,
    dcid: Bytes,
    scid: Bytes,
    protected_bits: u8,
    cursor: usize,
) -> Parsed {
    let Some(&odcid_len) = input.get(cursor) else {
        return Parsed::Malformed("truncated before the original connection ID length");
    };
    let odcid_end = cursor + 1 + usize::from(odcid_len);
    if odcid_end > input.len() {
        return Parsed::Malformed("truncated within the original connection ID");
    }
    let rest_start = odcid_end;
    if input.len() < rest_start + RETRY_INTEGRITY_TAG_BYTES {
        return Parsed::Malformed("retry is shorter than its integrity tag");
    }
    let token_end = input.len() - RETRY_INTEGRITY_TAG_BYTES;
    if token_end - rest_start > MAX_TOKEN_BYTES {
        return Parsed::Malformed("retry token exceeds the token byte limit");
    }
    Parsed::Packet(
        Box::new(Quic {
            packet_type: PacketType::Retry,
            version,
            dcid,
            scid,
            token: input.slice(rest_start..token_end),
            odcid: input.slice(cursor + 1..odcid_end),
            protected_bits,
            payload: input.slice(token_end..),
            ..Quic::default()
        }),
        input.len(),
    )
}

/// A canonical QUIC variable-length integer (RFC 9000 section 16) and its
/// width in bytes. Non-canonical encodings parse as malformed, keeping
/// re-encoding byte-exact.
fn read_varint(input: &[u8]) -> Option<(u64, usize)> {
    let first = *input.first()?;
    let length = 1_usize << (first >> 6);
    let raw = input.get(..length)?;
    let mut value = u64::from(first & 0x3f);
    for &byte in &raw[1..] {
        value = (value << 8) | u64::from(byte);
    }
    if write_varint(value).is_some_and(|encoded| encoded.as_slice() != raw) {
        return None;
    }
    Some((value, length))
}

/// The canonical encoding of a QUIC variable-length integer, if it fits.
fn write_varint(value: u64) -> Option<Vec<u8>> {
    let width = if value < 1 << 6 {
        0
    } else if value < 1 << 14 {
        1
    } else if value < 1 << 30 {
        2
    } else if value < 1 << 62 {
        3
    } else {
        return None;
    };
    let mut encoded = vec![0_u8; 1_usize << width];
    encoded[0] = (width as u8) << 6;
    encoded[0] |= (value >> (8 * ((1_usize << width) - 1))) as u8 & 0x3f;
    for (index, byte) in encoded.iter_mut().enumerate().skip(1) {
        let shift = 8 * ((1_usize << width) - 1 - index);
        *byte = (value >> shift) as u8;
    }
    Some(encoded)
}

fn set_packet_type(layer: &mut Quic, value: field::Value, name: &str) -> Result<(), field::Error> {
    let field::Value::Text(text) = value else {
        return Err(wrong_type(
            quic_schema(),
            name,
            "initial, zero_rtt, handshake, retry, version_negotiation, or one_rtt",
        ));
    };
    let packet_type =
        PacketType::from_name(&text).ok_or_else(|| out_of_range(quic_schema(), name))?;
    // Naming only the type still encodes: the default version follows it, so a
    // version negotiation is never rejected for keeping the default version 1.
    if packet_type == PacketType::VersionNegotiation && layer.version == 1 {
        layer.version = 0;
    } else if layer.version == 0 && packet_type != PacketType::VersionNegotiation {
        layer.version = 1;
    }
    layer.packet_type = packet_type;
    Ok(())
}

fn set_supported_versions(
    layer: &mut Quic,
    value: field::Value,
    name: &str,
) -> Result<(), field::Error> {
    let field::Value::List(values) = value else {
        return Err(wrong_type(quic_schema(), name, "a list of versions"));
    };
    if values.len() > MAX_SUPPORTED_VERSIONS {
        return Err(out_of_range(quic_schema(), name));
    }
    let mut versions = Vec::with_capacity(values.len());
    for value in values {
        let field::Value::Unsigned(value) = value else {
            return Err(wrong_type(quic_schema(), name, "a list of versions"));
        };
        versions.push(u32::try_from(value).map_err(|_| out_of_range(quic_schema(), name))?);
    }
    layer.supported_versions = versions;
    Ok(())
}

fn bytes_field(
    schema: &'static crate::layer::Schema,
    value: field::Value,
    name: &str,
) -> Result<Bytes, field::Error> {
    byte_string_field(schema, value, name)
}

reflective_layer! {
    fn quic_schema() => { protocol: protocol(NAME), name: "QUIC" }
    impl Quic {
        "type" => {
            kind: Text, derived: false, required: false,
            description: "Packet type: initial, zero_rtt, handshake, retry, version_negotiation, or one_rtt",
            get |layer| Some(field::Value::Text(layer.packet_type.as_str().to_owned())),
            set |layer, value, name| set_packet_type(layer, value, name)
        },
        "version" => { kind: Unsigned, derived: false, required: false, description: "Long-header version; zero in version negotiation", reflect: version },
        "dcid" => {
            kind: Bytes, derived: false, required: false,
            description: "Destination connection ID, verbatim",
            get |layer| Some(field::Value::Bytes(layer.dcid.clone())),
            set |layer, value, name| { layer.dcid = bytes_field(quic_schema(), value, name)?; Ok(()) }
        },
        "scid" => {
            kind: Bytes, derived: false, required: false,
            description: "Source connection ID, verbatim",
            get |layer| Some(field::Value::Bytes(layer.scid.clone())),
            set |layer, value, name| { layer.scid = bytes_field(quic_schema(), value, name)?; Ok(()) }
        },
        "token" => {
            kind: Bytes, derived: false, required: false,
            description: "Initial address-validation token, or the Retry token, verbatim",
            get |layer| Some(field::Value::Bytes(layer.token.clone())),
            set |layer, value, name| { layer.token = bytes_field(quic_schema(), value, name)?; Ok(()) }
        },
        "odcid" => {
            kind: Bytes, derived: false, required: false,
            description: "Retry original destination connection ID, verbatim",
            get |layer| Some(field::Value::Bytes(layer.odcid.clone())),
            set |layer, value, name| { layer.odcid = bytes_field(quic_schema(), value, name)?; Ok(()) }
        },
        "supported_versions" => {
            kind: List, derived: false, required: false,
            description: "Version negotiation supported versions, in wire order",
            get |layer| Some(field::Value::List(layer.supported_versions.iter().copied().map(field::Value::from).collect())),
            set |layer, value, name| set_supported_versions(layer, value, name)
        },
        "length" => {
            kind: Unsigned, derived: true, required: false,
            description: "Protected packet number and payload length of the packets that carry one",
            reflect: length
        },
        "spin" => { kind: Bool, derived: false, required: false, description: "Short-header spin bit, the one unprotected bit after the fixed bit", reflect: spin },
        "protected_bits" => {
            kind: Unsigned, derived: false, required: false,
            description: "Raw header-protection-masked first-byte bits, whose width depends on the packet type",
            reflect_bounded: protected_bits, 63_u16
        },
        "payload" => {
            kind: Bytes, derived: false, required: false,
            description: "Opaque remainder: protected packet number and frames, the short-header connection ID and protected bytes, or the Retry integrity tag",
            get |layer| Some(field::Value::Bytes(layer.payload.clone())),
            set |layer, value, name| { layer.payload = bytes_field(quic_schema(), value, name)?; Ok(()) }
        },
    }
    layout fn quic_static_layout();
}

/// Byte ranges of every field this packet's shape carries on the wire.
fn quic_layout(layer: &Quic) -> Vec<FieldLayout> {
    let mut fields = quic_static_layout();
    let byte_zero = ByteRange::new(0, 1);
    // Fields sorted by range start: see reflective_layer for the convention.
    let push = |fields: &mut Vec<FieldLayout>, name: &'static str, range: ByteRange| {
        fields.push(FieldLayout { name, range });
    };
    if !layer.is_long() {
        push(&mut fields, "type", byte_zero);
        push(&mut fields, "spin", byte_zero);
        push(&mut fields, "protected_bits", byte_zero);
        if !layer.payload.is_empty() {
            push(
                &mut fields,
                "payload",
                ByteRange::new(1, 1 + layer.payload.len()),
            );
        }
        return fields;
    }
    push(&mut fields, "type", ByteRange::new(0, 5));
    push(&mut fields, "protected_bits", byte_zero);
    push(&mut fields, "version", ByteRange::new(1, 5));
    push(&mut fields, "dcid", ByteRange::new(6, 6 + layer.dcid.len()));
    let scid_start = 7 + layer.dcid.len();
    push(
        &mut fields,
        "scid",
        ByteRange::new(scid_start, scid_start + layer.scid.len()),
    );
    let cursor = scid_start + layer.scid.len();
    let length_width = |length: &WireValue<u64>| match length {
        WireValue::Exact(length) => write_varint(*length)
            .map(|encoded| encoded.len())
            .unwrap_or(0),
        WireValue::Raw(raw) => raw.len(),
        WireValue::Auto => 0,
    };
    match layer.packet_type {
        PacketType::VersionNegotiation => {
            let end = cursor + layer.supported_versions.len() * 4;
            push(
                &mut fields,
                "supported_versions",
                ByteRange::new(cursor, end),
            );
        }
        PacketType::Initial => {
            let token_width = write_varint(u64::try_from(layer.token.len()).unwrap_or(u64::MAX))
                .map(|encoded| encoded.len())
                .unwrap_or(0);
            push(
                &mut fields,
                "token",
                ByteRange::new(
                    cursor + token_width,
                    cursor + token_width + layer.token.len(),
                ),
            );
            let length_start = cursor + token_width + layer.token.len();
            let length = length_width(&layer.length);
            push(
                &mut fields,
                "length",
                ByteRange::new(length_start, length_start + length),
            );
            push(
                &mut fields,
                "payload",
                ByteRange::new(
                    length_start + length,
                    length_start + length + layer.payload.len(),
                ),
            );
        }
        PacketType::ZeroRtt | PacketType::Handshake => {
            let length = length_width(&layer.length);
            push(
                &mut fields,
                "length",
                ByteRange::new(cursor, cursor + length),
            );
            push(
                &mut fields,
                "payload",
                ByteRange::new(cursor + length, cursor + length + layer.payload.len()),
            );
        }
        PacketType::Retry => {
            push(
                &mut fields,
                "odcid",
                ByteRange::new(cursor + 1, cursor + 1 + layer.odcid.len()),
            );
            let token_start = cursor + 1 + layer.odcid.len();
            push(
                &mut fields,
                "token",
                ByteRange::new(token_start, token_start + layer.token.len()),
            );
            push(
                &mut fields,
                "payload",
                ByteRange::new(
                    token_start + layer.token.len(),
                    token_start + layer.token.len() + layer.payload.len(),
                ),
            );
        }
        PacketType::OneRtt => unreachable!("short headers return above"),
    }
    if !fields.is_sorted_by_key(|field| field.range.start) {
        fields.sort_by_key(|field| field.range.start);
    }
    fields
}

/// Diagnostics the codec adds for valid but noteworthy wire shapes.
fn version_one_connection_id_diagnostics(layer: &Quic) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    if layer.version == 1 {
        for (name, length) in [("dcid", layer.dcid.len()), ("scid", layer.scid.len())] {
            if length > MAX_CONNECTION_ID_BYTES {
                diagnostics.push(
                    Diagnostic::warning(
                        "decode.quic_connection_id",
                        format!(
                            "version 1 caps connection IDs at {MAX_CONNECTION_ID_BYTES} bytes, \
                             but {name} carries {length}"
                        ),
                    )
                    .at_field(name),
                );
            }
        }
    }
    diagnostics
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct QuicCodec;

impl Codec for QuicCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &quic_schema().protocol
    }

    fn accepts_decoded_protocol(&self, protocol: &crate::layer::Id) -> bool {
        matches!(protocol.as_str(), "quic" | "raw")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &EncodeContext<'_>,
    ) -> Result<Encoded, crate::codec::Error> {
        if !payload.is_empty() {
            return Err(invalid(NAME, "quic is a complete UDP payload"));
        }
        let layer = typed_layer::<Quic>(NAME, layer)?;
        if let Some(stray) = layer.stray_fields().first() {
            return Err(invalid(
                NAME,
                format!("{stray} does not belong to a {} packet", layer.packet_type),
            ));
        }
        let mut diagnostics = Vec::new();
        for name in ["dcid", "scid", "odcid"] {
            let length = match name {
                "dcid" => layer.dcid.len(),
                "scid" => layer.scid.len(),
                _ => layer.odcid.len(),
            };
            if length > u8::MAX as usize {
                return Err(invalid(
                    NAME,
                    format!("{name} exceeds the one-byte length range"),
                ));
            }
            if layer.version == 1 && length > MAX_CONNECTION_ID_BYTES {
                diagnostics.push(
                    Diagnostic::warning(
                        "build.quic_connection_id",
                        format!(
                            "version 1 caps connection IDs at {MAX_CONNECTION_ID_BYTES} bytes, \
                             but {name} carries {length}"
                        ),
                    )
                    .at_field(name),
                );
            }
        }
        if layer.token.len() > MAX_TOKEN_BYTES {
            return Err(invalid(NAME, "token exceeds the token byte limit"));
        }
        if layer.supported_versions.len() > MAX_SUPPORTED_VERSIONS {
            return Err(invalid(
                NAME,
                "supported versions exceed the retention limit",
            ));
        }
        let first = layer.first_byte().map_err(|reason| invalid(NAME, reason))?;

        let mut encoded = Vec::new();
        encoded.push(first);
        if layer.is_long() {
            encoded.extend_from_slice(&layer.version.to_be_bytes());
            encoded.push(layer.dcid.len() as u8);
            encoded.extend_from_slice(&layer.dcid);
            encoded.push(layer.scid.len() as u8);
            encoded.extend_from_slice(&layer.scid);
            match layer.packet_type {
                PacketType::VersionNegotiation => {
                    if layer.supported_versions.is_empty() {
                        return Err(invalid(
                            NAME,
                            "version negotiation requires at least one supported version",
                        ));
                    }
                    for version in &layer.supported_versions {
                        encoded.extend_from_slice(&version.to_be_bytes());
                    }
                }
                PacketType::Initial => {
                    let token_length =
                        write_varint(u64::try_from(layer.token.len()).unwrap_or(u64::MAX))
                            .ok_or_else(|| invalid(NAME, "token length is not representable"))?;
                    encoded.extend_from_slice(&token_length);
                    encoded.extend_from_slice(&layer.token);
                    encoded.extend_from_slice(&length_bytes(
                        &layer.length,
                        &layer.payload,
                        &mut diagnostics,
                        context,
                    )?);
                    encoded.extend_from_slice(&layer.payload);
                }
                PacketType::ZeroRtt | PacketType::Handshake => {
                    encoded.extend_from_slice(&length_bytes(
                        &layer.length,
                        &layer.payload,
                        &mut diagnostics,
                        context,
                    )?);
                    encoded.extend_from_slice(&layer.payload);
                }
                PacketType::Retry => {
                    if layer.payload.len() != RETRY_INTEGRITY_TAG_BYTES {
                        return Err(invalid(
                            NAME,
                            format!(
                                "retry carries a {RETRY_INTEGRITY_TAG_BYTES}-byte integrity tag, \
                                 but the payload holds {} byte(s)",
                                layer.payload.len()
                            ),
                        ));
                    }
                    encoded.push(layer.odcid.len() as u8);
                    encoded.extend_from_slice(&layer.odcid);
                    encoded.extend_from_slice(&layer.token);
                    encoded.extend_from_slice(&layer.payload);
                }
                PacketType::OneRtt => unreachable!("short headers have no long-header fields"),
            }
        } else {
            encoded.extend_from_slice(&layer.payload);
        }
        ensure_encode_budget(NAME, encoded.len(), context)?;
        Ok(Encoded::header(encoded, Box::new(layer.clone()))
            .with_fields(quic_layout(layer))
            .with_diagnostics(diagnostics))
    }

    fn decode(
        &self,
        input: Bytes,
        _context: &DecodeContext<'_>,
    ) -> Result<Decoded, crate::codec::Error> {
        let (packet, covered) = match parse(&input) {
            Parsed::Packet(layer, covered) => (layer, covered),
            Parsed::NotQuic => return Ok(Raw::decoded(input)),
            Parsed::Malformed(reason) => return Err(invalid(NAME, reason)),
        };
        Ok(Decoded {
            fields: quic_layout(&packet),
            layer: packet.clone(),
            consumed: input.len().min(covered),
            payload_len: 0,
            next: Vec::new(),
            diagnostics: version_one_connection_id_diagnostics(&packet),
            stop: true,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, field::Value>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Quic::default(), fields)
    }
}

/// Resolves the protected-payload length against the payload that follows it.
fn length_bytes(
    length: &WireValue<u64>,
    payload: &[u8],
    diagnostics: &mut Vec<Diagnostic>,
    context: &EncodeContext<'_>,
) -> Result<Vec<u8>, crate::codec::Error> {
    let expected = u64::try_from(payload.len()).unwrap_or(u64::MAX);
    let (length, _) = resolve_fixed(
        NAME,
        "length",
        length,
        ValueExpectation::Required(expected),
        context.mode,
        diagnostics,
        u64::from_be_bytes,
    )?;
    write_varint(length)
        .ok_or_else(|| invalid(NAME, "length is not representable as a QUIC varint"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(input: &[u8]) -> Result<Decoded, crate::codec::Error> {
        let registry = crate::protocol::builtin::registry();
        let context = DecodeContext {
            parent: None,
            registry: &registry,
            network: None,
            hop_limit: None,
            discriminator: None,
        };
        QuicCodec.decode(Bytes::copy_from_slice(input), &context)
    }

    /// Re-encodes a dissected packet and expects the exact bytes back.
    fn round_trips(input: &[u8]) {
        let registry = crate::protocol::builtin::registry();
        let Decoded {
            layer, consumed, ..
        } = decode(input).expect("the packet dissects");
        let packet = crate::packet::Packet::new();
        let build_context = crate::codec::Addresses::default();
        let context = EncodeContext {
            packet: &packet,
            index: 0,
            build_context: &build_context,
            mode: crate::codec::Mode::Strict,
            registry: &registry,
            child: None,
            remaining_packet_bytes: usize::MAX,
        };
        let encoded = QuicCodec
            .encode(layer.as_ref(), &[], &context)
            .expect("the dissected packet re-encodes");
        assert_eq!(
            encoded.prefix.len(),
            consumed,
            "the covered bytes re-encode exactly"
        );
        assert_eq!(&input[..consumed], &encoded.prefix[..]);
    }

    #[test]
    fn version_one_initial_and_handshake_packets_round_trip_exactly() {
        // Long header, version 1, 8-byte DCID, empty SCID and token, length 4.
        let mut packet = vec![0xc3, 0, 0, 0, 1, 8];
        packet.extend_from_slice(&[0x51; 8]);
        packet.extend_from_slice(&[0, 0, 4]); // SCID, token, protected length
        packet.extend_from_slice(&[0x42; 4]);
        let Decoded {
            consumed, layer, ..
        } = decode(&packet).expect("initial dissects");
        assert_eq!(consumed, packet.len());
        let layer = layer.downcast_ref::<Quic>().unwrap();
        assert_eq!(layer.packet_type, PacketType::Initial);
        assert_eq!(layer.version, 1);
        assert_eq!(layer.dcid.len(), 8);
        assert!(layer.token.is_empty());
        assert_eq!(layer.payload.len(), 4);
        round_trips(&packet);

        // Handshake: byte 0xe0 carries type 2 in bits 5-4, DCID 2, SCID 1.
        let mut handshake = vec![0xe0, 0, 0, 0, 1, 2];
        handshake.extend_from_slice(&[0x11, 0x22]);
        handshake.extend_from_slice(&[1]);
        handshake.extend_from_slice(&[0x33]);
        handshake.extend_from_slice(&[2]); // protected length
        handshake.extend_from_slice(&[0xab, 0xcd]);
        let Decoded { layer, .. } = decode(&handshake).expect("handshake dissects");
        let handshake_layer = layer.downcast_ref::<Quic>().unwrap();
        assert_eq!(handshake_layer.packet_type, PacketType::Handshake);
        assert_eq!(handshake_layer.dcid, Bytes::from_static(&[0x11, 0x22]));
        assert_eq!(handshake_layer.scid, Bytes::from_static(&[0x33]));
        round_trips(&handshake);
    }

    #[test]
    fn short_headers_keep_the_connection_id_opaque() {
        let packet = [0x63, 0x0f, 0x10, 0x99, 0x7a];
        let Decoded {
            consumed, layer, ..
        } = decode(&packet).expect("short header dissects");
        assert_eq!(consumed, 5);
        let layer = layer.downcast_ref::<Quic>().unwrap();
        assert_eq!(layer.packet_type, PacketType::OneRtt);
        assert!(layer.spin, "bit 5 of 0x63 is set");
        assert_eq!(layer.protected_bits, 3);
        assert_eq!(layer.payload, Bytes::from_static(&[0x0f, 0x10, 0x99, 0x7a]));
        round_trips(&packet);
    }

    #[test]
    fn version_negotiation_keeps_the_wire_order_and_random_bits() {
        let mut packet = vec![0xda, 0, 0, 0, 0, 0, 0];
        packet.extend_from_slice(&1_u32.to_be_bytes());
        packet.extend_from_slice(&0x6b33_7458_u32.to_be_bytes());
        let Decoded { layer, .. } = decode(&packet).expect("version negotiation dissects");
        let layer = layer.downcast_ref::<Quic>().unwrap();
        assert_eq!(layer.packet_type, PacketType::VersionNegotiation);
        assert_eq!(layer.protected_bits, 0x1a);
        assert_eq!(layer.supported_versions, vec![1, 0x6b33_7458]);
        round_trips(&packet);
    }

    #[test]
    fn retry_packets_split_odcid_token_and_integrity_tag() {
        let mut packet = vec![0xf0, 0, 0, 0, 1, 4];
        packet.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]); // DCID
        packet.push(2); // SCID
        packet.extend_from_slice(&[0x55, 0x66]);
        packet.push(3); // ODCID length
        packet.extend_from_slice(&[0x77, 0x88, 0x99]);
        packet.extend_from_slice(b"tok"); // Retry token
        packet.extend_from_slice(&[0xee; RETRY_INTEGRITY_TAG_BYTES]);
        let Decoded { layer, .. } = decode(&packet).expect("retry dissects");
        let layer = layer.downcast_ref::<Quic>().unwrap();
        assert_eq!(layer.packet_type, PacketType::Retry);
        assert_eq!(layer.dcid, Bytes::from_static(&[0x11, 0x22, 0x33, 0x44]));
        assert_eq!(layer.scid, Bytes::from_static(&[0x55, 0x66]));
        assert_eq!(layer.odcid, Bytes::from_static(&[0x77, 0x88, 0x99]));
        assert_eq!(layer.token, Bytes::from_static(b"tok"));
        assert_eq!(layer.payload.len(), RETRY_INTEGRITY_TAG_BYTES);
        round_trips(&packet);
    }

    #[test]
    fn coalesced_packets_cover_only_the_declared_length() {
        let mut packet = vec![0xc0, 0, 0, 0, 1, 0, 0, 0, 3, 0xa, 0xb, 0xc];
        packet.extend_from_slice(&[0x63, 0x01]); // coalesced short header
        let Decoded { consumed, .. } = decode(&packet).expect("coalesced packet dissects");
        assert_eq!(consumed, 12, "the coalesced header stays outside the layer");
    }

    #[test]
    fn non_quic_and_broken_datagrams_never_claim_the_protocol() {
        // Neither the fixed bit nor a whole header: never claimed as QUIC.
        for not_quic in [
            Vec::new(),
            vec![0x05, 0x00, 0x00],
            vec![0xc0, 0x00],
            vec![0x40],
        ] {
            let Ok(Decoded { layer, .. }) = decode(&not_quic) else {
                panic!("unidentifiable datagrams must stay raw: {not_quic:?}")
            };
            assert_eq!(layer.protocol_id().as_str(), "raw", "{not_quic:?}");
        }
        for malformed in [
            // Connection IDs past the end.
            vec![0xc0, 0, 0, 0, 1, 200],
            // Non-canonical token length varint.
            vec![0xc0, 0, 0, 0, 1, 0, 0, 0x40, 2, 1, 1],
            // Token past the end.
            vec![0xc0, 0, 0, 0, 1, 0, 0, 8, 1, 2, 3, 4],
            // Empty protected payload.
            vec![0xc0, 0, 0, 0, 1, 0, 0, 0],
            // Version negotiation with a trailing partial version.
            vec![0xc0, 0, 0, 0, 0, 0, 0, 1, 2, 3],
            // Retry shorter than the integrity tag.
            vec![0xf0, 0, 0, 0, 1, 0, 0, 0, 1, 2],
        ] {
            assert!(
                decode(&malformed).is_err(),
                "malformed QUIC must fail: {malformed:?}"
            );
        }
    }
}
