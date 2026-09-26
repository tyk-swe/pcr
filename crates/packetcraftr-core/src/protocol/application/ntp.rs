// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! NTPv3/v4 client, server, and broadcast message model and codec.
//!
//! The fixed 48-byte header is fully typed, including the signed `poll` and
//! `precision` exponents and the four 64-bit timestamps kept as exact wire
//! integers so fractional precision is never lost. Extension fields and MAC
//! bytes after the header stay bounded opaque `extensions` data. Mode 6/7
//! control messages are outside this codec's scope: they and any input
//! shorter than the base header decode as `raw`.

use std::collections::BTreeMap;

use bytes::Bytes;

use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    field::{self, FieldValue},
    layer::{Layer, Raw, raw_layout, reflective_layer},
};

use crate::protocol::common::{
    ensure_encode_budget, invalid, make_layer, out_of_range, protocol, typed_layer, wrong_type,
};

use crate::protocol::BuiltinProtocol;

const NAME: &str = BuiltinProtocol::Ntp.as_str();

pub const NTP_HEADER_LEN: usize = 48;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ntp {
    /// Leap indicator (2 bits).
    pub leap: u8,
    /// NTP version number (3 bits); supported construction is 3 or 4.
    pub version: u8,
    /// Association mode (3 bits); supported construction is 1 through 5.
    pub mode: u8,
    pub stratum: u8,
    /// Log2 polling interval, signed.
    pub poll: i8,
    /// Log2 clock precision, signed.
    pub precision: i8,
    /// Root delay as the wire 16.16 fixed-point integer.
    pub root_delay: u32,
    /// Root dispersion as the wire 16.16 fixed-point integer.
    pub root_dispersion: u32,
    /// Reference identifier: four bytes, an ASCII kiss code or IPv4 octets.
    pub reference_id: Bytes,
    /// Seconds and fraction as the wire 64-bit timestamp.
    pub reference_timestamp: u64,
    pub origin_timestamp: u64,
    pub receive_timestamp: u64,
    pub transmit_timestamp: u64,
    /// Extension fields and optional MAC bytes after the base header.
    pub extensions: Bytes,
}

impl Default for Ntp {
    fn default() -> Self {
        Self {
            leap: 0,
            version: 4,
            mode: 3,
            stratum: 0,
            poll: 6,
            precision: 0,
            root_delay: 0,
            root_dispersion: 0,
            reference_id: Bytes::from_static(&[0, 0, 0, 0]),
            reference_timestamp: 0,
            origin_timestamp: 0,
            receive_timestamp: 0,
            transmit_timestamp: 0,
            extensions: Bytes::new(),
        }
    }
}

impl Ntp {
    /// Edits `reference_id`: exactly four bytes, or a four-character ASCII
    /// kiss-code string such as `RATE`.
    fn set_reference_id(&mut self, value: FieldValue, name: &str) -> Result<(), field::Error> {
        let bytes = match value {
            FieldValue::Bytes(value) => value,
            FieldValue::Text(value) if value.is_ascii() => Bytes::from(value.into_bytes()),
            _ => return Err(wrong_type(ntp_schema(), name, "four bytes")),
        };
        if bytes.len() != 4 {
            return Err(out_of_range(ntp_schema(), name));
        }
        self.reference_id = bytes;
        Ok(())
    }
}

reflective_layer! {
    fn ntp_schema() => { protocol: protocol(NAME), name: "NTP" }
    impl Ntp {
        "leap" => {
            kind: Unsigned, derived: false, required: false,
            description: "Leap indicator",
            reflect_bounded: leap, 3_u64,
            layout: (0, 1)
        },
        "version" => {
            kind: Unsigned, derived: false, required: true,
            description: "NTP version (3 or 4)",
            reflect_bounded: version, 7_u64,
            layout: (0, 1)
        },
        "mode" => {
            kind: Unsigned, derived: false, required: true,
            description: "Association mode (1-5 for client/server/broadcast)",
            reflect_bounded: mode, 7_u64,
            layout: (0, 1)
        },
        "stratum" => {
            kind: Unsigned, derived: false, required: false,
            description: "Clock stratum",
            reflect: stratum,
            layout: (1, 2)
        },
        "poll" => {
            kind: Signed, derived: false, required: false,
            description: "Poll interval as a signed log2 exponent",
            reflect: poll,
            layout: (2, 3)
        },
        "precision" => {
            kind: Signed, derived: false, required: false,
            description: "Clock precision as a signed log2 exponent",
            reflect: precision,
            layout: (3, 4)
        },
        "root_delay" => {
            kind: Unsigned, derived: false, required: false,
            description: "Root delay as a 16.16 fixed-point integer",
            reflect: root_delay,
            layout: (4, 8)
        },
        "root_dispersion" => {
            kind: Unsigned, derived: false, required: false,
            description: "Root dispersion as a 16.16 fixed-point integer",
            reflect: root_dispersion,
            layout: (8, 12)
        },
        "reference_id" => {
            kind: Bytes, derived: false, required: false,
            description: "Reference identifier (four bytes or ASCII kiss code)",
            get |layer| Some(FieldValue::Bytes(layer.reference_id.clone())),
            set |layer, value, name| layer.set_reference_id(value, name),
            layout: (12, 16)
        },
        "reference_timestamp" => {
            kind: Unsigned, derived: false, required: false,
            description: "Reference timestamp (seconds and fraction)",
            reflect: reference_timestamp,
            layout: (16, 24)
        },
        "origin_timestamp" => {
            kind: Unsigned, derived: false, required: false,
            description: "Origin timestamp (seconds and fraction)",
            reflect: origin_timestamp,
            layout: (24, 32)
        },
        "receive_timestamp" => {
            kind: Unsigned, derived: false, required: false,
            description: "Receive timestamp (seconds and fraction)",
            reflect: receive_timestamp,
            layout: (32, 40)
        },
        "transmit_timestamp" => {
            kind: Unsigned, derived: false, required: false,
            description: "Transmit timestamp (seconds and fraction)",
            reflect: transmit_timestamp,
            layout: (40, 48)
        },
        "extensions" => {
            kind: Bytes, derived: false, required: false,
            description: "Extension fields and optional MAC bytes",
            reflect: extensions,
            layout: (48, NTP_HEADER_LEN.saturating_add(extensions_len))
        },
    }
    layout fn ntp_layout(extensions_len: usize);
}

/// Whether the message's declared version and mode fall inside this codec's
/// NTPv3/v4 client/server/broadcast scope.
fn is_supported(version: u8, mode: u8) -> bool {
    matches!(version, 3 | 4) && matches!(mode, 1..=5)
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NtpCodec;

impl LayerCodec for NtpCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &ntp_schema().protocol
    }

    fn accepts_decoded_protocol(&self, protocol: &crate::layer::Id) -> bool {
        matches!(protocol.as_str(), "ntp" | "raw")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        if !payload.is_empty() {
            return Err(invalid(NAME, "NTP is a complete UDP payload"));
        }
        let layer = typed_layer::<Ntp>(NAME, layer)?;
        if !is_supported(layer.version, layer.mode) {
            return Err(invalid(
                NAME,
                format!(
                    "version {} mode {} is outside the supported NTPv3/v4 message scope",
                    layer.version, layer.mode
                ),
            ));
        }
        if layer.leap > 3 {
            return Err(invalid(
                NAME,
                format!("leap indicator {} exceeds its two-bit field", layer.leap),
            ));
        }
        if layer.reference_id.len() != 4 {
            return Err(invalid(NAME, "reference_id requires exactly four bytes"));
        }
        let contribution = NTP_HEADER_LEN
            .checked_add(layer.extensions.len())
            .ok_or_else(|| invalid(NAME, "message length overflow"))?;
        ensure_encode_budget(NAME, contribution, context)?;

        let mut message = Vec::with_capacity(contribution);
        message.push(layer.leap << 6 | layer.version << 3 | layer.mode);
        message.extend_from_slice(&[layer.stratum, layer.poll as u8, layer.precision as u8]);
        message.extend_from_slice(&layer.root_delay.to_be_bytes());
        message.extend_from_slice(&layer.root_dispersion.to_be_bytes());
        message.extend_from_slice(&layer.reference_id);
        message.extend_from_slice(&layer.reference_timestamp.to_be_bytes());
        message.extend_from_slice(&layer.origin_timestamp.to_be_bytes());
        message.extend_from_slice(&layer.receive_timestamp.to_be_bytes());
        message.extend_from_slice(&layer.transmit_timestamp.to_be_bytes());
        message.extend_from_slice(&layer.extensions);

        Ok(EncodedLayer::header(message, Box::new(layer.clone()))
            .with_fields(ntp_layout(layer.extensions.len())))
    }

    fn decode(
        &self,
        input: Bytes,
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        // Unsupported modes, other versions, and truncated headers stay
        // byte-faithful as `raw` instead of failing the packet's decode.
        let supported = input
            .first_chunk::<NTP_HEADER_LEN>()
            .is_some_and(|header| is_supported(header[0] >> 3 & 0x07, header[0] & 0x07));
        if !supported {
            let mut raw = DecodedLayer::terminal(Box::new(Raw::new(input.clone())), input.len());
            raw.fields = raw_layout(input.len());
            return Ok(raw);
        }
        let header: &[u8; NTP_HEADER_LEN] = input
            .first_chunk::<NTP_HEADER_LEN>()
            .expect("the supported check above requires a full base header");
        let extensions = input.slice(NTP_HEADER_LEN..);
        let extension_len = extensions.len();
        Ok(DecodedLayer {
            layer: Box::new(Ntp {
                leap: header[0] >> 6,
                version: header[0] >> 3 & 0x07,
                mode: header[0] & 0x07,
                stratum: header[1],
                poll: header[2] as i8,
                precision: header[3] as i8,
                root_delay: u32::from_be_bytes(header[4..8].try_into().unwrap_or_default()),
                root_dispersion: u32::from_be_bytes(header[8..12].try_into().unwrap_or_default()),
                reference_id: input.slice_ref(&header[12..16]),
                reference_timestamp: u64::from_be_bytes(
                    header[16..24].try_into().unwrap_or_default(),
                ),
                origin_timestamp: u64::from_be_bytes(header[24..32].try_into().unwrap_or_default()),
                receive_timestamp: u64::from_be_bytes(
                    header[32..40].try_into().unwrap_or_default(),
                ),
                transmit_timestamp: u64::from_be_bytes(
                    header[40..48].try_into().unwrap_or_default(),
                ),
                extensions,
            }),
            consumed: input.len(),
            payload_len: 0,
            next: Vec::new(),
            fields: ntp_layout(extension_len),
            diagnostics: Vec::new(),
            stop: true,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Ntp::default(), fields)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::LayerDecodeContext;

    fn context(registry: &crate::registry::Registry) -> LayerDecodeContext<'_> {
        LayerDecodeContext {
            parent: None,
            registry,
            allow_trailing_padding: false,
            network: None,
            discriminator: None,
        }
    }

    fn fixture() -> [u8; NTP_HEADER_LEN] {
        // leap 0, version 4, mode 3, stratum 2, poll 6, precision -20.
        let mut message = [0_u8; NTP_HEADER_LEN];
        message[0] = 0x23;
        message[1] = 2;
        message[2] = 6;
        message[3] = 0xec;
        message[12..16].copy_from_slice(b"RATE");
        message[40..48].copy_from_slice(&0xe6e1_2345_6789_abcd_u64.to_be_bytes());
        message
    }

    #[test]
    fn decode_types_all_base_fields_and_keeps_trailing_bytes() {
        let registry = crate::protocol::builtin::registry();
        let mut wire = fixture().to_vec();
        wire.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        let decoded = NtpCodec
            .decode(Bytes::from(wire), &context(&registry))
            .expect("supported header decodes");
        let layer = decoded.layer;
        assert_eq!(layer.field("version"), Some(FieldValue::Unsigned(4)));
        assert_eq!(layer.field("mode"), Some(FieldValue::Unsigned(3)));
        assert_eq!(layer.field("stratum"), Some(FieldValue::Unsigned(2)));
        assert_eq!(layer.field("poll"), Some(FieldValue::Signed(6)));
        assert_eq!(layer.field("precision"), Some(FieldValue::Signed(-20)));
        assert_eq!(
            layer.field("reference_id"),
            Some(FieldValue::Bytes(Bytes::from_static(b"RATE")))
        );
        assert_eq!(
            layer.field("transmit_timestamp"),
            Some(FieldValue::Unsigned(0xe6e1_2345_6789_abcd))
        );
        assert_eq!(
            layer.field("extensions"),
            Some(FieldValue::Bytes(Bytes::from_static(&[
                0xaa, 0xbb, 0xcc, 0xdd
            ])))
        );
        assert!(decoded.stop);
    }

    #[test]
    fn truncated_unsupported_and_control_messages_decode_as_raw() {
        let registry = crate::protocol::builtin::registry();
        for wire in [
            fixture()[..47].to_vec(),
            {
                let mut control = fixture().to_vec();
                control[0] = 0x26; // version 4, mode 6 (control)
                control
            },
            {
                let mut legacy = fixture().to_vec();
                legacy[0] = 0x13; // version 2, mode 3
                legacy
            },
            {
                let mut reserved = fixture().to_vec();
                reserved[0] = 0x20; // version 4, mode 0 (reserved)
                reserved
            },
        ] {
            let decoded = NtpCodec
                .decode(Bytes::copy_from_slice(&wire), &context(&registry))
                .expect("unsupported input falls back");
            assert_eq!(decoded.layer.protocol_id().as_str(), "raw");
            assert_eq!(decoded.layer.field("bytes"), Some(wire.into()));
        }
    }

    #[test]
    fn construction_rejects_out_of_scope_fields() {
        for (field, value) in [
            ("version", FieldValue::Unsigned(8)),
            ("mode", FieldValue::Unsigned(8)),
            ("leap", FieldValue::Unsigned(4)),
            ("poll", FieldValue::Signed(-129)),
            ("precision", FieldValue::Text("bad".to_owned())),
        ] {
            let mut layer = Ntp::default();
            assert!(
                layer.set_field(field, value).is_err(),
                "{field} must reject the value"
            );
        }
        let mut layer = Ntp::default();
        layer
            .set_field(
                "reference_id",
                FieldValue::Bytes(Bytes::from_static(b"GPS\0")),
            )
            .expect("four-byte reference id");
        assert!(
            layer
                .set_field(
                    "reference_id",
                    FieldValue::Bytes(Bytes::from_static(b"TOOLONG"))
                )
                .is_err()
        );
    }
}
