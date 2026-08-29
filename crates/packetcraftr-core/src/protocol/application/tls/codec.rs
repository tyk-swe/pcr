// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The per-frame `tls` layer codec.
//!
//! One TCP segment in, one layer out. The codec is total: it never returns an
//! error and never raises a warning, because packet loss, retransmission, and
//! mid-stream capture starts are ordinary on a TLS port and must not inflate
//! `expert` error counts.
//!
//! ```text
//! segment ─▶ looks_like_record_start?
//!    no  ─▶ raw layer over the whole segment, no diagnostics
//!    yes ─▶ parse_record loop (≤ MAX_RECORDS_PER_SEGMENT)
//!             0 complete records ─▶ raw layer, no diagnostics
//!            ≥1 complete records ─▶ tls layer over those records,
//!                                   remainder becomes a raw child
//! ```
//!
//! Handshake fields are published only when the whole handshake message lies
//! inside this segment; the stream collector is the authority for hellos split
//! across segments.
//!
//! The `ja3`, `ja3_raw`, and `ja4` fields are advisory: a fingerprint is
//! computed from client-controlled bytes and can be shaped at will by the peer.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use bytes::Bytes;

use crate::{
    codec::{DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    diagnostic::Diagnostic,
    field::FieldValue,
    layer::{Layer, Raw, raw_layout, reflective_layer},
    registry::Discriminator,
};

use super::super::super::common::{
    ensure_encode_budget, invalid, protocol, read_only, text_list, unsigned_list, wrong_layer,
};

use super::fingerprint::{Transport, ja3, ja4};
use super::hex;
use super::model::{
    CONTENT_TYPE_HANDSHAKE, ClientHello, HANDSHAKE_CLIENT_HELLO, HANDSHAKE_SERVER_HELLO, Handshake,
    Record, ServerHello,
};
use super::parse::{Outcome, looks_like_record_start, parse_handshake, parse_record};

/// Records dissected from one segment before the remainder becomes a raw tail.
///
/// A hostile peer can pack thousands of one-byte records into a single
/// segment; the cap keeps per-frame work linear in the segment length with a
/// small constant.
pub(crate) const MAX_RECORDS_PER_SEGMENT: usize = 64;

/// A record continues past the end of this segment.
pub(crate) const RECORD_CONTINUES: &str = "tls.record_continues";
/// Bytes after the last complete record are not a parsable record.
pub(crate) const RECORD_UNPARSED: &str = "tls.record_unparsed";
/// The segment holds more records than one frame publishes.
pub(crate) const RECORDS_CAPPED: &str = "tls.records_capped";
/// A server name was offered but is not a usable host name.
pub(crate) const SNI_INVALID: &str = "tls.sni_invalid";

/// The complete TLS records carried by one TCP segment.
///
/// The layer covers only whole records. A record continuing into the next
/// segment, a malformed tail, and records past the per-segment record cap all
/// stay outside it, as a `raw` child.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tls {
    /// Content type of the first record in the segment.
    pub content_type: u8,
    /// Legacy record version of the first record in the segment.
    pub version: u16,
    /// Complete records covered by this layer.
    pub record_count: u16,
    /// Handshake message type, when a whole handshake message is present.
    pub handshake_type: Option<u8>,
    /// Cipher suite chosen by a ServerHello.
    pub cipher_suite: Option<u16>,
    /// Version chosen by a ServerHello, after `supported_versions`.
    pub selected_version: Option<u16>,
    /// Named group of a ServerHello key share.
    pub key_share_group: Option<u16>,
    /// Whether a record continues past the end of this segment.
    pub incomplete: bool,
    /// Whether a ClientHello offered encrypted client hello.
    pub ech: bool,
    /// Validated server name offered by a ClientHello.
    pub sni: Option<String>,
    /// Verbatim server name bytes, whether or not they validated.
    pub sni_raw: Option<Bytes>,
    /// JA3 fingerprint of a ClientHello, as its MD5 digest.
    pub ja3: Option<String>,
    /// JA3 fingerprint of a ClientHello, before hashing.
    pub ja3_raw: Option<String>,
    /// JA4 fingerprint of a ClientHello.
    pub ja4: Option<String>,
    /// Application protocols offered by a ClientHello or chosen by a ServerHello.
    pub alpn: Vec<String>,
    /// Cipher suites offered by a ClientHello.
    pub cipher_suites: Vec<u16>,
    /// Versions offered by a ClientHello.
    pub supported_versions: Vec<u16>,
    /// Named groups offered by a ClientHello.
    pub supported_groups: Vec<u16>,
    wire: Bytes,
}

/// One segment's worth of dissection: a layer plus its unconsumed tail.
struct Dissection {
    layer: Tls,
    /// Bytes after the last complete record.
    remainder: usize,
    diagnostics: Vec<Diagnostic>,
}

impl Tls {
    /// Reads every complete record from the front of `wire`.
    ///
    /// Returns `None` when no complete record is present, which is how a
    /// coincidental record header inside opaque bytes stays `raw`.
    fn from_records(wire: &[u8]) -> Option<Dissection> {
        let mut records = Vec::new();
        let mut consumed = 0_usize;
        let mut diagnostics = Vec::new();
        let mut incomplete = false;
        loop {
            if records.len() == MAX_RECORDS_PER_SEGMENT {
                if consumed < wire.len() {
                    diagnostics.push(Diagnostic::info(
                        RECORDS_CAPPED,
                        format!(
                            "segment carries more than {MAX_RECORDS_PER_SEGMENT} TLS records; \
                             the remainder is preserved as raw bytes"
                        ),
                    ));
                }
                break;
            }
            match parse_record(wire.get(consumed..)?) {
                Outcome::Complete {
                    consumed: used,
                    value,
                } => {
                    consumed = consumed.checked_add(used)?;
                    records.push(value);
                }
                Outcome::NeedMore { .. } => {
                    if consumed < wire.len() {
                        incomplete = true;
                        diagnostics.push(Diagnostic::info(
                            RECORD_CONTINUES,
                            "a TLS record continues past the end of this segment",
                        ));
                    }
                    break;
                }
                Outcome::Malformed(_) => {
                    if consumed < wire.len() {
                        diagnostics.push(Diagnostic::info(
                            RECORD_UNPARSED,
                            "bytes after the last complete TLS record are not a TLS record",
                        ));
                    }
                    break;
                }
            }
        }
        let first = records.first()?;
        let mut layer = Tls {
            content_type: first.content_type,
            version: first.legacy_version,
            record_count: u16::try_from(records.len()).ok()?,
            handshake_type: None,
            cipher_suite: None,
            selected_version: None,
            key_share_group: None,
            incomplete,
            ech: false,
            sni: None,
            sni_raw: None,
            ja3: None,
            ja3_raw: None,
            ja4: None,
            alpn: Vec::new(),
            cipher_suites: Vec::new(),
            supported_versions: Vec::new(),
            supported_groups: Vec::new(),
            wire: Bytes::copy_from_slice(wire.get(..consumed)?),
        };
        layer.apply_handshake(&records, &mut diagnostics);
        Some(Dissection {
            layer,
            remainder: wire.len().saturating_sub(consumed),
            diagnostics,
        })
    }

    /// Publishes handshake fields when a whole handshake message fits in the
    /// leading run of handshake records.
    fn apply_handshake(&mut self, records: &[Record], diagnostics: &mut Vec<Diagnostic>) {
        if self.content_type != CONTENT_TYPE_HANDSHAKE {
            return;
        }
        let mut stream = Vec::new();
        for record in records.iter().take_while(|record| record.is_handshake()) {
            stream.extend_from_slice(&record.body);
        }
        let Outcome::Complete { value, .. } = parse_handshake(&stream) else {
            return;
        };
        match value {
            Handshake::ClientHello(hello) => {
                self.handshake_type = Some(HANDSHAKE_CLIENT_HELLO);
                self.apply_client_hello(&hello, diagnostics);
            }
            Handshake::ServerHello(hello) => {
                self.handshake_type = Some(HANDSHAKE_SERVER_HELLO);
                self.apply_server_hello(&hello);
            }
            Handshake::Other { kind, .. } => self.handshake_type = Some(kind),
        }
    }

    fn apply_client_hello(&mut self, hello: &ClientHello, diagnostics: &mut Vec<Diagnostic>) {
        let fingerprint = ja3(hello);
        self.ech = hello.ech;
        self.sni = hello.sni.as_deref().map(escape_wire_text);
        self.sni_raw = hello.sni_raw.clone();
        self.ja3 = Some(fingerprint.md5);
        self.ja3_raw = Some(fingerprint.raw);
        self.ja4 = Some(ja4(hello, Transport::Tcp));
        self.alpn = hello
            .alpn
            .iter()
            .map(|name| escape_wire_text(name))
            .collect();
        self.cipher_suites.clone_from(&hello.cipher_suites);
        self.supported_versions
            .clone_from(&hello.supported_versions);
        self.supported_groups.clone_from(&hello.supported_groups);
        if self.sni.is_none() && self.sni_raw.is_some() {
            diagnostics.push(
                Diagnostic::info(
                    SNI_INVALID,
                    "server name is empty, an IP literal, or not printable ASCII",
                )
                .at_field("sni_raw"),
            );
        }
    }

    fn apply_server_hello(&mut self, hello: &ServerHello) {
        self.cipher_suite = Some(hello.cipher_suite);
        self.selected_version = Some(hello.selected_version);
        self.key_share_group = hello.key_share_group;
        self.alpn = hello
            .alpn
            .iter()
            .map(|name| escape_wire_text(name))
            .collect();
    }

    /// The complete records this layer covers, byte for byte.
    #[must_use]
    pub fn wire(&self) -> &Bytes {
        &self.wire
    }

    fn validate_wire_consistency(&self) -> Result<(), crate::codec::Error> {
        let reparsed = Self::from_records(&self.wire).map(|dissection| dissection.layer);
        // `incomplete` describes the bytes after the retained records, which
        // this layer deliberately does not keep; every other field is a pure
        // function of the wire.
        let matches = reparsed.is_some_and(|mut parsed| {
            parsed.incomplete = self.incomplete;
            parsed == *self
        });
        if matches {
            Ok(())
        } else {
            Err(invalid(
                "tls",
                "TLS fields were changed after dissection and no longer match the retained wire payload",
            ))
        }
    }
}

/// Escapes text read from the wire the way DNS escapes label bytes:
/// graphic ASCII stays, everything else (including the space that would split
/// a `key=value` text line) becomes `\DDD` per byte. Unlike a
/// DNS label, `.` is not a separator here and is kept verbatim.
#[must_use]
pub(crate) fn escape_wire_text(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for byte in value.bytes() {
        if (0x21..=0x7e).contains(&byte) && byte != b'\\' {
            escaped.push(char::from(byte));
        } else {
            let _ = write!(escaped, "\\{byte:03}");
        }
    }
    escaped
}

fn optional_list(values: &[String]) -> Option<FieldValue> {
    (!values.is_empty()).then(|| text_list(values))
}

fn optional_codes(values: &[u16]) -> Option<FieldValue> {
    (!values.is_empty()).then(|| unsigned_list(values))
}

reflective_layer! {
    fn tls_schema() => { protocol: protocol("tls"), name: "TLS" }
    impl Tls {
        "content_type" => { kind: Unsigned, derived: false, required: false, description: "Record content type of the first record", get |layer| Some(FieldValue::from(layer.content_type)), set |_layer, _value, name| read_only(tls_schema(), name), layout: (0, 1) },
        "version" => { kind: Unsigned, derived: false, required: false, description: "Legacy record version of the first record", get |layer| Some(FieldValue::from(layer.version)), set |_layer, _value, name| read_only(tls_schema(), name), layout: (1, 3) },
        "record_count" => { kind: Unsigned, derived: false, required: false, description: "Complete records in this segment", get |layer| Some(FieldValue::from(layer.record_count)), set |_layer, _value, name| read_only(tls_schema(), name) },
        "handshake_type" => { kind: Unsigned, derived: false, required: false, description: "Handshake message type, when the whole message is in this segment", get |layer| layer.handshake_type.map(FieldValue::from), set |_layer, _value, name| read_only(tls_schema(), name) },
        "cipher_suite" => { kind: Unsigned, derived: false, required: false, description: "Cipher suite selected by a ServerHello", get |layer| layer.cipher_suite.map(FieldValue::from), set |_layer, _value, name| read_only(tls_schema(), name) },
        "selected_version" => { kind: Unsigned, derived: false, required: false, description: "Version selected by a ServerHello", get |layer| layer.selected_version.map(FieldValue::from), set |_layer, _value, name| read_only(tls_schema(), name) },
        "key_share_group" => { kind: Unsigned, derived: false, required: false, description: "Named group of a ServerHello key share", get |layer| layer.key_share_group.map(FieldValue::from), set |_layer, _value, name| read_only(tls_schema(), name) },
        "incomplete" => { kind: Bool, derived: false, required: false, description: "Whether a record continues past this segment", get |layer| Some(FieldValue::from(layer.incomplete)), set |_layer, _value, name| read_only(tls_schema(), name) },
        "ech" => { kind: Bool, derived: false, required: false, description: "Whether a ClientHello offered encrypted client hello", get |layer| Some(FieldValue::from(layer.ech)), set |_layer, _value, name| read_only(tls_schema(), name) },
        "sni" => { kind: Text, derived: false, required: false, description: "Validated server name offered by a ClientHello", get |layer| layer.sni.clone().map(FieldValue::Text), set |_layer, _value, name| read_only(tls_schema(), name) },
        "sni_raw" => { kind: Text, derived: false, required: false, description: "Verbatim server name bytes in hexadecimal", get |layer| layer.sni_raw.as_ref().map(|raw| FieldValue::Text(hex(raw))), set |_layer, _value, name| read_only(tls_schema(), name) },
        "ja3" => { kind: Text, derived: false, required: false, description: "Advisory JA3 fingerprint of a ClientHello (MD5 digest)", get |layer| layer.ja3.clone().map(FieldValue::Text), set |_layer, _value, name| read_only(tls_schema(), name) },
        "ja3_raw" => { kind: Text, derived: false, required: false, description: "Advisory JA3 fingerprint of a ClientHello before hashing", get |layer| layer.ja3_raw.clone().map(FieldValue::Text), set |_layer, _value, name| read_only(tls_schema(), name) },
        "ja4" => { kind: Text, derived: false, required: false, description: "Advisory JA4 fingerprint of a ClientHello", get |layer| layer.ja4.clone().map(FieldValue::Text), set |_layer, _value, name| read_only(tls_schema(), name) },
        "alpn" => { kind: List, derived: false, required: false, description: "Application protocols offered or selected", get |layer| optional_list(&layer.alpn), set |_layer, _value, name| read_only(tls_schema(), name) },
        "cipher_suites" => { kind: List, derived: false, required: false, description: "Cipher suites offered by a ClientHello", get |layer| optional_codes(&layer.cipher_suites), set |_layer, _value, name| read_only(tls_schema(), name) },
        "supported_versions" => { kind: List, derived: false, required: false, description: "Versions offered by a ClientHello", get |layer| optional_codes(&layer.supported_versions), set |_layer, _value, name| read_only(tls_schema(), name) },
        "supported_groups" => { kind: List, derived: false, required: false, description: "Named groups offered by a ClientHello", get |layer| optional_codes(&layer.supported_groups), set |_layer, _value, name| read_only(tls_schema(), name) }
    }
    layout pub(crate) fn tls_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TlsCodec;

impl LayerCodec for TlsCodec {
    fn protocol_id(&self) -> crate::layer::Id {
        protocol("tls")
    }

    /// A segment on a TLS port that is not TLS decodes as `raw`, so this codec
    /// legitimately produces either protocol.
    fn accepts_decoded_protocol(&self, protocol: &crate::layer::Id) -> bool {
        matches!(protocol.as_str(), "tls" | "raw")
    }

    fn published_schema(&self) -> Option<&'static crate::layer::Schema> {
        Some(tls_schema())
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = layer
            .as_any()
            .downcast_ref::<Tls>()
            .ok_or_else(|| wrong_layer("tls", layer))?;
        layer.validate_wire_consistency()?;
        ensure_encode_budget("tls", layer.wire.len(), context)?;
        Ok(EncodedLayer {
            prefix: layer.wire.to_vec(),
            suffix: Vec::new(),
            materialized: Box::new(layer.clone()),
            fields: tls_layout(),
            diagnostics: Vec::new(),
        })
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, crate::codec::Error> {
        let dissection = looks_like_record_start(input)
            .then(|| Tls::from_records(input))
            .flatten();
        let Some(Dissection {
            layer,
            remainder,
            diagnostics,
        }) = dissection
        else {
            return raw_segment(input);
        };
        Ok(DecodedLayerValue {
            layer: Box::new(layer),
            consumed: input.len().saturating_sub(remainder),
            payload_len: remainder,
            next: if remainder == 0 {
                Vec::new()
            } else {
                vec![Discriminator(0)]
            },
            fields: tls_layout(),
            diagnostics,
            stop: false,
            network: None,
        })
    }

    fn make_layer(
        &self,
        _fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        Err(crate::codec::Error::Unsupported {
            protocol: protocol("tls"),
            message: "TLS is dissection-only; build the segment payload as raw bytes".to_owned(),
        })
    }
}

/// Preserves a segment that is not TLS as opaque bytes, with no diagnostics:
/// a bound port carrying something else, or the middle of a split record, is
/// not a defect.
fn raw_segment(input: &[u8]) -> Result<DecodedLayerValue, crate::codec::Error> {
    let mut decoded = DecodedLayerValue::terminal(
        Box::new(Raw::new(Bytes::copy_from_slice(input))),
        input.len(),
    );
    decoded.fields = raw_layout(input.len());
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use super::super::test_wire::{TLS_1_2, record};
    use super::*;

    #[test]
    fn a_segment_without_a_record_header_has_no_dissection() {
        assert!(Tls::from_records(b"GET / HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn a_truncated_first_record_yields_no_layer() {
        let mut bytes = record(23, TLS_1_2, &[0; 40]);
        bytes.truncate(20);
        assert!(Tls::from_records(&bytes).is_none());
    }

    #[test]
    fn a_trailing_partial_record_marks_the_layer_incomplete() {
        let mut bytes = record(23, TLS_1_2, b"first");
        bytes.extend_from_slice(&record(23, TLS_1_2, b"second-record")[..6]);
        let dissection = Tls::from_records(&bytes).expect("one complete record");
        assert!(dissection.layer.incomplete);
        assert_eq!(dissection.layer.record_count, 1);
        assert_eq!(dissection.remainder, 6);
        assert_eq!(
            dissection
                .diagnostics
                .iter()
                .map(|diagnostic| diagnostic.code.as_str())
                .collect::<Vec<_>>(),
            vec![RECORD_CONTINUES]
        );
    }

    #[test]
    fn the_record_cap_stops_the_loop_and_reports_once() {
        let mut bytes = Vec::new();
        for _ in 0..MAX_RECORDS_PER_SEGMENT + 1 {
            bytes.extend_from_slice(&record(23, TLS_1_2, b"x"));
        }
        let dissection = Tls::from_records(&bytes).expect("capped records still dissect");
        assert_eq!(
            usize::from(dissection.layer.record_count),
            MAX_RECORDS_PER_SEGMENT
        );
        assert_eq!(dissection.remainder, 6);
        assert!(!dissection.layer.incomplete);
        assert_eq!(
            dissection
                .diagnostics
                .iter()
                .map(|diagnostic| diagnostic.code.as_str())
                .collect::<Vec<_>>(),
            vec![RECORDS_CAPPED]
        );
    }

    #[test]
    fn exactly_the_cap_reports_nothing() {
        let mut bytes = Vec::new();
        for _ in 0..MAX_RECORDS_PER_SEGMENT {
            bytes.extend_from_slice(&record(23, TLS_1_2, b"x"));
        }
        let dissection = Tls::from_records(&bytes).expect("capped records still dissect");
        assert_eq!(dissection.remainder, 0);
        assert!(dissection.diagnostics.is_empty());
    }

    #[test]
    fn wire_derived_text_escapes_control_bytes_but_keeps_dots() {
        assert_eq!(escape_wire_text("api.example.test"), "api.example.test");
        assert_eq!(escape_wire_text("h2\u{0}"), "h2\\000");
        assert_eq!(escape_wire_text("a\\b"), "a\\092b");
        assert_eq!(escape_wire_text("h2 x"), "h2\\032x");
    }

    #[test]
    fn hex_renders_lowercase_pairs() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff]), "000fff");
    }

    /// Encodes `layer` the way the builder does, with an empty packet around
    /// it: the codec writes back only the bytes the layer retained.
    fn encode(layer: &Tls) -> Result<EncodedLayer, crate::codec::Error> {
        let registry = crate::protocol::builtin::registry().expect("built-in registry");
        let packet = crate::Packet::new();
        let build_context = crate::build::Context::default();
        let context = LayerEncodeContext {
            packet: &packet,
            index: 0,
            build_context: &build_context,
            mode: crate::build::Mode::Strict,
            registry: &registry,
            child: None,
            remaining_packet_bytes: 4096,
        };
        TlsCodec.encode(layer, &[], &context)
    }

    #[test]
    fn a_dissected_layer_encodes_back_to_the_bytes_it_covered() {
        let bytes = record(23, TLS_1_2, b"encrypted");
        let layer = Tls::from_records(&bytes)
            .expect("one complete record")
            .layer;
        let encoded = encode(&layer).expect("an unmodified layer encodes");
        assert_eq!(encoded.prefix, bytes);
        assert_eq!(layer.wire().as_ref(), &bytes[..]);
    }

    #[test]
    fn changing_a_published_field_makes_the_layer_disagree_with_its_wire() {
        let bytes = record(23, TLS_1_2, b"encrypted");
        let mut layer = Tls::from_records(&bytes)
            .expect("one complete record")
            .layer;
        layer.record_count = 7;
        let Err(error) = encode(&layer) else {
            panic!("a changed field cannot be encoded");
        };
        assert!(
            error
                .to_string()
                .contains("no longer match the retained wire"),
            "{error}"
        );
    }

    #[test]
    fn tls_layers_cannot_be_built_from_fields() {
        let error = TlsCodec
            .make_layer(&BTreeMap::new())
            .expect_err("TLS is dissection-only");
        assert!(
            matches!(error, crate::codec::Error::Unsupported { .. }),
            "{error}"
        );
        assert!(error.to_string().contains("dissection-only"), "{error}");
    }
}
