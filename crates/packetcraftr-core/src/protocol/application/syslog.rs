// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use bytes::Bytes;

use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    diagnostic::Diagnostic,
    field::{self, FieldValue},
    layer::{Layer, Raw, reflective_layer},
    layout::{ByteRange, FieldLayout},
    protocol::{
        application::byte_string_field,
        common::{
            ensure_encode_budget, invalid, make_layer, out_of_range, protocol,
            strict_or_diagnostic, structured::Encoder, typed_layer, wrong_type,
        },
    },
};

use crate::protocol::BuiltinProtocol;

const NAME: &str = BuiltinProtocol::Syslog.as_str();

/// Longer datagrams decode as `raw` and are refused on encode.
pub const MAX_MESSAGE_BYTES: usize = 8192;
/// RFC 5424 structured data is a run of bracketed elements; a longer run
/// decodes as `raw`.
pub const MAX_STRUCTURED_DATA_ELEMENTS: usize = 128;

const MAX_PRIORITY: u16 = 191;
const FACILITY_MAX: u8 = 31;
const SEVERITY_MAX: u8 = 7;
/// `<`, up to three digits and `>`.
const MAX_PRIORITY_FIELD_LEN: usize = 5;
const NIL: &[u8] = b"-";

/// The two message shapes `<PRI>` can introduce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyslogFormat {
    /// RFC 5424: a version digit, six header fields and structured data.
    Rfc5424,
    /// RFC 3164 and anything else after the priority, kept as one byte string.
    Rfc3164,
}

impl SyslogFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rfc5424 => "rfc5424",
            Self::Rfc3164 => "rfc3164",
        }
    }
}

display_via_as_str!(SyslogFormat);

/// Syslog message (RFC 5424 and RFC 3164) on UDP port 514. Header fields and
/// the message are raw bytes: nothing is normalised, and encoding a decoded
/// layer reproduces the datagram it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Syslog {
    /// The priority value is `facility * 8 + severity`; RFC 5424 allows 0..=191.
    pub facility: u8,
    pub severity: u8,
    pub format: SyslogFormat,
    /// RFC 5424 fields; empty for an RFC 3164 message.
    pub version: Bytes,
    pub timestamp: Bytes,
    pub hostname: Bytes,
    pub app_name: Bytes,
    pub procid: Bytes,
    pub msgid: Bytes,
    /// `-` or one or more bracketed elements.
    pub structured_data: Bytes,
    /// The RFC 5424 message after the structured data, or everything after an
    /// RFC 3164 priority. `None` means the datagram ends before it.
    pub message: Option<Bytes>,
}

impl Default for Syslog {
    fn default() -> Self {
        let nil = Bytes::from_static(NIL);
        Self {
            facility: 1,
            severity: 6,
            format: SyslogFormat::Rfc5424,
            version: Bytes::from_static(b"1"),
            timestamp: nil.clone(),
            hostname: nil.clone(),
            app_name: nil.clone(),
            procid: nil.clone(),
            msgid: nil.clone(),
            structured_data: nil,
            message: None,
        }
    }
}

impl Syslog {
    fn priority(&self) -> u16 {
        u16::from(self.facility) * 8 + u16::from(self.severity)
    }

    /// Moves the untouched RFC 5424 defaults with a format change, so naming
    /// only the format yields a message that encodes. Fields a caller set to
    /// anything else stay and are refused by a legacy message.
    fn switch_header_defaults(&mut self, to: SyslogFormat) {
        let defaults = Self::default();
        let fields = [
            (&mut self.version, &defaults.version),
            (&mut self.timestamp, &defaults.timestamp),
            (&mut self.hostname, &defaults.hostname),
            (&mut self.app_name, &defaults.app_name),
            (&mut self.procid, &defaults.procid),
            (&mut self.msgid, &defaults.msgid),
            (&mut self.structured_data, &defaults.structured_data),
        ];
        for (field, default) in fields {
            match to {
                SyslogFormat::Rfc3164 if field == default => *field = Bytes::new(),
                SyslogFormat::Rfc5424 if field.is_empty() => *field = default.clone(),
                _ => {}
            }
        }
    }

    fn header_fields(&self) -> [(&'static str, &Bytes); 6] {
        [
            ("version", &self.version),
            ("timestamp", &self.timestamp),
            ("hostname", &self.hostname),
            ("app_name", &self.app_name),
            ("procid", &self.procid),
            ("msgid", &self.msgid),
        ]
    }

    /// Fields RFC 5424 bounds and the header fields that cannot be told apart
    /// from their separators.
    fn header_problems(&self) -> Vec<&'static str> {
        let limits = [None, None, Some(255), Some(48), Some(128), Some(32)];
        self.header_fields()
            .into_iter()
            .zip(limits)
            .filter(|((name, value), limit)| {
                let printable = value.iter().all(|byte| (33..=126).contains(byte));
                let version_shaped = *name != "version"
                    || (value.len() <= 3
                        && value
                            .first()
                            .is_some_and(|first| (b'1'..=b'9').contains(first))
                        && value.iter().all(u8::is_ascii_digit));
                value.is_empty()
                    || !printable
                    || !version_shaped
                    || limit.is_some_and(|limit| value.len() > limit)
            })
            .map(|((name, _), _)| name)
            .collect()
    }
}

fn format_value(format: SyslogFormat) -> FieldValue {
    FieldValue::Text(format.as_str().to_owned())
}

fn set_format(layer: &mut Syslog, value: FieldValue, name: &str) -> Result<(), field::Error> {
    let FieldValue::Text(text) = value else {
        return Err(wrong_type(syslog_schema(), name, "rfc5424 or rfc3164"));
    };
    let format = match text.to_ascii_lowercase().as_str() {
        "rfc5424" => SyslogFormat::Rfc5424,
        "rfc3164" => SyslogFormat::Rfc3164,
        _ => return Err(out_of_range(syslog_schema(), name)),
    };
    if format != layer.format {
        layer.switch_header_defaults(format);
    }
    layer.format = format;
    Ok(())
}

fn byte_string(value: FieldValue, name: &str) -> Result<Bytes, field::Error> {
    byte_string_field(syslog_schema(), value, name)
}

reflective_layer! {
    fn syslog_schema() => { protocol: protocol(NAME), name: "Syslog" }
    impl Syslog {
        "facility" => { kind: Unsigned, derived: false, required: true, description: "Facility, the priority divided by eight; 0 to 23 are defined", reflect_bounded: facility, FACILITY_MAX },
        "severity" => { kind: Unsigned, derived: false, required: true, description: "Severity, the priority modulo eight", reflect_bounded: severity, SEVERITY_MAX },
        "format" => {
            kind: Text, derived: false, required: false,
            description: "Message shape: rfc5424 or rfc3164",
            get |layer| Some(format_value(layer.format)),
            set |layer, value, name| set_format(layer, value, name)
        },
        "version" => {
            kind: Bytes, derived: false, required: false,
            description: "RFC 5424 version digits",
            get |layer| Some(FieldValue::Bytes(layer.version.clone())),
            set |layer, value, name| { layer.version = byte_string(value, name)?; Ok(()) }
        },
        "timestamp" => {
            kind: Bytes, derived: false, required: false,
            description: "RFC 5424 timestamp, verbatim",
            get |layer| Some(FieldValue::Bytes(layer.timestamp.clone())),
            set |layer, value, name| { layer.timestamp = byte_string(value, name)?; Ok(()) }
        },
        "hostname" => {
            kind: Bytes, derived: false, required: false,
            description: "RFC 5424 hostname",
            get |layer| Some(FieldValue::Bytes(layer.hostname.clone())),
            set |layer, value, name| { layer.hostname = byte_string(value, name)?; Ok(()) }
        },
        "app_name" => {
            kind: Bytes, derived: false, required: false,
            description: "RFC 5424 application name",
            get |layer| Some(FieldValue::Bytes(layer.app_name.clone())),
            set |layer, value, name| { layer.app_name = byte_string(value, name)?; Ok(()) }
        },
        "procid" => {
            kind: Bytes, derived: false, required: false,
            description: "RFC 5424 process identifier",
            get |layer| Some(FieldValue::Bytes(layer.procid.clone())),
            set |layer, value, name| { layer.procid = byte_string(value, name)?; Ok(()) }
        },
        "msgid" => {
            kind: Bytes, derived: false, required: false,
            description: "RFC 5424 message identifier",
            get |layer| Some(FieldValue::Bytes(layer.msgid.clone())),
            set |layer, value, name| { layer.msgid = byte_string(value, name)?; Ok(()) }
        },
        "structured_data" => {
            kind: Bytes, derived: false, required: false,
            description: "RFC 5424 structured data: - or bracketed elements, verbatim",
            get |layer| Some(FieldValue::Bytes(layer.structured_data.clone())),
            set |layer, value, name| { layer.structured_data = byte_string(value, name)?; Ok(()) }
        },
        "message" => {
            kind: Bytes, derived: false, required: false,
            description: "RFC 5424 message, or the whole RFC 3164 text after the priority",
            get |layer| layer.message.clone().map(FieldValue::Bytes),
            set |layer, value, name| { layer.message = Some(byte_string(value, name)?); Ok(()) }
        },
    }
    layout fn syslog_static_layout();
}

fn syslog_layout(layer: &Syslog) -> Vec<FieldLayout> {
    let mut fields = syslog_static_layout();
    let priority_end = format!("<{}>", layer.priority()).len();
    for name in ["facility", "severity"] {
        fields.push(FieldLayout {
            name,
            range: ByteRange::new(0, priority_end),
        });
    }
    let mut cursor = priority_end;
    let mut push = |name: &'static str, length: usize, separator: bool| {
        let end = cursor.saturating_add(length);
        fields.push(FieldLayout {
            name,
            range: ByteRange::new(cursor, end),
        });
        cursor = end.saturating_add(usize::from(separator));
    };
    if layer.format == SyslogFormat::Rfc5424 {
        for (name, value) in layer.header_fields() {
            push(name, value.len(), true);
        }
        push("structured_data", layer.structured_data.len(), true);
    }
    if let Some(message) = &layer.message {
        push("message", message.len(), false);
    }
    fields
}

/// What a bracketed run looks like from its first byte.
#[derive(Debug, PartialEq, Eq)]
enum StructuredData {
    /// The run's byte length.
    Elements(usize),
    Malformed,
    TooMany,
}

/// Elements end at the first `]` that no backslash escapes.
fn scan_structured_data(data: &[u8]) -> StructuredData {
    let mut cursor = 0_usize;
    let mut elements = 0_usize;
    while data.get(cursor) == Some(&b'[') {
        if elements == MAX_STRUCTURED_DATA_ELEMENTS {
            return StructuredData::TooMany;
        }
        elements += 1;
        cursor += 1;
        loop {
            match data.get(cursor) {
                None => return StructuredData::Malformed,
                Some(b'\\') => cursor = cursor.saturating_add(2),
                Some(b']') => {
                    cursor += 1;
                    break;
                }
                Some(_) => cursor += 1,
            }
        }
    }
    if cursor == 0 {
        StructuredData::Malformed
    } else {
        StructuredData::Elements(cursor)
    }
}

fn is_nil_or_elements(data: &[u8]) -> bool {
    data == NIL || scan_structured_data(data) == StructuredData::Elements(data.len())
}

/// `<PRI>` with one to three canonical decimal digits and a value of at most
/// 191, and the offset after it.
fn parse_priority(input: &[u8]) -> Option<(u16, usize)> {
    if input.first() != Some(&b'<') {
        return None;
    }
    let close = input
        .iter()
        .take(MAX_PRIORITY_FIELD_LEN)
        .position(|byte| *byte == b'>')?;
    let digits = input.get(1..close)?;
    if digits.is_empty()
        || !digits.iter().all(u8::is_ascii_digit)
        || (digits.len() > 1 && digits.first() == Some(&b'0'))
    {
        return None;
    }
    let priority = digits
        .iter()
        .fold(0_u16, |value, digit| value * 10 + u16::from(digit - b'0'));
    (priority <= MAX_PRIORITY).then_some((priority, close + 1))
}

enum Rfc5424 {
    Message(Box<Syslog>),
    Legacy,
    TooManyElements,
}

/// A body is RFC 5424 when a version, five more header fields and structured
/// data follow the priority; anything else is treated as legacy text.
fn parse_rfc5424(body: &Bytes, template: Syslog) -> Rfc5424 {
    let mut header: [Bytes; 6] = Default::default();
    let mut cursor = 0_usize;
    for field in &mut header {
        let Some(length) = body
            .get(cursor..)
            .and_then(|rest| rest.iter().position(|byte| *byte == b' '))
        else {
            return Rfc5424::Legacy;
        };
        *field = body.slice(cursor..cursor + length);
        cursor += length + 1;
    }
    let version_valid = header[0].len() <= 3
        && header[0]
            .first()
            .is_some_and(|first| (b'1'..=b'9').contains(first))
        && header[0].iter().all(u8::is_ascii_digit);
    if !version_valid {
        return Rfc5424::Legacy;
    }
    let rest = body.get(cursor..).unwrap_or_default();
    let structured_len = if rest.first() == Some(&b'-') {
        1
    } else {
        match scan_structured_data(rest) {
            StructuredData::Elements(length) => length,
            StructuredData::Malformed => return Rfc5424::Legacy,
            StructuredData::TooMany => return Rfc5424::TooManyElements,
        }
    };
    let message = match rest.get(structured_len) {
        None => None,
        Some(b' ') => Some(body.slice(cursor + structured_len + 1..)),
        Some(_) => return Rfc5424::Legacy,
    };
    let [version, timestamp, hostname, app_name, procid, msgid] = header;
    Rfc5424::Message(Box::new(Syslog {
        format: SyslogFormat::Rfc5424,
        version,
        timestamp,
        hostname,
        app_name,
        procid,
        msgid,
        structured_data: body.slice(cursor..cursor + structured_len),
        message,
        ..template
    }))
}

/// `None` leaves the datagram to the `raw` fallback: no valid `<PRI>`, a
/// priority above 191, or a message beyond the size and element limits.
fn parse(input: &Bytes) -> Option<Syslog> {
    if input.len() > MAX_MESSAGE_BYTES {
        return None;
    }
    let (priority, body_start) = parse_priority(input)?;
    let body = input.slice(body_start..);
    let template = Syslog {
        // the priority is at most 191, so both parts fit their fields
        facility: (priority / 8) as u8,
        severity: (priority % 8) as u8,
        format: SyslogFormat::Rfc3164,
        version: Bytes::new(),
        timestamp: Bytes::new(),
        hostname: Bytes::new(),
        app_name: Bytes::new(),
        procid: Bytes::new(),
        msgid: Bytes::new(),
        structured_data: Bytes::new(),
        message: Some(body.clone()),
    };
    match parse_rfc5424(&body, template.clone()) {
        Rfc5424::Message(layer) => Some(*layer),
        Rfc5424::Legacy => Some(template),
        Rfc5424::TooManyElements => None,
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SyslogCodec;

impl LayerCodec for SyslogCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &syslog_schema().protocol
    }

    fn accepts_decoded_protocol(&self, protocol: &crate::layer::Id) -> bool {
        matches!(protocol.as_str(), "syslog" | "raw")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        if !payload.is_empty() {
            return Err(invalid(NAME, "syslog is a complete UDP payload"));
        }
        let layer = typed_layer::<Syslog>(NAME, layer)?;
        if layer.facility > FACILITY_MAX || layer.severity > SEVERITY_MAX {
            return Err(invalid(NAME, "field exceeds its wire range"));
        }
        let mut diagnostics = Vec::new();
        if layer.priority() > MAX_PRIORITY {
            strict_or_diagnostic(
                NAME,
                "build.syslog_priority",
                "facility",
                format!(
                    "priority {} exceeds 191; facilities above 23 are undefined",
                    layer.priority()
                ),
                context,
                &mut diagnostics,
            )?;
        }

        let mut encoder = Encoder::new(NAME, MAX_MESSAGE_BYTES);
        encoder.bytes(format!("<{}>", layer.priority()).as_bytes())?;
        match layer.format {
            SyslogFormat::Rfc5424 => {
                encode_rfc5424(layer, context, &mut diagnostics, &mut encoder)?;
            }
            SyslogFormat::Rfc3164 => {
                let stray = layer
                    .header_fields()
                    .into_iter()
                    .map(|(name, value)| (name, value.is_empty()))
                    .chain([("structured_data", layer.structured_data.is_empty())])
                    .find(|(_, empty)| !empty);
                if let Some((name, _)) = stray {
                    return Err(invalid(
                        NAME,
                        format!("{name} belongs to the rfc5424 format"),
                    ));
                }
            }
        }
        if let Some(message) = &layer.message {
            encoder.bytes(message)?;
        }
        let message = encoder.finish();
        ensure_encode_budget(NAME, message.len(), context)?;
        Ok(EncodedLayer::header(message, Box::new(layer.clone()))
            .with_fields(syslog_layout(layer))
            .with_diagnostics(diagnostics))
    }

    fn decode(
        &self,
        input: Bytes,
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        let Some(layer) = parse(&input) else {
            return Ok(Raw::decoded(input));
        };
        let mut diagnostics = Vec::new();
        if layer.format == SyslogFormat::Rfc5424 {
            for field in layer.header_problems() {
                diagnostics.push(
                    Diagnostic::warning(
                        "decode.syslog_header",
                        format!("RFC 5424 {field} is empty, malformed or over its length limit"),
                    )
                    .at_field(field),
                );
            }
        }
        Ok(DecodedLayer {
            fields: syslog_layout(&layer),
            layer: Box::new(layer),
            consumed: input.len(),
            payload_len: 0,
            next: Vec::new(),
            diagnostics,
            stop: true,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Syslog::default(), fields)
    }
}

fn encode_rfc5424(
    layer: &Syslog,
    context: &LayerEncodeContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
    encoder: &mut Encoder,
) -> Result<(), crate::codec::Error> {
    for (name, value) in layer.header_fields() {
        if value.contains(&b' ') {
            return Err(invalid(
                NAME,
                format!("{name} contains a space, which would split the header"),
            ));
        }
    }
    if let Some(problem) = layer.header_problems().into_iter().next() {
        strict_or_diagnostic(
            NAME,
            "build.syslog_header",
            problem,
            format!(
                "RFC 5424 {problem} must be printable ASCII within its length limit; use - for none"
            ),
            context,
            diagnostics,
        )?;
    }
    if !is_nil_or_elements(&layer.structured_data) {
        match scan_structured_data(&layer.structured_data) {
            StructuredData::TooMany => {
                return Err(invalid(
                    NAME,
                    format!("structured data exceeds {MAX_STRUCTURED_DATA_ELEMENTS} elements"),
                ));
            }
            StructuredData::Elements(_) | StructuredData::Malformed => strict_or_diagnostic(
                NAME,
                "build.syslog_structured_data",
                "structured_data",
                "structured data must be - or a run of bracketed elements",
                context,
                diagnostics,
            )?,
        }
    }
    for (_, value) in layer.header_fields() {
        encoder.bytes(value)?;
        encoder.u8(b' ')?;
    }
    encoder.bytes(&layer.structured_data)?;
    if layer.message.is_some() {
        encoder.u8(b' ')?;
    }
    Ok(())
}
