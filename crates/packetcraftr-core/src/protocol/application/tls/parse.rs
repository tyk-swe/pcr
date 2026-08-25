// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded, allocation-capped TLS record and handshake parsing.
//!
//! The parser is pure: it knows nothing about TCP, segments, or streams. It
//! reads one record or one handshake message from a byte slice and reports
//! [`Outcome::NeedMore`] with the total input length required for the next
//! [`Outcome::Complete`], so a caller that owns the stream (the per-frame
//! codec, or the session collector) decides when to buffer and when to give
//! up. Every read goes through checked slicing, so malformed input yields
//! [`Outcome::Malformed`] and never a panic.

use std::net::IpAddr;

use bytes::Bytes;

use super::super::super::common::invalid;
use super::model::{
    CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_CHANGE_CIPHER_SPEC, ClientHello, Extension,
    HANDSHAKE_CLIENT_HELLO, HANDSHAKE_HEADER_LEN, HANDSHAKE_SERVER_HELLO,
    HELLO_RETRY_REQUEST_RANDOM, Handshake, MAX_ALPN, MAX_CIPHER_SUITES, MAX_EXTENSION_LEN,
    MAX_EXTENSIONS, MAX_HANDSHAKE_BODY, MAX_LEGACY_VERSION, MAX_RECORD_BODY, MAX_SESSION_ID_LEN,
    MAX_SNI_LEN, MIN_LEGACY_VERSION, RECORD_HEADER_LEN, Record, ServerHello, extension,
};

type Error = crate::codec::Error;

/// The result of reading one framed item from a byte slice.
#[derive(Debug)]
pub enum Outcome<T> {
    /// A complete item, with the number of input bytes it occupied.
    Complete {
        /// Bytes consumed from the front of the input.
        consumed: usize,
        /// The parsed item.
        value: T,
    },
    /// The input is a plausible prefix; `minimum` is the total input length
    /// required before a `Complete` can be produced.
    NeedMore {
        /// Total input length needed, counting the bytes already supplied.
        minimum: usize,
    },
    /// The input cannot be a valid item, whatever follows it. The error
    /// describes which rule or limit it broke.
    Malformed(crate::codec::Error),
}

impl<T> Outcome<T> {
    /// Reports whether a complete item was parsed.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Complete { .. })
    }
}

/// Reports whether `input` starts with a plausible TLS record header.
///
/// This is the dissection gate: content type in `20..=23`, legacy version in
/// `0x0300..=0x0304`, and a declared body length in `1..=MAX_RECORD_BODY`. It
/// accepts exactly the headers [`parse_record`] accepts, so a gate pass
/// followed by a `Malformed` from [`parse_record`] is impossible for the same
/// first record. Fewer than [`RECORD_HEADER_LEN`] bytes cannot be gated and
/// report `false`.
#[must_use]
pub fn looks_like_record_start(input: &[u8]) -> bool {
    input
        .first_chunk::<RECORD_HEADER_LEN>()
        .is_some_and(|header| record_header(header).is_ok())
}

/// Reads one TLS record from the front of `input`.
pub fn parse_record(input: &[u8]) -> Outcome<Record> {
    let Some(header) = input.first_chunk::<RECORD_HEADER_LEN>() else {
        return Outcome::NeedMore {
            minimum: RECORD_HEADER_LEN,
        };
    };
    let header = match record_header(header) {
        Ok(header) => header,
        Err(error) => return Outcome::Malformed(error),
    };
    let total = RECORD_HEADER_LEN + header.length;
    let Some(body) = input.get(RECORD_HEADER_LEN..total) else {
        return Outcome::NeedMore { minimum: total };
    };
    Outcome::Complete {
        consumed: total,
        value: Record {
            content_type: header.content_type,
            legacy_version: header.legacy_version,
            body: Bytes::copy_from_slice(body),
        },
    }
}

/// Reads one handshake message from the front of `input`.
///
/// `input` is the concatenation of handshake record bodies, not a record
/// stream: a handshake message may span several records, and several messages
/// may share one record.
pub fn parse_handshake(input: &[u8]) -> Outcome<Handshake> {
    let Some(header) = input.first_chunk::<HANDSHAKE_HEADER_LEN>() else {
        return Outcome::NeedMore {
            minimum: HANDSHAKE_HEADER_LEN,
        };
    };
    let kind = header[0];
    let declared = u32::from_be_bytes([0, header[1], header[2], header[3]]);
    let Ok(length) = usize::try_from(declared) else {
        return Outcome::Malformed(invalid(
            "tls",
            format!("handshake body of {declared} bytes exceeds the address space"),
        ));
    };
    if length > MAX_HANDSHAKE_BODY {
        return Outcome::Malformed(invalid(
            "tls",
            format!("handshake body of {length} bytes exceeds the limit of {MAX_HANDSHAKE_BODY}"),
        ));
    }
    let total = HANDSHAKE_HEADER_LEN + length;
    let Some(body) = input.get(HANDSHAKE_HEADER_LEN..total) else {
        return Outcome::NeedMore { minimum: total };
    };
    let value = match kind {
        HANDSHAKE_CLIENT_HELLO => {
            parse_client_hello(body).map(|hello| Handshake::ClientHello(Box::new(hello)))
        }
        HANDSHAKE_SERVER_HELLO => {
            parse_server_hello(body).map(|hello| Handshake::ServerHello(Box::new(hello)))
        }
        kind => Ok(Handshake::Other { kind, len: length }),
    };
    match value {
        Ok(value) => Outcome::Complete {
            consumed: total,
            value,
        },
        Err(error) => Outcome::Malformed(error),
    }
}

/// Parses a ClientHello body: the bytes after the handshake header.
pub fn parse_client_hello(body: &[u8]) -> Result<ClientHello, crate::codec::Error> {
    let mut reader = Reader::new(body);
    let mut hello = ClientHello {
        legacy_version: reader.u16()?,
        random: reader.random()?,
        ..ClientHello::default()
    };
    hello.session_id = Bytes::copy_from_slice(session_id(&mut reader)?);
    let suites = reader.vector16()?;
    hello.cipher_suites = u16_list(suites, MAX_CIPHER_SUITES, "cipher suite")?;
    hello.compression = reader.vector8()?.to_vec();
    if reader.is_empty() {
        return Ok(hello);
    }
    let extensions = reader.vector16()?;
    parse_client_extensions(extensions, &mut hello)?;
    trailing_bytes(&reader, "ClientHello")?;
    Ok(hello)
}

/// Parses a ServerHello body: the bytes after the handshake header.
pub fn parse_server_hello(body: &[u8]) -> Result<ServerHello, crate::codec::Error> {
    let mut reader = Reader::new(body);
    let mut hello = ServerHello {
        legacy_version: reader.u16()?,
        random: reader.random()?,
        ..ServerHello::default()
    };
    hello.selected_version = hello.legacy_version;
    hello.is_hello_retry_request = hello.random == HELLO_RETRY_REQUEST_RANDOM;
    let _session_id = session_id(&mut reader)?;
    hello.cipher_suite = reader.u16()?;
    hello.compression = reader.u8()?;
    if reader.is_empty() {
        return Ok(hello);
    }
    let extensions = reader.vector16()?;
    parse_server_extensions(extensions, &mut hello)?;
    trailing_bytes(&reader, "ServerHello")?;
    Ok(hello)
}

/// Rejects a hello that carries bytes after its extension block: the message
/// length is declared, so anything left over is not a hello this parser read
/// correctly.
fn trailing_bytes(reader: &Reader<'_>, what: &str) -> Result<(), Error> {
    let remaining = reader.remaining();
    if remaining == 0 {
        return Ok(());
    }
    Err(invalid(
        "tls",
        format!("{what} has {remaining} trailing bytes after its extension block"),
    ))
}

struct RecordHeader {
    content_type: u8,
    legacy_version: u16,
    length: usize,
}

fn record_header(header: &[u8; RECORD_HEADER_LEN]) -> Result<RecordHeader, Error> {
    let content_type = header[0];
    if !(CONTENT_TYPE_CHANGE_CIPHER_SPEC..=CONTENT_TYPE_APPLICATION_DATA).contains(&content_type) {
        return Err(invalid(
            "tls",
            format!(
                "record content type {content_type} is outside \
                 {CONTENT_TYPE_CHANGE_CIPHER_SPEC}..={CONTENT_TYPE_APPLICATION_DATA}"
            ),
        ));
    }
    let legacy_version = u16::from_be_bytes([header[1], header[2]]);
    if !(MIN_LEGACY_VERSION..=MAX_LEGACY_VERSION).contains(&legacy_version) {
        return Err(invalid(
            "tls",
            format!(
                "record version {legacy_version:#06x} is outside \
                 {MIN_LEGACY_VERSION:#06x}..={MAX_LEGACY_VERSION:#06x}"
            ),
        ));
    }
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if length == 0 {
        return Err(invalid("tls", "record body length is zero"));
    }
    if length > MAX_RECORD_BODY {
        return Err(invalid(
            "tls",
            format!("record body of {length} bytes exceeds the limit of {MAX_RECORD_BODY}"),
        ));
    }
    Ok(RecordHeader {
        content_type,
        legacy_version,
        length,
    })
}

fn session_id<'a>(reader: &mut Reader<'a>) -> Result<&'a [u8], Error> {
    let session_id = reader.vector8()?;
    if session_id.len() > MAX_SESSION_ID_LEN {
        return Err(invalid(
            "tls",
            format!(
                "session identifier of {} bytes exceeds the limit of {MAX_SESSION_ID_LEN}",
                session_id.len()
            ),
        ));
    }
    Ok(session_id)
}

fn parse_client_extensions(input: &[u8], hello: &mut ClientHello) -> Result<(), Error> {
    let mut reader = Reader::new(input);
    while !reader.is_empty() {
        let (extension, body) = next_extension(&mut reader, hello.extensions.len())?;
        hello.extensions.push(extension);
        apply_client_extension(extension.kind, body, hello)?;
    }
    Ok(())
}

fn parse_server_extensions(input: &[u8], hello: &mut ServerHello) -> Result<(), Error> {
    let mut reader = Reader::new(input);
    while !reader.is_empty() {
        let (extension, body) = next_extension(&mut reader, hello.extensions.len())?;
        hello.extensions.push(extension);
        apply_server_extension(extension.kind, body, hello)?;
    }
    Ok(())
}

fn next_extension<'a>(
    reader: &mut Reader<'a>,
    seen: usize,
) -> Result<(Extension, &'a [u8]), Error> {
    if seen >= MAX_EXTENSIONS {
        return Err(invalid(
            "tls",
            format!("extension count exceeds the limit of {MAX_EXTENSIONS}"),
        ));
    }
    let kind = reader.u16()?;
    let len = usize::from(reader.u16()?);
    if len > MAX_EXTENSION_LEN {
        return Err(invalid(
            "tls",
            format!(
                "extension {kind:#06x} of {len} bytes exceeds the limit of {MAX_EXTENSION_LEN}"
            ),
        ));
    }
    let body = reader.take(len)?;
    Ok((Extension { kind, len }, body))
}

fn apply_client_extension(kind: u16, body: &[u8], hello: &mut ClientHello) -> Result<(), Error> {
    match kind {
        extension::SERVER_NAME => parse_server_name(body, hello),
        extension::ALPN => {
            hello.alpn_raw = parse_alpn(body)?;
            hello.alpn = hello
                .alpn_raw
                .iter()
                .map(|protocol| String::from_utf8_lossy(protocol).into_owned())
                .collect();
            Ok(())
        }
        extension::SUPPORTED_VERSIONS => {
            hello.supported_versions = parse_client_supported_versions(body)?;
            Ok(())
        }
        extension::SUPPORTED_GROUPS => {
            hello.supported_groups = parse_u16_vector16(body, "supported group")?;
            Ok(())
        }
        extension::SIGNATURE_ALGORITHMS => {
            hello.signature_algorithms = parse_u16_vector16(body, "signature algorithm")?;
            Ok(())
        }
        extension::KEY_SHARE => {
            hello.key_share_groups = parse_client_key_share(body)?;
            Ok(())
        }
        extension::EC_POINT_FORMATS => {
            hello.ec_point_formats = parse_ec_point_formats(body)?;
            Ok(())
        }
        extension::ENCRYPTED_CLIENT_HELLO => {
            hello.ech = true;
            Ok(())
        }
        _ => Ok(()),
    }
}

fn apply_server_extension(kind: u16, body: &[u8], hello: &mut ServerHello) -> Result<(), Error> {
    match kind {
        extension::SUPPORTED_VERSIONS => {
            let mut reader = Reader::new(body);
            hello.selected_version = reader.u16()?;
            Ok(())
        }
        extension::KEY_SHARE => {
            let mut reader = Reader::new(body);
            hello.key_share_group = Some(reader.u16()?);
            Ok(())
        }
        extension::ALPN => {
            hello.alpn_raw = parse_alpn(body)?.into_iter().next();
            hello.alpn = hello
                .alpn_raw
                .as_ref()
                .map(|protocol| String::from_utf8_lossy(protocol).into_owned());
            Ok(())
        }
        _ => Ok(()),
    }
}

fn parse_server_name(body: &[u8], hello: &mut ClientHello) -> Result<(), Error> {
    hello.has_sni_extension = true;
    if body.is_empty() {
        return Ok(());
    }
    let mut reader = Reader::new(body);
    let mut list = Reader::new(reader.vector16()?);
    while !list.is_empty() {
        let name_type = list.u8()?;
        let name = list.vector16()?;
        if name_type != 0 {
            continue;
        }
        if name.len() > MAX_SNI_LEN {
            return Err(invalid(
                "tls",
                format!(
                    "server name of {} bytes exceeds the limit of {MAX_SNI_LEN}",
                    name.len()
                ),
            ));
        }
        hello.sni_raw = Some(Bytes::copy_from_slice(name));
        hello.sni = validated_host_name(name);
        return Ok(());
    }
    Ok(())
}

/// Accepts a host name only when it is a non-empty, printable-ASCII name that
/// is not an IP literal. Anything else keeps its raw bytes and no text form.
fn validated_host_name(name: &[u8]) -> Option<String> {
    if name.is_empty() || !name.iter().all(u8::is_ascii_graphic) {
        return None;
    }
    let text = std::str::from_utf8(name).ok()?;
    if text.parse::<IpAddr>().is_ok() {
        return None;
    }
    Some(text.to_owned())
}

/// Reads the ALPN protocol list as raw wire bytes. The text form is derived
/// by the caller: JA4 reads the bytes, display reads the text.
fn parse_alpn(body: &[u8]) -> Result<Vec<Bytes>, Error> {
    let mut reader = Reader::new(body);
    let mut list = Reader::new(reader.vector16()?);
    let mut protocols = Vec::new();
    while !list.is_empty() {
        if protocols.len() >= MAX_ALPN {
            return Err(invalid(
                "tls",
                format!("ALPN list exceeds the limit of {MAX_ALPN} protocols"),
            ));
        }
        let protocol = list.vector8()?;
        if protocol.is_empty() {
            return Err(invalid("tls", "ALPN protocol name is empty"));
        }
        protocols.push(Bytes::copy_from_slice(protocol));
    }
    Ok(protocols)
}

fn parse_client_supported_versions(body: &[u8]) -> Result<Vec<u16>, Error> {
    let mut reader = Reader::new(body);
    let versions = reader.vector8()?;
    u16_list(versions, MAX_EXTENSION_LEN / 2, "supported version")
}

fn parse_u16_vector16(body: &[u8], what: &str) -> Result<Vec<u16>, Error> {
    let mut reader = Reader::new(body);
    let values = reader.vector16()?;
    u16_list(values, MAX_EXTENSION_LEN / 2, what)
}

fn parse_client_key_share(body: &[u8]) -> Result<Vec<u16>, Error> {
    let mut reader = Reader::new(body);
    let mut list = Reader::new(reader.vector16()?);
    let mut groups = Vec::new();
    while !list.is_empty() {
        if groups.len() >= MAX_EXTENSIONS {
            return Err(invalid(
                "tls",
                format!("key_share list exceeds the limit of {MAX_EXTENSIONS} entries"),
            ));
        }
        groups.push(list.u16()?);
        let _key_exchange = list.vector16()?;
    }
    Ok(groups)
}

fn parse_ec_point_formats(body: &[u8]) -> Result<Vec<u8>, Error> {
    let mut reader = Reader::new(body);
    Ok(reader.vector8()?.to_vec())
}

fn u16_list(input: &[u8], limit: usize, what: &str) -> Result<Vec<u16>, Error> {
    if !input.len().is_multiple_of(2) {
        return Err(invalid(
            "tls",
            format!(
                "{what} list of {} bytes is not a whole number of entries",
                input.len()
            ),
        ));
    }
    let count = input.len() / 2;
    if count > limit {
        return Err(invalid(
            "tls",
            format!("{what} list of {count} entries exceeds the limit of {limit}"),
        ));
    }
    Ok(input
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect())
}

struct Reader<'a> {
    input: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, cursor: 0 }
    }

    fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.cursor)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self
            .cursor
            .checked_add(len)
            .ok_or_else(|| invalid("tls", "handshake offset arithmetic overflowed"))?;
        let slice = self.input.get(self.cursor..end).ok_or_else(|| {
            invalid(
                "tls",
                format!(
                    "handshake field needs {len} bytes but only {} remain",
                    self.input.len().saturating_sub(self.cursor)
                ),
            )
        })?;
        self.cursor = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Error> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn random(&mut self) -> Result<[u8; 32], Error> {
        let bytes = self.take(32)?;
        <[u8; 32]>::try_from(bytes).map_err(|_| invalid("tls", "hello random is not 32 bytes"))
    }

    fn vector8(&mut self) -> Result<&'a [u8], Error> {
        let len = usize::from(self.u8()?);
        self.take(len)
    }

    fn vector16(&mut self) -> Result<&'a [u8], Error> {
        let len = usize::from(self.u16()?);
        self.take(len)
    }
}

#[cfg(test)]
mod tests {
    use super::super::model::{
        CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_HANDSHAKE, HANDSHAKE_CLIENT_HELLO,
        HANDSHAKE_SERVER_HELLO, HELLO_RETRY_REQUEST_RANDOM, Handshake, MAX_ALPN, MAX_CIPHER_SUITES,
        MAX_EXTENSION_LEN, MAX_EXTENSIONS, MAX_HANDSHAKE_BODY, MAX_RECORD_BODY, RECORD_HEADER_LEN,
    };
    use super::{Outcome, looks_like_record_start, parse_handshake, parse_record, u16_list};

    fn record(content_type: u8, version: u16, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![content_type];
        bytes.extend_from_slice(&version.to_be_bytes());
        let length = u16::try_from(body.len()).expect("test record body fits in u16");
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(body);
        bytes
    }

    fn handshake_message(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![kind];
        let length = u32::try_from(body.len()).expect("test handshake body fits in u24");
        bytes.extend_from_slice(&length.to_be_bytes()[1..]);
        bytes.extend_from_slice(body);
        bytes
    }

    fn vector8(body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![u8::try_from(body.len()).expect("test vector fits in u8")];
        bytes.extend_from_slice(body);
        bytes
    }

    fn vector16(body: &[u8]) -> Vec<u8> {
        let mut bytes = u16::try_from(body.len())
            .expect("test vector fits in u16")
            .to_be_bytes()
            .to_vec();
        bytes.extend_from_slice(body);
        bytes
    }

    fn u16_bytes(values: &[u16]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| value.to_be_bytes())
            .collect()
    }

    fn extension(kind: u16, body: &[u8]) -> Vec<u8> {
        let mut bytes = kind.to_be_bytes().to_vec();
        bytes.extend_from_slice(&vector16(body));
        bytes
    }

    fn client_hello_body(
        legacy_version: u16,
        session_id: &[u8],
        ciphers: &[u16],
        extensions: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut bytes = legacy_version.to_be_bytes().to_vec();
        bytes.extend_from_slice(&[7u8; 32]);
        bytes.extend_from_slice(&vector8(session_id));
        bytes.extend_from_slice(&vector16(&u16_bytes(ciphers)));
        bytes.extend_from_slice(&vector8(&[0]));
        let extensions: Vec<u8> = extensions.concat();
        bytes.extend_from_slice(&vector16(&extensions));
        bytes
    }

    fn server_hello_body(
        legacy_version: u16,
        random: [u8; 32],
        cipher: u16,
        extensions: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut bytes = legacy_version.to_be_bytes().to_vec();
        bytes.extend_from_slice(&random);
        bytes.extend_from_slice(&vector8(&[]));
        bytes.extend_from_slice(&cipher.to_be_bytes());
        bytes.push(0);
        let extensions: Vec<u8> = extensions.concat();
        bytes.extend_from_slice(&vector16(&extensions));
        bytes
    }

    fn server_name_extension(name: &[u8]) -> Vec<u8> {
        let mut entry = vec![0u8];
        entry.extend_from_slice(&vector16(name));
        extension(0x0000, &vector16(&entry))
    }

    fn alpn_extension(protocols: &[&[u8]]) -> Vec<u8> {
        let list: Vec<u8> = protocols
            .iter()
            .flat_map(|protocol| vector8(protocol))
            .collect();
        extension(0x0010, &vector16(&list))
    }

    fn client_hello(extensions: &[Vec<u8>]) -> Vec<u8> {
        handshake_message(
            HANDSHAKE_CLIENT_HELLO,
            &client_hello_body(0x0303, &[9; 32], &[0x1301, 0xc02f], extensions),
        )
    }

    fn parsed_client_hello(extensions: &[Vec<u8>]) -> super::ClientHello {
        match parse_handshake(&client_hello(extensions)) {
            Outcome::Complete {
                value: Handshake::ClientHello(hello),
                ..
            } => *hello,
            other => panic!("expected a complete ClientHello, got {other:?}"),
        }
    }

    fn malformed_message(outcome: Outcome<Handshake>) -> String {
        match outcome {
            Outcome::Malformed(error) => error.to_string(),
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn the_gate_accepts_only_plausible_record_headers() {
        let body = [0u8; 4];
        assert!(looks_like_record_start(&record(20, 0x0300, &body)));
        assert!(looks_like_record_start(&record(23, 0x0304, &body)));
        assert!(!looks_like_record_start(&record(19, 0x0303, &body)));
        assert!(!looks_like_record_start(&record(24, 0x0303, &body)));
        assert!(!looks_like_record_start(&record(22, 0x02ff, &body)));
        assert!(!looks_like_record_start(&record(22, 0x0305, &body)));
        assert!(!looks_like_record_start(&record(22, 0x0303, &[])));
        assert!(!looks_like_record_start(&[0x80, 0x2c, 0x01, 0x03, 0x01]));
        assert!(!looks_like_record_start(&[22, 0x03, 0x03]));
        assert!(!looks_like_record_start(&[]));
    }

    #[test]
    fn the_gate_and_the_record_parser_accept_exactly_the_same_headers() {
        for content_type in 18..=25u8 {
            for version in [0x02ffu16, 0x0300, 0x0303, 0x0304, 0x0305] {
                for length in [0u16, 1, 64] {
                    let mut header = vec![content_type];
                    header.extend_from_slice(&version.to_be_bytes());
                    header.extend_from_slice(&length.to_be_bytes());
                    let malformed = matches!(parse_record(&header), Outcome::Malformed(_));
                    assert_eq!(
                        looks_like_record_start(&header),
                        !malformed,
                        "gate and parser disagree on {content_type}/{version:#06x}/{length}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_short_record_header_asks_for_the_header_length() {
        let complete = record(CONTENT_TYPE_HANDSHAKE, 0x0303, &[1, 2, 3]);
        for prefix in 0..RECORD_HEADER_LEN {
            match parse_record(&complete[..prefix]) {
                Outcome::NeedMore { minimum } => assert_eq!(minimum, RECORD_HEADER_LEN),
                other => panic!("expected NeedMore at {prefix} bytes, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_partial_record_body_asks_for_the_whole_record() {
        let complete = record(CONTENT_TYPE_HANDSHAKE, 0x0303, &[1, 2, 3, 4]);
        for prefix in RECORD_HEADER_LEN..complete.len() {
            match parse_record(&complete[..prefix]) {
                Outcome::NeedMore { minimum } => assert_eq!(minimum, complete.len()),
                other => panic!("expected NeedMore at {prefix} bytes, got {other:?}"),
            }
        }
        match parse_record(&complete) {
            Outcome::Complete { consumed, value } => {
                assert_eq!(consumed, complete.len());
                assert_eq!(value.content_type, CONTENT_TYPE_HANDSHAKE);
                assert_eq!(value.legacy_version, 0x0303);
                assert_eq!(value.body.as_ref(), &[1, 2, 3, 4]);
                assert!(value.is_handshake());
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn a_record_keeps_only_its_own_bytes_and_reports_the_rest_as_unconsumed() {
        let mut stream = record(CONTENT_TYPE_HANDSHAKE, 0x0303, &[1, 2]);
        stream.extend_from_slice(&record(CONTENT_TYPE_APPLICATION_DATA, 0x0303, &[3, 4, 5]));
        match parse_record(&stream) {
            Outcome::Complete { consumed, value } => {
                assert_eq!(consumed, RECORD_HEADER_LEN + 2);
                assert_eq!(value.body.as_ref(), &[1, 2]);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn a_zero_length_or_oversized_record_is_malformed() {
        let empty = record(CONTENT_TYPE_HANDSHAKE, 0x0303, &[]);
        assert!(matches!(parse_record(&empty), Outcome::Malformed(_)));

        let mut oversized = vec![CONTENT_TYPE_HANDSHAKE, 0x03, 0x03];
        let length = u16::try_from(MAX_RECORD_BODY + 1).expect("limit fits in u16");
        oversized.extend_from_slice(&length.to_be_bytes());
        oversized.extend(std::iter::repeat_n(0u8, MAX_RECORD_BODY + 1));
        assert!(matches!(parse_record(&oversized), Outcome::Malformed(_)));

        let at_limit = record(
            CONTENT_TYPE_HANDSHAKE,
            0x0303,
            &vec![0u8; MAX_RECORD_BODY][..],
        );
        assert!(parse_record(&at_limit).is_complete());
    }

    #[test]
    fn a_short_handshake_header_or_body_asks_for_more() {
        let message = handshake_message(9, &[1, 2, 3, 4, 5]);
        for prefix in 0..4 {
            match parse_handshake(&message[..prefix]) {
                Outcome::NeedMore { minimum } => assert_eq!(minimum, 4),
                other => panic!("expected NeedMore at {prefix} bytes, got {other:?}"),
            }
        }
        for prefix in 4..message.len() {
            match parse_handshake(&message[..prefix]) {
                Outcome::NeedMore { minimum } => assert_eq!(minimum, message.len()),
                other => panic!("expected NeedMore at {prefix} bytes, got {other:?}"),
            }
        }
        match parse_handshake(&message) {
            Outcome::Complete { consumed, value } => {
                assert_eq!(consumed, message.len());
                assert_eq!(value, Handshake::Other { kind: 9, len: 5 });
                assert_eq!(value.kind(), 9);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn an_oversized_handshake_body_is_malformed_before_any_copy() {
        let mut message = vec![HANDSHAKE_CLIENT_HELLO];
        let length = u32::try_from(MAX_HANDSHAKE_BODY + 1).expect("limit fits in u24");
        message.extend_from_slice(&length.to_be_bytes()[1..]);
        assert!(matches!(parse_handshake(&message), Outcome::Malformed(_)));
    }

    #[test]
    fn a_client_hello_carries_its_offer_in_wire_order() {
        let hello = parsed_client_hello(&[
            server_name_extension(b"api.example.test"),
            alpn_extension(&[b"h2", b"http/1.1"]),
            extension(0x002b, &vector8(&u16_bytes(&[0x0a0a, 0x0304, 0x0303]))),
            extension(0x000a, &vector16(&u16_bytes(&[0x1a1a, 0x001d, 0x0017]))),
            extension(0x000d, &vector16(&u16_bytes(&[0x0403, 0x0804]))),
            extension(0x000b, &vector8(&[0, 1, 2])),
        ]);
        assert_eq!(hello.legacy_version, 0x0303);
        assert_eq!(hello.random, [7; 32]);
        assert_eq!(hello.session_id.as_ref(), &[9u8; 32]);
        assert_eq!(hello.cipher_suites, vec![0x1301, 0xc02f]);
        assert_eq!(hello.compression, vec![0]);
        assert_eq!(
            hello.extension_kinds().collect::<Vec<_>>(),
            vec![0x0000, 0x0010, 0x002b, 0x000a, 0x000d, 0x000b]
        );
        assert_eq!(hello.sni.as_deref(), Some("api.example.test"));
        assert_eq!(hello.sni_raw.as_deref(), Some(&b"api.example.test"[..]));
        assert!(hello.has_sni_extension);
        assert_eq!(hello.alpn, vec!["h2".to_owned(), "http/1.1".to_owned()]);
        assert_eq!(hello.supported_versions, vec![0x0a0a, 0x0304, 0x0303]);
        assert_eq!(hello.supported_groups, vec![0x1a1a, 0x001d, 0x0017]);
        assert_eq!(hello.signature_algorithms, vec![0x0403, 0x0804]);
        assert_eq!(hello.ec_point_formats, vec![0, 1, 2]);
        assert!(!hello.ech);
    }

    #[test]
    fn a_client_hello_without_extensions_still_parses() {
        let body = {
            let mut bytes = 0x0301u16.to_be_bytes().to_vec();
            bytes.extend_from_slice(&[0u8; 32]);
            bytes.extend_from_slice(&vector8(&[]));
            bytes.extend_from_slice(&vector16(&u16_bytes(&[0x002f])));
            bytes.extend_from_slice(&vector8(&[0]));
            bytes
        };
        match parse_handshake(&handshake_message(HANDSHAKE_CLIENT_HELLO, &body)) {
            Outcome::Complete {
                value: Handshake::ClientHello(hello),
                ..
            } => {
                assert!(hello.extensions.is_empty());
                assert!(!hello.has_sni_extension);
                assert_eq!(hello.cipher_suites, vec![0x002f]);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn key_share_reports_every_offered_group() {
        let mut list = Vec::new();
        for group in [0x0a0au16, 0x001d, 0x0017] {
            list.extend_from_slice(&group.to_be_bytes());
            list.extend_from_slice(&vector16(&[1, 2, 3, 4]));
        }
        let hello = parsed_client_hello(&[extension(0x0033, &vector16(&list))]);
        assert_eq!(hello.key_share_groups, vec![0x0a0a, 0x001d, 0x0017]);
    }

    #[test]
    fn an_encrypted_client_hello_extension_raises_the_ech_flag() {
        let hello = parsed_client_hello(&[extension(0xfe0d, &[0, 1, 2, 3])]);
        assert!(hello.ech);
    }

    #[test]
    fn an_unrecognized_extension_is_recorded_but_not_interpreted() {
        let hello = parsed_client_hello(&[extension(0x1234, &[0xff; 8])]);
        assert_eq!(hello.extensions.len(), 1);
        assert_eq!(hello.extensions[0].kind, 0x1234);
        assert_eq!(hello.extensions[0].len, 8);
    }

    #[test]
    fn an_unusable_server_name_keeps_its_raw_bytes_and_drops_the_text() {
        for name in [&b""[..], b"192.0.2.10", b"2001:db8::1", b"caf\xc3\xa9.test"] {
            let hello = parsed_client_hello(&[server_name_extension(name)]);
            assert!(
                hello.has_sni_extension,
                "{name:?} must record the extension"
            );
            assert_eq!(hello.sni, None, "{name:?} must not produce a host name");
            if name.is_empty() {
                assert_eq!(hello.sni_raw.as_deref(), Some(&b""[..]));
            } else {
                assert_eq!(hello.sni_raw.as_deref(), Some(name));
            }
        }
    }

    #[test]
    fn an_empty_server_name_extension_still_marks_sni_as_offered() {
        let hello = parsed_client_hello(&[extension(0x0000, &[])]);
        assert!(hello.has_sni_extension);
        assert_eq!(hello.sni, None);
        assert_eq!(hello.sni_raw, None);
    }

    #[test]
    fn an_oversized_server_name_is_malformed() {
        let name = vec![b'a'; 256];
        let outcome = parse_handshake(&client_hello(&[server_name_extension(&name)]));
        assert!(malformed_message(outcome).contains("server name"));
    }

    #[test]
    fn a_session_identifier_longer_than_the_protocol_allows_is_malformed() {
        let body = client_hello_body(0x0303, &[0; 33], &[0x1301], &[]);
        let outcome = parse_handshake(&handshake_message(HANDSHAKE_CLIENT_HELLO, &body));
        assert!(malformed_message(outcome).contains("session identifier"));
    }

    #[test]
    fn an_odd_cipher_suite_list_is_malformed() {
        let mut body = 0x0303u16.to_be_bytes().to_vec();
        body.extend_from_slice(&[0u8; 32]);
        body.extend_from_slice(&vector8(&[]));
        body.extend_from_slice(&vector16(&[0x13, 0x01, 0xc0]));
        body.extend_from_slice(&vector8(&[0]));
        let outcome = parse_handshake(&handshake_message(HANDSHAKE_CLIENT_HELLO, &body));
        assert!(malformed_message(outcome).contains("whole number of entries"));
    }

    #[test]
    fn a_cipher_suite_list_past_the_limit_is_malformed() {
        let ciphers: Vec<u16> = (0..=u16::try_from(MAX_CIPHER_SUITES).expect("limit fits"))
            .map(|index| index.wrapping_mul(3))
            .collect();
        let body = client_hello_body(0x0303, &[], &ciphers, &[]);
        let outcome = parse_handshake(&handshake_message(HANDSHAKE_CLIENT_HELLO, &body));
        assert!(malformed_message(outcome).contains("cipher suite"));
    }

    #[test]
    fn an_extension_count_past_the_limit_is_malformed() {
        let extensions: Vec<Vec<u8>> = (0..=MAX_EXTENSIONS)
            .map(|index| {
                let kind = u16::try_from(index).expect("extension index fits") + 0x2000;
                extension(kind, &[])
            })
            .collect();
        let outcome = parse_handshake(&client_hello(&extensions));
        assert!(malformed_message(outcome).contains("extension count"));
    }

    #[test]
    fn an_extension_longer_than_the_limit_is_malformed() {
        let mut declared = 0x1234u16.to_be_bytes().to_vec();
        let length = u16::try_from(MAX_EXTENSION_LEN + 1).expect("limit fits in u16");
        declared.extend_from_slice(&length.to_be_bytes());
        declared.extend(std::iter::repeat_n(0u8, MAX_EXTENSION_LEN + 1));
        let outcome = parse_handshake(&client_hello(&[declared]));
        assert!(malformed_message(outcome).contains("exceeds the limit"));
    }

    #[test]
    fn an_extension_that_overruns_the_extension_block_is_malformed() {
        let mut overrun = 0x1234u16.to_be_bytes().to_vec();
        overrun.extend_from_slice(&32u16.to_be_bytes());
        overrun.extend_from_slice(&[0; 4]);
        let outcome = parse_handshake(&client_hello(&[overrun]));
        assert!(malformed_message(outcome).contains("only"));
    }

    #[test]
    fn a_truncated_alpn_list_is_malformed() {
        let mut body = 4u16.to_be_bytes().to_vec();
        body.extend_from_slice(&[2, b'h']);
        let outcome = parse_handshake(&client_hello(&[extension(0x0010, &body)]));
        assert!(matches!(outcome, Outcome::Malformed(_)));
    }

    #[test]
    fn an_empty_alpn_protocol_name_is_malformed() {
        let list = vector8(&[]);
        let outcome = parse_handshake(&client_hello(&[extension(0x0010, &vector16(&list))]));
        assert!(malformed_message(outcome).contains("ALPN protocol name is empty"));
    }

    #[test]
    fn a_server_hello_reports_the_negotiated_version_and_group() {
        let body = server_hello_body(
            0x0303,
            [1; 32],
            0x1301,
            &[
                extension(0x002b, &0x0304u16.to_be_bytes()),
                extension(0x0033, &{
                    let mut share = 0x001du16.to_be_bytes().to_vec();
                    share.extend_from_slice(&vector16(&[9; 32]));
                    share
                }),
            ],
        );
        match parse_handshake(&handshake_message(HANDSHAKE_SERVER_HELLO, &body)) {
            Outcome::Complete {
                value: Handshake::ServerHello(hello),
                ..
            } => {
                assert_eq!(hello.legacy_version, 0x0303);
                assert_eq!(hello.selected_version, 0x0304);
                assert_eq!(hello.cipher_suite, 0x1301);
                assert_eq!(hello.compression, 0);
                assert_eq!(hello.key_share_group, Some(0x001d));
                assert_eq!(hello.alpn, None);
                assert!(!hello.is_hello_retry_request);
                assert_eq!(
                    hello.extension_kinds().collect::<Vec<_>>(),
                    vec![0x002b, 0x0033]
                );
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn a_server_hello_without_supported_versions_falls_back_to_its_legacy_version() {
        let body = server_hello_body(0x0303, [2; 32], 0xc02f, &[alpn_extension(&[b"http/1.1"])]);
        match parse_handshake(&handshake_message(HANDSHAKE_SERVER_HELLO, &body)) {
            Outcome::Complete {
                value: Handshake::ServerHello(hello),
                ..
            } => {
                assert_eq!(hello.selected_version, 0x0303);
                assert_eq!(hello.alpn.as_deref(), Some("http/1.1"));
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn the_hello_retry_request_random_is_recognized() {
        let body = server_hello_body(
            0x0303,
            HELLO_RETRY_REQUEST_RANDOM,
            0x1301,
            &[extension(0x0033, &0x001du16.to_be_bytes())],
        );
        match parse_handshake(&handshake_message(HANDSHAKE_SERVER_HELLO, &body)) {
            Outcome::Complete {
                value: Handshake::ServerHello(hello),
                ..
            } => {
                assert!(hello.is_hello_retry_request);
                assert_eq!(hello.key_share_group, Some(0x001d));
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn a_truncated_hello_body_is_malformed_rather_than_incomplete() {
        let body = client_hello_body(0x0303, &[], &[0x1301], &[]);
        let outcome = parse_handshake(&handshake_message(HANDSHAKE_CLIENT_HELLO, &body[..10]));
        assert!(matches!(outcome, Outcome::Malformed(_)));
    }

    #[test]
    fn an_alpn_list_past_the_limit_is_malformed() {
        let protocols = vec![&b"a"[..]; MAX_ALPN + 1];
        let outcome = parse_handshake(&client_hello(&[alpn_extension(&protocols)]));
        assert!(malformed_message(outcome).contains("ALPN list"));
    }

    #[test]
    fn alpn_keeps_the_raw_bytes_of_a_name_that_is_not_utf8() {
        let hello = parsed_client_hello(&[alpn_extension(&[b"\xffh2", b"h2"])]);
        assert_eq!(
            hello.alpn_raw.first().map(|raw| raw.as_ref()),
            Some(&b"\xffh2"[..])
        );
        assert_eq!(hello.alpn_raw.len(), 2);
        // The text form is lossy, which is why the raw bytes are kept.
        assert_eq!(hello.alpn, vec!["\u{fffd}h2".to_owned(), "h2".to_owned()]);
    }

    #[test]
    fn a_key_share_list_past_the_extension_limit_is_malformed() {
        let mut list = Vec::new();
        for index in 0..=MAX_EXTENSIONS {
            let group = u16::try_from(index).expect("group index fits") + 0x0100;
            list.extend_from_slice(&group.to_be_bytes());
            list.extend_from_slice(&vector16(&[]));
        }
        let outcome = parse_handshake(&client_hello(&[extension(0x0033, &vector16(&list))]));
        assert!(malformed_message(outcome).contains("key_share list"));
    }

    #[test]
    fn a_server_name_list_reports_the_first_host_name_entry() {
        let mut list = vec![9u8];
        list.extend_from_slice(&vector16(b"not-a-host-name"));
        list.push(0);
        list.extend_from_slice(&vector16(b"api.example.test"));
        let hello = parsed_client_hello(&[extension(0x0000, &vector16(&list))]);
        assert_eq!(hello.sni.as_deref(), Some("api.example.test"));
        assert_eq!(hello.sni_raw.as_deref(), Some(&b"api.example.test"[..]));
    }

    #[test]
    fn a_u16_list_past_its_entry_cap_is_malformed() {
        // The cap sits above what one extension body can carry, so it is
        // asserted here directly rather than through a hello.
        let limit = MAX_EXTENSION_LEN / 2;
        let input = vec![0u8; (limit + 1) * 2];
        let error = u16_list(&input, limit, "supported group")
            .expect_err("a list past the cap is rejected");
        assert!(
            error.to_string().contains("supported group list"),
            "{error}"
        );
        assert!(u16_list(&input[..limit * 2], limit, "supported group").is_ok());
    }

    #[test]
    fn bytes_after_a_client_hello_extension_block_are_malformed() {
        let mut body = client_hello_body(0x0303, &[], &[0x1301], &[]);
        body.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let outcome = parse_handshake(&handshake_message(HANDSHAKE_CLIENT_HELLO, &body));
        let message = malformed_message(outcome);
        assert!(
            message.contains("ClientHello has 4 trailing bytes"),
            "{message}"
        );
    }

    #[test]
    fn bytes_after_a_server_hello_extension_block_are_malformed() {
        let mut body = server_hello_body(0x0303, [1; 32], 0x1301, &[]);
        body.extend_from_slice(&[0x00]);
        let outcome = parse_handshake(&handshake_message(HANDSHAKE_SERVER_HELLO, &body));
        let message = malformed_message(outcome);
        assert!(
            message.contains("ServerHello has 1 trailing bytes"),
            "{message}"
        );
    }

    /// A cheap deterministic generator: no dependency, and a failure reproduces
    /// from the seed printed in the assertion.
    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    #[test]
    fn mutated_handshake_bytes_never_panic() {
        let seed = client_hello(&[
            server_name_extension(b"api.example.test"),
            alpn_extension(&[b"h2", b"http/1.1"]),
            extension(0x002b, &vector8(&u16_bytes(&[0x0304, 0x0303]))),
            extension(0x000a, &vector16(&u16_bytes(&[0x001d, 0x0017]))),
            extension(0x000d, &vector16(&u16_bytes(&[0x0403]))),
            extension(
                0x0033,
                &vector16(&{
                    let mut share = 0x001du16.to_be_bytes().to_vec();
                    share.extend_from_slice(&vector16(&[3; 32]));
                    share
                }),
            ),
        ]);
        let framed = record(CONTENT_TYPE_HANDSHAKE, 0x0303, &seed);
        let mut random = XorShift(0x5eed_1234_abcd_0001);

        for iteration in 0..2_000u32 {
            let mut bytes = framed.clone();
            let mutations = 1 + usize::try_from(random.next() % 4).expect("small count fits");
            for _ in 0..mutations {
                let index = usize::try_from(random.next() % 64).expect("small index fits")
                    * bytes.len()
                    / 64;
                let value = u8::try_from(random.next() % 256).expect("byte value fits");
                if let Some(slot) = bytes.get_mut(index) {
                    *slot = value;
                }
            }
            if random.next().is_multiple_of(3) {
                let keep = usize::try_from(random.next() % 64).expect("small length fits")
                    * bytes.len()
                    / 64;
                bytes.truncate(keep);
            }

            let outcome = parse_record(&bytes);
            assert!(
                !matches!(outcome, Outcome::Complete { consumed, .. } if consumed > bytes.len()),
                "iteration {iteration} consumed more than it was given"
            );
            if let Outcome::Complete { value, .. } = outcome {
                let _ = parse_handshake(value.body.as_ref());
            }
            let _ = parse_handshake(&bytes);
            if bytes.len() > RECORD_HEADER_LEN {
                let _ = parse_handshake(&bytes[RECORD_HEADER_LEN..]);
            }
            let _ = looks_like_record_start(&bytes);
        }
    }
}
