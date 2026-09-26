// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Handshake message parsing on top of the shared bounded [`Reader`].
//!
//! `parse_handshake` frames one message; the hello parsers and the extension
//! helpers below it interpret the declared body. Everything reports through
//! the same [`Outcome`] the record layer uses.

use std::net::IpAddr;

use bytes::Bytes;

use super::super::super::Error;
use super::super::super::{
    ClientHello, Extension, HANDSHAKE_CLIENT_HELLO, HANDSHAKE_HEADER_LEN, HANDSHAKE_SERVER_HELLO,
    HELLO_RETRY_REQUEST_RANDOM, Handshake, MAX_ALPN, MAX_CIPHER_SUITES, MAX_EXTENSION_LEN,
    MAX_EXTENSIONS, MAX_HANDSHAKE_BODY, MAX_SESSION_ID_LEN, MAX_SNI_LEN, ServerHello, extension,
};
use super::{Outcome, Reader};

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
        return Outcome::Malformed(Error::invalid(format!(
            "handshake body of {declared} bytes exceeds the address space"
        )));
    };
    if length > MAX_HANDSHAKE_BODY {
        return Outcome::Malformed(Error::invalid(format!(
            "handshake body of {length} bytes exceeds the limit of {MAX_HANDSHAKE_BODY}"
        )));
    }
    let total = HANDSHAKE_HEADER_LEN.saturating_add(length);
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
fn parse_client_hello(body: &[u8]) -> Result<ClientHello, Error> {
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
pub(super) fn parse_server_hello(body: &[u8]) -> Result<ServerHello, Error> {
    let mut reader = Reader::new(body);
    let mut hello = ServerHello {
        legacy_version: reader.u16()?,
        random: reader.random()?,
        ..ServerHello::default()
    };
    hello.selected_version = hello.legacy_version;
    hello.is_hello_retry_request = hello.random == HELLO_RETRY_REQUEST_RANDOM;
    hello.session_id = Bytes::copy_from_slice(session_id(&mut reader)?);
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

/// Rejects a hello or extension body that carries bytes after the fields this
/// parser reads: the length is declared, so anything left over is not a body
/// this parser read correctly. `what` names the body.
fn trailing_bytes(reader: &Reader<'_>, what: &str) -> Result<(), Error> {
    let remaining = reader.remaining();
    if remaining == 0 {
        return Ok(());
    }
    Err(Error::invalid(format!(
        "{what} has {remaining} trailing bytes"
    )))
}

fn session_id<'a>(reader: &mut Reader<'a>) -> Result<&'a [u8], Error> {
    let session_id = reader.vector8()?;
    if session_id.len() > MAX_SESSION_ID_LEN {
        return Err(Error::invalid(format!(
            "session identifier of {} bytes exceeds the limit of {MAX_SESSION_ID_LEN}",
            session_id.len()
        )));
    }
    Ok(session_id)
}

pub(super) fn parse_client_extensions(input: &[u8], hello: &mut ClientHello) -> Result<(), Error> {
    let mut reader = Reader::new(input);
    let mut seen = std::collections::HashSet::new();
    while !reader.is_empty() {
        let (extension, body) = next_extension(&mut reader, hello.extensions.len())?;
        if !seen.insert(extension.kind) {
            return Err(Error::invalid("duplicate hello extension"));
        }
        apply_client_extension(extension.kind, body, hello)?;
        hello.extensions.push(extension);
    }
    Ok(())
}

pub(super) fn parse_server_extensions(input: &[u8], hello: &mut ServerHello) -> Result<(), Error> {
    let mut reader = Reader::new(input);
    let mut seen = std::collections::HashSet::new();
    while !reader.is_empty() {
        let (extension, body) = next_extension(&mut reader, hello.extensions.len())?;
        if !seen.insert(extension.kind) {
            return Err(Error::invalid("duplicate hello extension"));
        }
        apply_server_extension(extension.kind, body, hello)?;
        hello.extensions.push(extension);
    }
    Ok(())
}

fn next_extension<'a>(
    reader: &mut Reader<'a>,
    seen: usize,
) -> Result<(Extension, &'a [u8]), Error> {
    if seen >= MAX_EXTENSIONS {
        return Err(Error::invalid(format!(
            "extension count exceeds the limit of {MAX_EXTENSIONS}"
        )));
    }
    let kind = reader.u16()?;
    let len = usize::from(reader.u16()?);
    if len > MAX_EXTENSION_LEN {
        return Err(Error::invalid(format!(
            "extension {kind:#06x} of {len} bytes exceeds the limit of {MAX_EXTENSION_LEN}"
        )));
    }
    let body = reader.take(len)?;
    Ok((
        Extension {
            kind,
            len,
            data: Bytes::copy_from_slice(body),
        },
        body,
    ))
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
            hello.supported_groups =
                parse_u16_vector16(body, "supported_groups extension", "supported group")?;
            Ok(())
        }
        extension::SIGNATURE_ALGORITHMS => {
            hello.signature_algorithms = parse_u16_vector16(
                body,
                "signature_algorithms extension",
                "signature algorithm",
            )?;
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

pub(super) fn apply_server_extension(
    kind: u16,
    body: &[u8],
    hello: &mut ServerHello,
) -> Result<(), Error> {
    match kind {
        extension::SUPPORTED_VERSIONS => {
            let mut reader = Reader::new(body);
            hello.selected_version = reader.u16()?;
            trailing_bytes(&reader, "supported_versions extension")
        }
        extension::KEY_SHARE => {
            let mut reader = Reader::new(body);
            hello.key_share_group = Some(reader.u16()?);
            if !hello.is_hello_retry_request && reader.vector16()?.is_empty() {
                return Err(Error::invalid("ServerHello key_exchange is empty"));
            }
            trailing_bytes(&reader, "key_share extension")
        }
        extension::ALPN => {
            let protocols = parse_alpn(body)?;
            if protocols.len() != 1 {
                return Err(Error::invalid(
                    "ServerHello ALPN must select exactly one protocol",
                ));
            }
            hello.alpn_raw = protocols.into_iter().next();
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
    trailing_bytes(&reader, "server_name extension")?;
    while !list.is_empty() {
        let name_type = list.u8()?;
        let name = list.vector16()?;
        if name_type != 0 {
            continue;
        }
        if name.len() > MAX_SNI_LEN {
            return Err(Error::invalid(format!(
                "server name of {} bytes exceeds the limit of {MAX_SNI_LEN}",
                name.len()
            )));
        }
        if hello.sni_raw.is_none() {
            hello.sni_raw = Some(Bytes::copy_from_slice(name));
            hello.sni = validated_host_name(name);
        }
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
    trailing_bytes(&reader, "ALPN extension")?;
    let mut protocols = Vec::new();
    while !list.is_empty() {
        if protocols.len() >= MAX_ALPN {
            return Err(Error::invalid(format!(
                "ALPN list exceeds the limit of {MAX_ALPN} protocols"
            )));
        }
        let protocol = list.vector8()?;
        if protocol.is_empty() {
            return Err(Error::invalid("ALPN protocol name is empty"));
        }
        protocols.push(Bytes::copy_from_slice(protocol));
    }
    Ok(protocols)
}

fn parse_client_supported_versions(body: &[u8]) -> Result<Vec<u16>, Error> {
    let mut reader = Reader::new(body);
    let versions = reader.vector8()?;
    trailing_bytes(&reader, "supported_versions extension")?;
    u16_list(versions, MAX_EXTENSION_LEN / 2, "supported version")
}

fn parse_u16_vector16(body: &[u8], extension: &str, what: &str) -> Result<Vec<u16>, Error> {
    let mut reader = Reader::new(body);
    let values = reader.vector16()?;
    trailing_bytes(&reader, extension)?;
    u16_list(values, MAX_EXTENSION_LEN / 2, what)
}

fn parse_client_key_share(body: &[u8]) -> Result<Vec<u16>, Error> {
    let mut reader = Reader::new(body);
    let mut list = Reader::new(reader.vector16()?);
    trailing_bytes(&reader, "key_share extension")?;
    let mut groups = Vec::new();
    while !list.is_empty() {
        if groups.len() >= MAX_EXTENSIONS {
            return Err(Error::invalid(format!(
                "key_share list exceeds the limit of {MAX_EXTENSIONS} entries"
            )));
        }
        groups.push(list.u16()?);
        if list.vector16()?.is_empty() {
            return Err(Error::invalid("ClientHello key_exchange is empty"));
        }
    }
    Ok(groups)
}

fn parse_ec_point_formats(body: &[u8]) -> Result<Vec<u8>, Error> {
    let mut reader = Reader::new(body);
    let formats = reader.vector8()?.to_vec();
    trailing_bytes(&reader, "ec_point_formats extension")?;
    Ok(formats)
}

pub(super) fn u16_list(input: &[u8], limit: usize, what: &str) -> Result<Vec<u16>, Error> {
    if !input.len().is_multiple_of(2) {
        return Err(Error::invalid(format!(
            "{what} list of {} bytes is not a whole number of entries",
            input.len()
        )));
    }
    let count = input.len() / 2;
    if count > limit {
        return Err(Error::invalid(format!(
            "{what} list of {count} entries exceeds the limit of {limit}"
        )));
    }
    let values = input
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_be_bytes(*pair))
        .collect();
    Ok(values)
}
