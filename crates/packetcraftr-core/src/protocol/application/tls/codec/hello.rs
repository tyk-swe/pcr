// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;

use super::super::{
    CONTENT_TYPE_HANDSHAKE, ClientHello, Error, Extension, HANDSHAKE_CLIENT_HELLO,
    HANDSHAKE_HEADER_LEN, HANDSHAKE_SERVER_HELLO, Hello, HelloKind, MAX_ALPN, MAX_CIPHER_SUITES,
    MAX_EXTENSION_LEN, MAX_EXTENSIONS, MAX_HANDSHAKE_BODY, MAX_LEGACY_VERSION, MAX_SESSION_ID_LEN,
    MAX_SNI_LEN, MIN_LEGACY_VERSION, ServerHello, extension,
};
use super::NAME;
use crate::protocol::common::structured::Encoder;

impl Extension {
    pub fn server_name(name: impl AsRef<[u8]>) -> Result<Self, Error> {
        let name = name.as_ref();
        if name.len() > MAX_SNI_LEN {
            return Err(Error::invalid("server name exceeds limit"));
        }
        let mut body = Encoder::new(NAME, MAX_EXTENSION_LEN);
        body.u16(
            u16::try_from(name.len() + 3)
                .map_err(|_| Error::invalid("server name length overflow"))?,
        )?;
        body.u8(0)?;
        body.u16(name.len() as u16)?;
        body.bytes(name)?;
        Ok(Self {
            kind: extension::SERVER_NAME,
            data: body.finish().into(),
        })
    }
    pub fn alpn(protocols: &[Bytes]) -> Result<Self, Error> {
        if protocols.len() > MAX_ALPN {
            return Err(Error::invalid("ALPN count exceeded"));
        }
        let mut names = Encoder::new(NAME, MAX_EXTENSION_LEN - 2);
        for name in protocols {
            if name.is_empty() || name.len() > 255 {
                return Err(Error::invalid("ALPN identifier must contain 1..=255 bytes"));
            }
            names.u8(name.len() as u8)?;
            names.bytes(name)?;
        }
        let names = names.finish();
        let mut body = Encoder::new(NAME, MAX_EXTENSION_LEN);
        body.u16(names.len() as u16)?;
        body.bytes(&names)?;
        Ok(Self {
            kind: extension::ALPN,
            data: body.finish().into(),
        })
    }
}

impl Hello {
    pub fn to_wire(&self) -> Result<Bytes, Error> {
        if !(MIN_LEGACY_VERSION..=MAX_LEGACY_VERSION).contains(&self.record_version)
            || self.session_id.len() > MAX_SESSION_ID_LEN
            || self.cipher_suites.is_empty()
            || self.cipher_suites.len() > MAX_CIPHER_SUITES
            || self.compression.is_empty()
            || self.compression.len() > 255
            || self.extensions.len() > MAX_EXTENSIONS
        {
            return Err(Error::invalid(
                "hello field exceeds its protocol or resource bound",
            ));
        }
        if self.kind == HelloKind::Server
            && (self.cipher_suites.len() != 1 || self.compression.len() != 1)
        {
            return Err(Error::invalid(
                "ServerHello selects one cipher and compression method",
            ));
        }
        let mut body = Encoder::new(NAME, MAX_HANDSHAKE_BODY);
        body.u16(self.legacy_version)?;
        body.bytes(&self.random)?;
        body.u8(self.session_id.len() as u8)?;
        body.bytes(&self.session_id)?;
        if self.kind == HelloKind::Client {
            body.u16((self.cipher_suites.len() * 2) as u16)?;
        }
        for suite in &self.cipher_suites {
            body.u16(*suite)?;
        }
        if self.kind == HelloKind::Client {
            body.u8(self.compression.len() as u8)?;
        }
        body.bytes(&self.compression)?;
        let mut extensions = Encoder::new(NAME, u16::MAX as usize);
        let mut seen = std::collections::HashSet::new();
        for extension in &self.extensions {
            if !seen.insert(extension.kind) || extension.data.len() > MAX_EXTENSION_LEN {
                return Err(Error::invalid("duplicate or oversized extension"));
            }
            extensions.u16(extension.kind)?;
            extensions.u16(extension.data.len() as u16)?;
            extensions.bytes(&extension.data)?;
        }
        let extensions = extensions.finish();
        body.u16(extensions.len() as u16)?;
        body.bytes(&extensions)?;
        let body = body.finish();
        let mut handshake = Encoder::new(NAME, MAX_HANDSHAKE_BODY + HANDSHAKE_HEADER_LEN);
        handshake.u8(if self.kind == HelloKind::Client {
            HANDSHAKE_CLIENT_HELLO
        } else {
            HANDSHAKE_SERVER_HELLO
        })?;
        handshake.bytes(&(body.len() as u32).to_be_bytes()[1..])?;
        handshake.bytes(&body)?;
        let handshake = handshake.finish();
        let mut output = Encoder::new(NAME, MAX_HANDSHAKE_BODY + 64);
        for chunk in handshake.chunks(16_384) {
            output.u8(CONTENT_TYPE_HANDSHAKE)?;
            output.u16(self.record_version)?;
            output.u16(chunk.len() as u16)?;
            output.bytes(chunk)?;
        }
        Ok(output.finish().into())
    }

    pub(in super::super) fn from_client(hello: &ClientHello, record_version: u16) -> Self {
        Self {
            kind: HelloKind::Client,
            record_version,
            legacy_version: hello.legacy_version,
            random: hello.random,
            session_id: hello.session_id.clone(),
            cipher_suites: hello.cipher_suites.clone(),
            compression: hello.compression.clone(),
            extensions: hello.extensions.clone(),
        }
    }
    pub(in super::super) fn from_server(hello: &ServerHello, record_version: u16) -> Self {
        Self {
            kind: HelloKind::Server,
            record_version,
            legacy_version: hello.legacy_version,
            random: hello.random,
            session_id: hello.session_id.clone(),
            cipher_suites: vec![hello.cipher_suite],
            compression: vec![hello.compression],
            extensions: hello.extensions.clone(),
        }
    }
}
