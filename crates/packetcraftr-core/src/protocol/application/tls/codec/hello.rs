// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Canonical hello fixtures. Extension bodies remain authoritative opaque bytes.

use super::{
    codec::tls_schema,
    model::{self, ClientHello, ServerHello},
};
use crate::protocol::common::{
    invalid, out_of_range,
    structured::{Encoder, Object, list, member, object},
};
use crate::{
    codec::Error,
    field::{FieldKind, FieldValue},
    layer::{FieldError, FieldSchema},
};
use bytes::Bytes;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HelloKind {
    Client,
    Server,
}

/// One ordered extension with an exact body; helpers construct common bodies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HelloExtension {
    pub kind: u16,
    pub data: Bytes,
}

impl HelloExtension {
    pub fn server_name(name: impl AsRef<[u8]>) -> Result<Self, Error> {
        let name = name.as_ref();
        if name.len() > model::MAX_SNI_LEN {
            return Err(invalid("tls", "server name exceeds limit"));
        }
        let mut body = Encoder::new("tls", model::MAX_EXTENSION_LEN);
        body.u16(
            u16::try_from(name.len() + 3)
                .map_err(|_| invalid("tls", "server name length overflow"))?,
        )?;
        body.u8(0)?;
        body.u16(name.len() as u16)?;
        body.bytes(name)?;
        Ok(Self {
            kind: model::extension::SERVER_NAME,
            data: body.finish().into(),
        })
    }
    pub fn alpn(protocols: &[Bytes]) -> Result<Self, Error> {
        if protocols.len() > model::MAX_ALPN {
            return Err(invalid("tls", "ALPN count exceeded"));
        }
        let mut names = Encoder::new("tls", model::MAX_EXTENSION_LEN - 2);
        for name in protocols {
            if name.is_empty() || name.len() > 255 {
                return Err(invalid("tls", "ALPN identifier must contain 1..=255 bytes"));
            }
            names.u8(name.len() as u8)?;
            names.bytes(name)?;
        }
        let names = names.finish();
        let mut body = Encoder::new("tls", model::MAX_EXTENSION_LEN);
        body.u16(names.len() as u16)?;
        body.bytes(&names)?;
        Ok(Self {
            kind: model::extension::ALPN,
            data: body.finish().into(),
        })
    }
}

/// A bounded ClientHello or ServerHello fixture, without cryptographic state.
/// Server fixtures require exactly one cipher suite and compression method.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    pub kind: HelloKind,
    pub record_version: u16,
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub session_id: Bytes,
    pub cipher_suites: Vec<u16>,
    pub compression: Vec<u8>,
    pub extensions: Vec<HelloExtension>,
}

impl Default for Hello {
    fn default() -> Self {
        Self {
            kind: HelloKind::Client,
            record_version: 0x0303,
            legacy_version: 0x0303,
            random: [0; 32],
            session_id: Bytes::new(),
            cipher_suites: vec![0xc02f],
            compression: vec![0],
            extensions: Vec::new(),
        }
    }
}

impl Hello {
    pub fn to_wire(&self) -> Result<Bytes, Error> {
        if !(model::MIN_LEGACY_VERSION..=model::MAX_LEGACY_VERSION).contains(&self.record_version)
            || self.session_id.len() > model::MAX_SESSION_ID_LEN
            || self.cipher_suites.is_empty()
            || self.cipher_suites.len() > model::MAX_CIPHER_SUITES
            || self.compression.is_empty()
            || self.compression.len() > 255
            || self.extensions.len() > model::MAX_EXTENSIONS
        {
            return Err(invalid(
                "tls",
                "hello field exceeds its protocol or resource bound",
            ));
        }
        if self.kind == HelloKind::Server
            && (self.cipher_suites.len() != 1 || self.compression.len() != 1)
        {
            return Err(invalid(
                "tls",
                "ServerHello selects one cipher and compression method",
            ));
        }
        let mut body = Encoder::new("tls", model::MAX_HANDSHAKE_BODY);
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
        let mut extensions = Encoder::new("tls", u16::MAX as usize);
        let mut seen = std::collections::HashSet::new();
        for extension in &self.extensions {
            if !seen.insert(extension.kind) || extension.data.len() > model::MAX_EXTENSION_LEN {
                return Err(invalid("tls", "duplicate or oversized extension"));
            }
            extensions.u16(extension.kind)?;
            extensions.u16(extension.data.len() as u16)?;
            extensions.bytes(&extension.data)?;
        }
        let extensions = extensions.finish();
        body.u16(extensions.len() as u16)?;
        body.bytes(&extensions)?;
        let body = body.finish();
        let mut handshake = Encoder::new("tls", model::MAX_HANDSHAKE_BODY + 4);
        handshake.u8(if self.kind == HelloKind::Client { 1 } else { 2 })?;
        handshake.bytes(&(body.len() as u32).to_be_bytes()[1..])?;
        handshake.bytes(&body)?;
        let handshake = handshake.finish();
        let mut output = Encoder::new("tls", model::MAX_HANDSHAKE_BODY + 64);
        for chunk in handshake.chunks(16_384) {
            output.u8(model::CONTENT_TYPE_HANDSHAKE)?;
            output.u16(self.record_version)?;
            output.u16(chunk.len() as u16)?;
            output.bytes(chunk)?;
        }
        Ok(output.finish().into())
    }

    pub(super) fn from_client(hello: &ClientHello, record_version: u16) -> Self {
        Self {
            kind: HelloKind::Client,
            record_version,
            legacy_version: hello.legacy_version,
            random: hello.random,
            session_id: hello.session_id.clone(),
            cipher_suites: hello.cipher_suites.clone(),
            compression: hello.compression.clone(),
            extensions: extensions(&hello.extensions),
        }
    }
    pub(super) fn from_server(hello: &ServerHello, record_version: u16) -> Self {
        Self {
            kind: HelloKind::Server,
            record_version,
            legacy_version: hello.legacy_version,
            random: hello.random,
            session_id: hello.session_id.clone(),
            cipher_suites: vec![hello.cipher_suite],
            compression: vec![hello.compression],
            extensions: extensions(&hello.extensions),
        }
    }
    pub(super) fn value(&self) -> FieldValue {
        object([
            (
                "kind",
                if self.kind == HelloKind::Client {
                    "client"
                } else {
                    "server"
                }
                .into(),
            ),
            ("record_version", self.record_version.into()),
            ("legacy_version", self.legacy_version.into()),
            ("random", Bytes::copy_from_slice(&self.random).into()),
            ("session_id", self.session_id.clone().into()),
            (
                "cipher_suites",
                FieldValue::List(self.cipher_suites.iter().map(|v| (*v).into()).collect()),
            ),
            (
                "compression",
                Bytes::copy_from_slice(&self.compression).into(),
            ),
            (
                "extensions",
                FieldValue::List(
                    self.extensions
                        .iter()
                        .map(|e| object([("type", e.kind.into()), ("data", e.data.clone().into())]))
                        .collect(),
                ),
            ),
        ])
    }
    pub(super) fn from_value(value: FieldValue) -> Result<Self, FieldError> {
        let mut o = Object::new(value, tls_schema(), "hello")?;
        let mut hello = Self::default();
        hello.kind = match o.value("kind", "client".to_owned())?.as_str() {
            "client" => HelloKind::Client,
            "server" => HelloKind::Server,
            _ => return Err(out_of_range(tls_schema(), "hello.kind")),
        };
        hello.record_version = o.value("record_version", hello.record_version)?;
        hello.legacy_version = o.value("legacy_version", hello.legacy_version)?;
        let random = o.value("random", Bytes::from(vec![0; 32]))?;
        hello.random = random
            .as_ref()
            .try_into()
            .map_err(|_| out_of_range(tls_schema(), "hello.random"))?;
        hello.session_id = o.value("session_id", Bytes::new())?;
        hello.compression = o.value("compression", Bytes::from_static(&[0]))?.to_vec();
        if let Some(value) = o.take("cipher_suites") {
            hello.cipher_suites = list(
                value,
                model::MAX_CIPHER_SUITES,
                tls_schema(),
                "hello.cipher_suites",
            )?
            .into_iter()
            .map(|value| {
                value
                    .as_u64()
                    .and_then(|v| u16::try_from(v).ok())
                    .ok_or_else(|| out_of_range(tls_schema(), "hello.cipher_suites"))
            })
            .collect::<Result<_, _>>()?;
        }
        if let Some(value) = o.take("extensions") {
            for value in list(
                value,
                model::MAX_EXTENSIONS,
                tls_schema(),
                "hello.extensions",
            )? {
                let mut e = Object::new(value, tls_schema(), "hello.extensions")?;
                let extension = if let Some(value) = e.take("server_name") {
                    let FieldValue::Text(name) = value else {
                        return Err(out_of_range(tls_schema(), "server_name"));
                    };
                    HelloExtension::server_name(name)
                        .map_err(|_| out_of_range(tls_schema(), "server_name"))?
                } else if let Some(value) = e.take("alpn") {
                    let protocols = list(value, model::MAX_ALPN, tls_schema(), "alpn")?
                        .into_iter()
                        .map(|value| {
                            let mut bytes = Bytes::new();
                            match value {
                                FieldValue::Text(text) => bytes = Bytes::from(text),
                                value => crate::layer::reflect_set(
                                    &mut bytes,
                                    tls_schema(),
                                    "alpn",
                                    value,
                                )?,
                            }
                            Ok(bytes)
                        })
                        .collect::<Result<Vec<_>, FieldError>>()?;
                    HelloExtension::alpn(&protocols)
                        .map_err(|_| out_of_range(tls_schema(), "alpn"))?
                } else {
                    HelloExtension {
                        kind: e.value("type", 0u16)?,
                        data: e.value("data", Bytes::new())?,
                    }
                };
                e.finish()?;
                hello.extensions.push(extension);
            }
        }
        o.finish()?;
        Ok(hello)
    }
}

fn extensions(values: &[model::Extension]) -> Vec<HelloExtension> {
    values
        .iter()
        .map(|e| HelloExtension {
            kind: e.kind,
            data: e.data.clone(),
        })
        .collect()
}
const EXTENSION_FIELDS: &[FieldSchema] = &[
    member("type", FieldKind::Unsigned, &[]),
    member("data", FieldKind::Bytes, &[]),
];
pub(super) const FIELDS: &[FieldSchema] = &[
    member("kind", FieldKind::Text, &[]),
    member("record_version", FieldKind::Unsigned, &[]),
    member("legacy_version", FieldKind::Unsigned, &[]),
    member("random", FieldKind::Bytes, &[]),
    member("session_id", FieldKind::Bytes, &[]),
    member("cipher_suites", FieldKind::List, &[]),
    member("compression", FieldKind::Bytes, &[]),
    member("extensions", FieldKind::List, EXTENSION_FIELDS),
];
