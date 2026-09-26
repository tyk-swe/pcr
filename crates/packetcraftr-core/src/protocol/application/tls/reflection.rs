// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;

use super::codec::NAME;
use super::{
    Hello, HelloExtension, HelloKind, MAX_ALPN, MAX_CIPHER_SUITES, MAX_EXTENSIONS, Tls, hex,
};
use crate::{
    field::{self, FieldKind, FieldValue},
    layer::{FieldSchema, reflective_layer},
    protocol::common::{
        out_of_range, protocol, read_only,
        structured::{Object, list, member, object},
        text_list, unsigned_list,
    },
};

impl Tls {
    fn set_hello(&mut self, value: FieldValue) -> Result<(), crate::field::Error> {
        let hello = Hello::from_value(value)?;
        let replacement = Self::try_from(hello)
            .map_err(|_| crate::protocol::common::out_of_range(tls_schema(), "hello"))?;
        *self = replacement;
        Ok(())
    }
}

impl Hello {
    fn value(&self) -> FieldValue {
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
    fn from_value(value: FieldValue) -> Result<Self, field::Error> {
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
                MAX_CIPHER_SUITES,
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
            for value in list(value, MAX_EXTENSIONS, tls_schema(), "hello.extensions")? {
                let mut e = Object::new(value, tls_schema(), "hello.extensions")?;
                let extension = if let Some(value) = e.take("server_name") {
                    let FieldValue::Text(name) = value else {
                        return Err(out_of_range(tls_schema(), "server_name"));
                    };
                    HelloExtension::server_name(name)
                        .map_err(|_| out_of_range(tls_schema(), "server_name"))?
                } else if let Some(value) = e.take("alpn") {
                    let protocols = list(value, MAX_ALPN, tls_schema(), "alpn")?
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
                        .collect::<Result<Vec<_>, field::Error>>()?;
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

fn optional_list(values: &[String]) -> Option<FieldValue> {
    (!values.is_empty()).then(|| text_list(values))
}

fn optional_codes(values: &[u16]) -> Option<FieldValue> {
    (!values.is_empty()).then(|| unsigned_list(values))
}

reflective_layer! {
    pub(super) fn tls_schema() => { protocol: protocol(NAME), name: "TLS" }
    impl Tls {
        "hello" => { kind: Object, derived: false, required: false, description: "Complete hello fixture; extension type/data retain exact unknown bodies", children: HELLO_FIELDS, get |layer| layer.hello.as_ref().map(Hello::value), set |layer, value, _name| layer.set_hello(value) },
        "wire" => { kind: Bytes, derived: false, required: false, description: "Retained TLS record bytes", get |layer| Some(layer.wire.clone().into()), set |_layer, _value, name| read_only(tls_schema(), name) },
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
    layout pub(super) fn tls_layout();
}

const EXTENSION_FIELDS: &[FieldSchema] = &[
    member("type", FieldKind::Unsigned, &[]),
    member("data", FieldKind::Bytes, &[]),
];
const HELLO_FIELDS: &[FieldSchema] = &[
    member("kind", FieldKind::Text, &[]),
    member("record_version", FieldKind::Unsigned, &[]),
    member("legacy_version", FieldKind::Unsigned, &[]),
    member("random", FieldKind::Bytes, &[]),
    member("session_id", FieldKind::Bytes, &[]),
    member("cipher_suites", FieldKind::List, &[]),
    member("compression", FieldKind::Bytes, &[]),
    member("extensions", FieldKind::List, EXTENSION_FIELDS),
];
