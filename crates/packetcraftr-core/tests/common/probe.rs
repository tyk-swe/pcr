// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! A reflective probe protocol with a child layer, registered on a private
//! link type, for exercising the runtime without built-in protocols.

use bytes::Bytes;
use packetcraftr_core::codec::{
    DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext,
};
use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::field::{FieldValue, WireValue};
use packetcraftr_core::frame::LinkType;
use packetcraftr_core::layer::Layer;
use packetcraftr_core::registry::Discriminator;
use packetcraftr_core::{Packet, document, reflective_layer};
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Probe {
    pub(crate) value: u8,
    pub(crate) enabled: bool,
    pub(crate) label: String,
    pub(crate) bytes: Bytes,
    pub(crate) ipv4: Ipv4Addr,
    pub(crate) ipv6: Ipv6Addr,
    pub(crate) mac: [u8; 6],
    pub(crate) token: [u8; 8],
    pub(crate) wire: WireValue<u16>,
}

impl Default for Probe {
    fn default() -> Self {
        Self {
            value: 1,
            enabled: false,
            label: "probe".to_owned(),
            bytes: Bytes::new(),
            ipv4: Ipv4Addr::UNSPECIFIED,
            ipv6: Ipv6Addr::UNSPECIFIED,
            mac: [0; 6],
            token: [0; 8],
            wire: WireValue::Auto,
        }
    }
}

reflective_layer! {
    fn probe_schema() => { protocol: packetcraftr_core::layer::Id::new("probe"), name: "Probe" }
    impl Probe {
        "value" | "probe_value" => {
            kind: Unsigned, derived: false, required: true,
            description: "One-byte probe value",
            reflect: value,
            layout: (0, 1)
        },
        "enabled" => {
            kind: Bool, derived: false, required: true,
            description: "Probe flag",
            get |layer| Some(packetcraftr_core::layer::reflect_get(&layer.enabled)),
            set |layer, value, name| packetcraftr_core::layer::reflect_set(
                &mut layer.enabled, probe_schema(), name, value
            )
        },
        "label" => {
            kind: Text, derived: false, required: true,
            description: "Probe label",
            get |layer| Some(packetcraftr_core::layer::reflect_get(&layer.label)),
            set |layer, value, name| packetcraftr_core::layer::reflect_set(
                &mut layer.label, probe_schema(), name, value
            )
        },
        "bytes" => {
            kind: Bytes, derived: false, required: false,
            description: "Probe bytes",
            get |layer| Some(packetcraftr_core::layer::reflect_get(&layer.bytes)),
            set |layer, value, name| packetcraftr_core::layer::reflect_set(
                &mut layer.bytes, probe_schema(), name, value
            )
        },
        "ipv4" => {
            kind: Ipv4, derived: false, required: true,
            description: "Probe IPv4 address",
            get |layer| Some(packetcraftr_core::layer::reflect_get(&layer.ipv4)),
            set |layer, value, name| packetcraftr_core::layer::reflect_set(
                &mut layer.ipv4, probe_schema(), name, value
            )
        },
        "ipv6" => {
            kind: Ipv6, derived: false, required: true,
            description: "Probe IPv6 address",
            get |layer| Some(packetcraftr_core::layer::reflect_get(&layer.ipv6)),
            set |layer, value, name| packetcraftr_core::layer::reflect_set(
                &mut layer.ipv6, probe_schema(), name, value
            )
        },
        "mac" => {
            kind: Mac, derived: false, required: true,
            description: "Probe MAC address",
            get |layer| Some(packetcraftr_core::layer::reflect_get(&layer.mac)),
            set |layer, value, name| packetcraftr_core::layer::reflect_set(
                &mut layer.mac, probe_schema(), name, value
            )
        },
        "token" => {
            kind: Bytes, derived: false, required: true,
            description: "Eight-byte token",
            get |layer| Some(packetcraftr_core::layer::reflect_get(&layer.token)),
            set |layer, value, name| packetcraftr_core::layer::reflect_set(
                &mut layer.token, probe_schema(), name, value
            )
        },
        "wire" => {
            kind: Unsigned, derived: true, required: true,
            description: "Derived wire value",
            get |layer| Some(packetcraftr_core::layer::reflect_get(&layer.wire)),
            set |layer, value, name| packetcraftr_core::layer::reflect_set(
                &mut layer.wire, probe_schema(), name, value
            )
        }
    }
    layout pub(crate) fn probe_layout();
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Child {
    pub(crate) value: u8,
}

reflective_layer! {
    fn child_schema() => { protocol: packetcraftr_core::layer::Id::new("child"), name: "Child" }
    impl Child {
        "value" => {
            kind: Unsigned, derived: false, required: true,
            description: "Child value",
            get |layer| Some(packetcraftr_core::layer::reflect_get(&layer.value)),
            set |layer, value, name| packetcraftr_core::layer::reflect_set(
                &mut layer.value, child_schema(), name, value
            ),
            layout: (0, 1)
        }
    }
    layout pub(crate) fn child_layout();
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ProbeCodec;

impl LayerCodec for ProbeCodec {
    fn protocol_id(&self) -> &'static packetcraftr_core::layer::Id {
        &probe_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        _context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, packetcraftr_core::codec::Error> {
        let probe = layer.as_any().downcast_ref::<Probe>().ok_or_else(|| {
            packetcraftr_core::codec::Error::WrongLayer {
                expected: "probe".into(),
                actual: *layer.protocol_id(),
            }
        })?;
        let mut encoded = EncodedLayer::header(vec![probe.value], Box::new(probe.clone()));
        encoded.fields = probe_layout();
        encoded
            .diagnostics
            .push(Diagnostic::info("probe.encoded", "encoded probe"));
        Ok(encoded)
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, packetcraftr_core::codec::Error> {
        let Some(value) = input.first().copied() else {
            return Err(packetcraftr_core::codec::Error::Truncated {
                protocol: "probe".into(),
                needed: 1,
                available: 0,
            });
        };
        let payload_len = input.len() - 1;
        Ok(DecodedLayer {
            layer: Box::new(Probe {
                value,
                ..Probe::default()
            }),
            consumed: 1,
            payload_len,
            next: (payload_len != 0)
                .then_some(Discriminator(7))
                .into_iter()
                .collect(),
            fields: probe_layout(),
            diagnostics: vec![Diagnostic::warning("probe.decoded", "decoded probe")],
            stop: payload_len == 0,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, packetcraftr_core::codec::Error> {
        let mut layer = Probe::default();
        for (name, value) in fields {
            layer.set_field(name, value.clone())?;
        }
        Ok(Box::new(layer))
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ChildCodec;

impl LayerCodec for ChildCodec {
    fn protocol_id(&self) -> &'static packetcraftr_core::layer::Id {
        &child_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        _context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, packetcraftr_core::codec::Error> {
        let child = layer.as_any().downcast_ref::<Child>().ok_or_else(|| {
            packetcraftr_core::codec::Error::WrongLayer {
                expected: "child".into(),
                actual: *layer.protocol_id(),
            }
        })?;
        let mut encoded = EncodedLayer::header(vec![child.value], Box::new(child.clone()));
        encoded.fields = child_layout();
        Ok(encoded)
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, packetcraftr_core::codec::Error> {
        let value =
            input
                .first()
                .copied()
                .ok_or_else(|| packetcraftr_core::codec::Error::Truncated {
                    protocol: "child".into(),
                    needed: 1,
                    available: 0,
                })?;
        let mut decoded = DecodedLayer::terminal(Box::new(Child { value }), 1);
        decoded.fields = child_layout();
        Ok(decoded)
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, packetcraftr_core::codec::Error> {
        let mut layer = Child::default();
        for (name, value) in fields {
            layer.set_field(name, value.clone())?;
        }
        Ok(Box::new(layer))
    }
}

pub(crate) fn probe_registry() -> packetcraftr_core::registry::Registry {
    let mut builder = packetcraftr_core::registry::Builder::new();
    builder
        .register_codec(ProbeCodec, &["p"])
        .expect("register probe");
    builder
        .register_codec(ChildCodec, &[])
        .expect("register child");
    builder.bind_link_type(777, "probe").expect("bind root");
    builder.bind("probe", 7, "child", 10).expect("bind child");
    builder.build().expect("valid test registry")
}

/// The link type the fixture registry binds to the `probe` root.
pub(crate) const PROBE_LINK_TYPE: LinkType = LinkType(777);

/// Protocol order plus every reflected field, the comparison the document
/// projection preserves exactly.
pub(crate) fn structure(packet: &Packet) -> document::Packet {
    document::Packet::from_packet(packet)
}
