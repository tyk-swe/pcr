// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::OnceLock;

use crate::packet::internal::{
    CodecError, DecodedLayerValue, Discriminator, EncodedLayer, FieldError, FieldKind, FieldSchema,
    FieldValue, Layer, LayerCodec, LayerDecodeContext, LayerEncodeContext, LayerSchema, ProtocolId,
    WireValue,
};

use super::common::{
    aliased_fields, expected_discriminator, field_layout, impl_layer_boilerplate, invalid, ipv4,
    mac, make_layer, out_of_range, protocol, resolve_u16, resolve_u8, set_wire_u16, set_wire_u8,
    truncated, unknown_field, validate_auto_raw_discriminator, validate_raw_child_discriminator,
    wire_u16, wire_u8, wrong_layer, wrong_type, ValueExpectation,
};

const ETHERNET_LEN: usize = 14;
const VLAN_LEN: usize = 4;
const ARP_ETHERNET_IPV4_LEN: usize = 28;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ethernet {
    pub destination: [u8; 6],
    pub source: [u8; 6],
    pub ether_type: WireValue<u16>,
}

impl Default for Ethernet {
    fn default() -> Self {
        Self {
            destination: [0; 6],
            source: [0; 6],
            ether_type: WireValue::Auto,
        }
    }
}

fn ethernet_schema() -> &'static LayerSchema {
    static SCHEMA: OnceLock<LayerSchema> = OnceLock::new();
    static FIELDS: &[FieldSchema] = &[
        FieldSchema {
            name: "destination",
            kind: FieldKind::Mac,
            derived: false,
            required: true,
            description: "Destination MAC address",
        },
        FieldSchema {
            name: "source",
            kind: FieldKind::Mac,
            derived: false,
            required: true,
            description: "Source MAC address",
        },
        FieldSchema {
            name: "ether_type",
            kind: FieldKind::Unsigned,
            derived: true,
            required: false,
            description: "EtherType discriminator",
        },
    ];
    SCHEMA.get_or_init(|| LayerSchema {
        protocol: protocol("ethernet"),
        name: "Ethernet II",
        fields: FIELDS,
    })
}

impl Layer for Ethernet {
    impl_layer_boilerplate!(Ethernet, ethernet_schema);

    fn field(&self, name: &str) -> Option<FieldValue> {
        match name {
            "destination" => Some(FieldValue::Mac(self.destination)),
            "source" => Some(FieldValue::Mac(self.source)),
            "ether_type" => Some(wire_u16(&self.ether_type)),
            _ => None,
        }
    }

    fn set_field(&mut self, name: &str, value: FieldValue) -> Result<(), FieldError> {
        match (name, value) {
            ("destination", value) => {
                self.destination =
                    mac(&value).ok_or_else(|| wrong_type(ethernet_schema(), name, "mac address"))?
            }
            ("source", value) => {
                self.source =
                    mac(&value).ok_or_else(|| wrong_type(ethernet_schema(), name, "mac address"))?
            }
            ("ether_type", value) => {
                return set_wire_u16(&mut self.ether_type, ethernet_schema(), name, value)
            }
            _ => return Err(unknown_field(ethernet_schema(), name)),
        }
        Ok(())
    }

    fn normalize(&mut self) {
        self.ether_type.normalize();
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct EthernetCodec;

impl LayerCodec for EthernetCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("ethernet")
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["eth", "ether", "ethernet2"]
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<Ethernet>()
            .ok_or_else(|| wrong_layer("ethernet", layer))?;
        let expectation = expected_discriminator("ethernet", context, 0_u16);
        let mut diagnostics = Vec::new();
        validate_auto_raw_discriminator(
            "ethernet",
            "ether_type",
            &layer.ether_type,
            context,
            &mut diagnostics,
        )?;
        let (ether_type, materialized_type) = resolve_u16(
            "ethernet",
            "ether_type",
            &layer.ether_type,
            expectation,
            context.mode,
            &mut diagnostics,
        )?;
        validate_raw_child_discriminator(
            "ethernet",
            u64::from(ether_type),
            context,
            &mut diagnostics,
        )?;
        let mut header = Vec::with_capacity(ETHERNET_LEN);
        header.extend_from_slice(&layer.destination);
        header.extend_from_slice(&layer.source);
        header.extend_from_slice(&ether_type.to_be_bytes());
        let mut materialized = layer.clone();
        materialized.ether_type = materialized_type;
        Ok(EncodedLayer {
            prefix: header,
            suffix: Vec::new(),
            materialized: Box::new(materialized),
            fields: vec![
                field_layout("destination", 0, 6),
                field_layout("source", 6, 12),
                field_layout("ether_type", 12, 14),
            ],
            diagnostics,
        })
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < ETHERNET_LEN {
            return Err(truncated("ethernet", ETHERNET_LEN, input.len()));
        }
        let mut destination = [0; 6];
        destination.copy_from_slice(&input[..6]);
        let mut source = [0; 6];
        source.copy_from_slice(&input[6..12]);
        let ether_type = u16::from_be_bytes([input[12], input[13]]);
        Ok(DecodedLayerValue {
            layer: Box::new(Ethernet {
                destination,
                source,
                ether_type: WireValue::Exact(ether_type),
            }),
            consumed: ETHERNET_LEN,
            payload_offset: ETHERNET_LEN,
            payload_len: input.len() - ETHERNET_LEN,
            next: vec![Discriminator(u64::from(ether_type))],
            fields: vec![
                field_layout("destination", 0, 6),
                field_layout("source", 6, 12),
                field_layout("ether_type", 12, 14),
            ],
            diagnostics: Vec::new(),
            stop: input.len() == ETHERNET_LEN,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(
            Ethernet::default(),
            &aliased_fields(
                "ethernet",
                fields,
                &[("dst", "destination"), ("src", "source")],
            )?,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vlan {
    pub priority: u8,
    pub drop_eligible: bool,
    pub vlan_id: u16,
    pub ether_type: WireValue<u16>,
}

impl Default for Vlan {
    fn default() -> Self {
        Self {
            priority: 0,
            drop_eligible: false,
            vlan_id: 1,
            ether_type: WireValue::Auto,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vlan8021ad {
    pub priority: u8,
    pub drop_eligible: bool,
    pub vlan_id: u16,
    pub ether_type: WireValue<u16>,
}

impl Default for Vlan8021ad {
    fn default() -> Self {
        Self {
            priority: 0,
            drop_eligible: false,
            vlan_id: 1,
            ether_type: WireValue::Auto,
        }
    }
}

fn vlan_fields() -> &'static [FieldSchema] {
    static FIELDS: &[FieldSchema] = &[
        FieldSchema {
            name: "priority",
            kind: FieldKind::Unsigned,
            derived: false,
            required: false,
            description: "IEEE 802.1 priority code point",
        },
        FieldSchema {
            name: "drop_eligible",
            kind: FieldKind::Bool,
            derived: false,
            required: false,
            description: "Drop eligible indicator",
        },
        FieldSchema {
            name: "vlan_id",
            kind: FieldKind::Unsigned,
            derived: false,
            required: true,
            description: "VLAN identifier",
        },
        FieldSchema {
            name: "ether_type",
            kind: FieldKind::Unsigned,
            derived: true,
            required: false,
            description: "Encapsulated EtherType",
        },
    ];
    FIELDS
}

fn vlan_schema() -> &'static LayerSchema {
    static SCHEMA: OnceLock<LayerSchema> = OnceLock::new();
    SCHEMA.get_or_init(|| LayerSchema {
        protocol: protocol("vlan"),
        name: "IEEE 802.1Q VLAN",
        fields: vlan_fields(),
    })
}

fn vlan_ad_schema() -> &'static LayerSchema {
    static SCHEMA: OnceLock<LayerSchema> = OnceLock::new();
    SCHEMA.get_or_init(|| LayerSchema {
        protocol: protocol("vlan8021ad"),
        name: "IEEE 802.1ad Service VLAN",
        fields: vlan_fields(),
    })
}

macro_rules! impl_vlan_layer {
    ($ty:ty, $schema:path) => {
        impl Layer for $ty {
            impl_layer_boilerplate!($ty, $schema);

            fn field(&self, name: &str) -> Option<FieldValue> {
                match name {
                    "priority" => Some(FieldValue::Unsigned(u64::from(self.priority))),
                    "drop_eligible" => Some(FieldValue::Bool(self.drop_eligible)),
                    "vlan_id" => Some(FieldValue::Unsigned(u64::from(self.vlan_id))),
                    "ether_type" => Some(wire_u16(&self.ether_type)),
                    _ => None,
                }
            }

            fn set_field(&mut self, name: &str, value: FieldValue) -> Result<(), FieldError> {
                match (name, value) {
                    ("priority", FieldValue::Unsigned(value)) => {
                        self.priority = u8::try_from(value)
                            .ok()
                            .filter(|value| *value <= 7)
                            .ok_or_else(|| out_of_range($schema(), name))?;
                    }
                    ("drop_eligible", FieldValue::Bool(value)) => self.drop_eligible = value,
                    ("vlan_id", FieldValue::Unsigned(value)) => {
                        self.vlan_id = u16::try_from(value)
                            .ok()
                            .filter(|value| *value <= 4095)
                            .ok_or_else(|| out_of_range($schema(), name))?;
                    }
                    ("ether_type", value) => {
                        return set_wire_u16(&mut self.ether_type, $schema(), name, value)
                    }
                    ("priority" | "vlan_id", _) => {
                        return Err(wrong_type($schema(), name, "unsigned"))
                    }
                    ("drop_eligible", _) => return Err(wrong_type($schema(), name, "bool")),
                    _ => return Err(unknown_field($schema(), name)),
                }
                Ok(())
            }

            fn normalize(&mut self) {
                self.ether_type.normalize();
            }
        }
    };
}

impl_vlan_layer!(Vlan, vlan_schema);
impl_vlan_layer!(Vlan8021ad, vlan_ad_schema);

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct VlanCodec;

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Vlan8021adCodec;

fn encode_vlan<L>(
    name: &str,
    priority: u8,
    drop_eligible: bool,
    vlan_id: u16,
    ether_type_value: &WireValue<u16>,
    context: &LayerEncodeContext<'_>,
    materialize: impl FnOnce(WireValue<u16>) -> L,
) -> Result<EncodedLayer, CodecError>
where
    L: Layer + Clone + 'static,
{
    if priority > 7 || vlan_id > 4095 {
        return Err(invalid(
            name,
            "VLAN priority or identifier is outside its wire range",
        ));
    }
    let expectation = expected_discriminator(name, context, 0_u16);
    let mut diagnostics = Vec::new();
    validate_auto_raw_discriminator(
        name,
        "ether_type",
        ether_type_value,
        context,
        &mut diagnostics,
    )?;
    let (ether_type, materialized_type) = resolve_u16(
        name,
        "ether_type",
        ether_type_value,
        expectation,
        context.mode,
        &mut diagnostics,
    )?;
    validate_raw_child_discriminator(name, u64::from(ether_type), context, &mut diagnostics)?;
    let tci = (u16::from(priority) << 13)
        | (if drop_eligible { 1 << 12 } else { 0 })
        | (vlan_id & 0x0fff);
    let mut prefix = Vec::with_capacity(VLAN_LEN);
    prefix.extend_from_slice(&tci.to_be_bytes());
    prefix.extend_from_slice(&ether_type.to_be_bytes());
    Ok(EncodedLayer {
        prefix,
        suffix: Vec::new(),
        materialized: Box::new(materialize(materialized_type)),
        fields: vec![
            field_layout("priority", 0, 2),
            field_layout("drop_eligible", 0, 2),
            field_layout("vlan_id", 0, 2),
            field_layout("ether_type", 2, 4),
        ],
        diagnostics,
    })
}

fn decode_vlan(
    name: &str,
    input: &[u8],
    layer: impl FnOnce(u8, bool, u16, WireValue<u16>) -> Box<dyn Layer>,
) -> Result<DecodedLayerValue, CodecError> {
    if input.len() < VLAN_LEN {
        return Err(truncated(name, VLAN_LEN, input.len()));
    }
    let tci = u16::from_be_bytes([input[0], input[1]]);
    let ether_type = u16::from_be_bytes([input[2], input[3]]);
    Ok(DecodedLayerValue {
        layer: layer(
            ((tci >> 13) & 7) as u8,
            (tci & 0x1000) != 0,
            tci & 0x0fff,
            WireValue::Exact(ether_type),
        ),
        consumed: VLAN_LEN,
        payload_offset: VLAN_LEN,
        payload_len: input.len() - VLAN_LEN,
        next: vec![Discriminator(u64::from(ether_type))],
        fields: vec![
            field_layout("priority", 0, 2),
            field_layout("drop_eligible", 0, 2),
            field_layout("vlan_id", 0, 2),
            field_layout("ether_type", 2, 4),
        ],
        diagnostics: Vec::new(),
        stop: input.len() == VLAN_LEN,
        network: None,
    })
}

impl LayerCodec for VlanCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("vlan")
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["dot1q", "8021q"]
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<Vlan>()
            .ok_or_else(|| wrong_layer("vlan", layer))?;
        encode_vlan(
            "vlan",
            layer.priority,
            layer.drop_eligible,
            layer.vlan_id,
            &layer.ether_type,
            context,
            |ether_type| Vlan {
                ether_type,
                ..layer.clone()
            },
        )
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        decode_vlan(
            "vlan",
            input,
            |priority, drop_eligible, vlan_id, ether_type| {
                Box::new(Vlan {
                    priority,
                    drop_eligible,
                    vlan_id,
                    ether_type,
                })
            },
        )
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(
            Vlan::default(),
            &aliased_fields(
                "vlan",
                fields,
                &[
                    ("vid", "vlan_id"),
                    ("pcp", "priority"),
                    ("dei", "drop_eligible"),
                ],
            )?,
        )
    }
}

impl LayerCodec for Vlan8021adCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("vlan8021ad")
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["dot1ad", "8021ad", "qinq"]
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<Vlan8021ad>()
            .ok_or_else(|| wrong_layer("vlan8021ad", layer))?;
        encode_vlan(
            "vlan8021ad",
            layer.priority,
            layer.drop_eligible,
            layer.vlan_id,
            &layer.ether_type,
            context,
            |ether_type| Vlan8021ad {
                ether_type,
                ..layer.clone()
            },
        )
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        decode_vlan(
            "vlan8021ad",
            input,
            |priority, drop_eligible, vlan_id, ether_type| {
                Box::new(Vlan8021ad {
                    priority,
                    drop_eligible,
                    vlan_id,
                    ether_type,
                })
            },
        )
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(
            Vlan8021ad::default(),
            &aliased_fields(
                "vlan8021ad",
                fields,
                &[
                    ("vid", "vlan_id"),
                    ("pcp", "priority"),
                    ("dei", "drop_eligible"),
                ],
            )?,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Arp {
    pub hardware_type: u16,
    pub protocol_type: u16,
    pub hardware_len: WireValue<u8>,
    pub protocol_len: WireValue<u8>,
    pub operation: u16,
    pub sender_hardware: [u8; 6],
    pub sender_protocol: Ipv4Addr,
    pub target_hardware: [u8; 6],
    pub target_protocol: Ipv4Addr,
}

impl Default for Arp {
    fn default() -> Self {
        Self {
            hardware_type: 1,
            protocol_type: 0x0800,
            hardware_len: WireValue::Auto,
            protocol_len: WireValue::Auto,
            operation: 1,
            sender_hardware: [0; 6],
            sender_protocol: Ipv4Addr::UNSPECIFIED,
            target_hardware: [0; 6],
            target_protocol: Ipv4Addr::UNSPECIFIED,
        }
    }
}

fn arp_schema() -> &'static LayerSchema {
    static SCHEMA: OnceLock<LayerSchema> = OnceLock::new();
    static FIELDS: &[FieldSchema] = &[
        FieldSchema {
            name: "hardware_type",
            kind: FieldKind::Unsigned,
            derived: false,
            required: true,
            description: "Hardware address family",
        },
        FieldSchema {
            name: "protocol_type",
            kind: FieldKind::Unsigned,
            derived: false,
            required: true,
            description: "Protocol address family",
        },
        FieldSchema {
            name: "hardware_len",
            kind: FieldKind::Unsigned,
            derived: true,
            required: false,
            description: "Hardware address length",
        },
        FieldSchema {
            name: "protocol_len",
            kind: FieldKind::Unsigned,
            derived: true,
            required: false,
            description: "Protocol address length",
        },
        FieldSchema {
            name: "operation",
            kind: FieldKind::Unsigned,
            derived: false,
            required: true,
            description: "ARP operation",
        },
        FieldSchema {
            name: "sender_hardware",
            kind: FieldKind::Mac,
            derived: false,
            required: true,
            description: "Sender hardware address",
        },
        FieldSchema {
            name: "sender_protocol",
            kind: FieldKind::Ipv4,
            derived: false,
            required: true,
            description: "Sender IPv4 address",
        },
        FieldSchema {
            name: "target_hardware",
            kind: FieldKind::Mac,
            derived: false,
            required: true,
            description: "Target hardware address",
        },
        FieldSchema {
            name: "target_protocol",
            kind: FieldKind::Ipv4,
            derived: false,
            required: true,
            description: "Target IPv4 address",
        },
    ];
    SCHEMA.get_or_init(|| LayerSchema {
        protocol: protocol("arp"),
        name: "ARP",
        fields: FIELDS,
    })
}

impl Layer for Arp {
    impl_layer_boilerplate!(Arp, arp_schema);

    fn field(&self, name: &str) -> Option<FieldValue> {
        match name {
            "hardware_type" => Some(self.hardware_type.into()),
            "protocol_type" => Some(self.protocol_type.into()),
            "hardware_len" => Some(wire_u8(&self.hardware_len)),
            "protocol_len" => Some(wire_u8(&self.protocol_len)),
            "operation" => Some(self.operation.into()),
            "sender_hardware" => Some(FieldValue::Mac(self.sender_hardware)),
            "sender_protocol" => Some(FieldValue::Ipv4(self.sender_protocol)),
            "target_hardware" => Some(FieldValue::Mac(self.target_hardware)),
            "target_protocol" => Some(FieldValue::Ipv4(self.target_protocol)),
            _ => None,
        }
    }

    fn set_field(&mut self, name: &str, value: FieldValue) -> Result<(), FieldError> {
        match (name, value) {
            ("hardware_type", FieldValue::Unsigned(value)) => {
                self.hardware_type =
                    u16::try_from(value).map_err(|_| out_of_range(arp_schema(), name))?
            }
            ("protocol_type", FieldValue::Unsigned(value)) => {
                self.protocol_type =
                    u16::try_from(value).map_err(|_| out_of_range(arp_schema(), name))?
            }
            ("hardware_len", value) => {
                return set_wire_u8(&mut self.hardware_len, arp_schema(), name, value)
            }
            ("protocol_len", value) => {
                return set_wire_u8(&mut self.protocol_len, arp_schema(), name, value)
            }
            ("operation", FieldValue::Unsigned(value)) => {
                self.operation =
                    u16::try_from(value).map_err(|_| out_of_range(arp_schema(), name))?
            }
            ("sender_hardware", value) => {
                self.sender_hardware =
                    mac(&value).ok_or_else(|| wrong_type(arp_schema(), name, "mac address"))?
            }
            ("target_hardware", value) => {
                self.target_hardware =
                    mac(&value).ok_or_else(|| wrong_type(arp_schema(), name, "mac address"))?
            }
            ("sender_protocol", value) => {
                self.sender_protocol =
                    ipv4(&value).ok_or_else(|| wrong_type(arp_schema(), name, "ipv4"))?
            }
            ("target_protocol", value) => {
                self.target_protocol =
                    ipv4(&value).ok_or_else(|| wrong_type(arp_schema(), name, "ipv4"))?
            }
            ("hardware_type" | "protocol_type" | "operation", _) => {
                return Err(wrong_type(arp_schema(), name, "unsigned"))
            }
            _ => return Err(unknown_field(arp_schema(), name)),
        }
        Ok(())
    }

    fn normalize(&mut self) {
        self.hardware_len.normalize();
        self.protocol_len.normalize();
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct ArpCodec;

impl LayerCodec for ArpCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("arp")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<Arp>()
            .ok_or_else(|| wrong_layer("arp", layer))?;
        let mut diagnostics = Vec::new();
        if layer.hardware_type != 1 || layer.protocol_type != 0x0800 {
            let message = format!(
                "typed ARP requires Ethernet/IPv4 types (htype={}, ptype=0x{:04x})",
                layer.hardware_type, layer.protocol_type
            );
            if context.mode == crate::packet::internal::BuildMode::Strict {
                return Err(CodecError::Unsupported {
                    protocol: protocol("arp"),
                    message,
                });
            }
            diagnostics.push(
                crate::packet::internal::Diagnostic::warning("build.arp_address_types", message)
                    .at_field("hardware_type"),
            );
        }
        let (hardware_len, materialized_hardware_len) = resolve_u8(
            "arp",
            "hardware_len",
            &layer.hardware_len,
            ValueExpectation::Required(6),
            context.mode,
            &mut diagnostics,
        )?;
        let (protocol_len, materialized_protocol_len) = resolve_u8(
            "arp",
            "protocol_len",
            &layer.protocol_len,
            ValueExpectation::Required(4),
            context.mode,
            &mut diagnostics,
        )?;
        let mut prefix = Vec::with_capacity(ARP_ETHERNET_IPV4_LEN);
        prefix.extend_from_slice(&layer.hardware_type.to_be_bytes());
        prefix.extend_from_slice(&layer.protocol_type.to_be_bytes());
        prefix.push(hardware_len);
        prefix.push(protocol_len);
        prefix.extend_from_slice(&layer.operation.to_be_bytes());
        prefix.extend_from_slice(&layer.sender_hardware);
        prefix.extend_from_slice(&layer.sender_protocol.octets());
        prefix.extend_from_slice(&layer.target_hardware);
        prefix.extend_from_slice(&layer.target_protocol.octets());
        let mut materialized = layer.clone();
        materialized.hardware_len = materialized_hardware_len;
        materialized.protocol_len = materialized_protocol_len;
        Ok(EncodedLayer {
            prefix,
            suffix: Vec::new(),
            materialized: Box::new(materialized),
            fields: vec![
                field_layout("hardware_type", 0, 2),
                field_layout("protocol_type", 2, 4),
                field_layout("hardware_len", 4, 5),
                field_layout("protocol_len", 5, 6),
                field_layout("operation", 6, 8),
                field_layout("sender_hardware", 8, 14),
                field_layout("sender_protocol", 14, 18),
                field_layout("target_hardware", 18, 24),
                field_layout("target_protocol", 24, 28),
            ],
            diagnostics,
        })
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < 8 {
            return Err(truncated("arp", 8, input.len()));
        }
        let hardware_len = input[4];
        let protocol_len = input[5];
        let hardware_type = u16::from_be_bytes([input[0], input[1]]);
        let protocol_type = u16::from_be_bytes([input[2], input[3]]);
        if hardware_type != 1 || protocol_type != 0x0800 || hardware_len != 6 || protocol_len != 4 {
            return Err(CodecError::Unsupported {
                protocol: protocol("arp"),
                message: format!(
                    "only Ethernet/IPv4 ARP is typed (htype={hardware_type}, ptype=0x{protocol_type:04x}, hlen={hardware_len}, plen={protocol_len})"
                ),
            });
        }
        if input.len() < ARP_ETHERNET_IPV4_LEN {
            return Err(truncated("arp", ARP_ETHERNET_IPV4_LEN, input.len()));
        }
        let mut sender_hardware = [0; 6];
        sender_hardware.copy_from_slice(&input[8..14]);
        let mut target_hardware = [0; 6];
        target_hardware.copy_from_slice(&input[18..24]);
        let layer = Arp {
            hardware_type,
            protocol_type,
            hardware_len: WireValue::Exact(hardware_len),
            protocol_len: WireValue::Exact(protocol_len),
            operation: u16::from_be_bytes([input[6], input[7]]),
            sender_hardware,
            sender_protocol: Ipv4Addr::new(input[14], input[15], input[16], input[17]),
            target_hardware,
            target_protocol: Ipv4Addr::new(input[24], input[25], input[26], input[27]),
        };
        Ok(DecodedLayerValue {
            layer: Box::new(layer),
            consumed: ARP_ETHERNET_IPV4_LEN,
            payload_offset: ARP_ETHERNET_IPV4_LEN,
            payload_len: 0,
            next: Vec::new(),
            fields: vec![
                field_layout("hardware_type", 0, 2),
                field_layout("protocol_type", 2, 4),
                field_layout("hardware_len", 4, 5),
                field_layout("protocol_len", 5, 6),
                field_layout("operation", 6, 8),
                field_layout("sender_hardware", 8, 14),
                field_layout("sender_protocol", 14, 18),
                field_layout("target_hardware", 18, 24),
                field_layout("target_protocol", 24, 28),
            ],
            diagnostics: Vec::new(),
            stop: true,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(
            Arp::default(),
            &aliased_fields(
                "arp",
                fields,
                &[
                    ("sha", "sender_hardware"),
                    ("spa", "sender_protocol"),
                    ("tha", "target_hardware"),
                    ("tpa", "target_protocol"),
                    ("op", "operation"),
                ],
            )?,
        )
    }
}
