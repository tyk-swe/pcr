// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use crate::packet::{
    codec::{
        CodecError, DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext,
        LayerEncodeContext,
    },
    diagnostic::Diagnostic,
    field::{FieldValue, WireValue},
    layer::{Layer, ProtocolId, reflect_get, reflect_set, reflective_layer},
    registry::Discriminator,
};

use super::super::common::{
    binding_protocol, expected_discriminator, invalid, make_layer, out_of_range, protocol,
    resolve_u16, truncated, validate_auto_raw_discriminator, validate_raw_child_discriminator,
    wrong_layer, wrong_type,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CaptureByteOrder {
    #[default]
    Little,
    Big,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BsdNull {
    pub family: u32,
    pub byte_order: CaptureByteOrder,
}

impl Default for BsdNull {
    fn default() -> Self {
        Self {
            family: 2,
            byte_order: CaptureByteOrder::Little,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BsdLoop {
    pub family: u32,
}

impl Default for BsdLoop {
    fn default() -> Self {
        Self { family: 2 }
    }
}

reflective_layer! {
    fn loop_schema() => { protocol: protocol("bsd_loop"), name: "BSD LOOP" }
    impl BsdLoop {
        "family" => { kind: Unsigned, derived: false, required: true, description: "Address-family discriminator", get |layer| Some(reflect_get(&layer.family)), set |layer, value, name| reflect_set(&mut layer.family, loop_schema(), name, value), layout: (0, 4) }
    }
    layout fn loop_layout();
}

reflective_layer! {
    fn null_schema() => { protocol: protocol("bsd_null"), name: "BSD NULL" }
    impl BsdNull {
        "family" => { kind: Unsigned, derived: false, required: true, description: "Address-family discriminator", get |layer| Some(reflect_get(&layer.family)), set |layer, value, name| reflect_set(&mut layer.family, null_schema(), name, value), layout: (0, 4) },
        "byte_order" => { kind: Text, derived: false, required: true, description: "Host byte order used by the captured NULL header", get |layer| Some(FieldValue::Text(match layer.byte_order { CaptureByteOrder::Little => "little", CaptureByteOrder::Big => "big" }.to_owned())), set |layer, value, name| match value { FieldValue::Text(value) if value.eq_ignore_ascii_case("little") => { layer.byte_order = CaptureByteOrder::Little; Ok(()) }, FieldValue::Text(value) if value.eq_ignore_ascii_case("big") => { layer.byte_order = CaptureByteOrder::Big; Ok(()) }, FieldValue::Text(_) => Err(out_of_range(null_schema(), name)), _ => Err(wrong_type(null_schema(), name, "text")) }, layout: (0, 4) }
    }
    layout fn null_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct BsdNullCodec;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct BsdLoopCodec;

#[derive(Clone, Copy, Debug)]
enum FamilyHeader {
    Null,
    Loop,
}

fn family_discriminator(family: u32) -> u64 {
    match family {
        2 => 4,
        10 | 24 | 28 | 30 => 6,
        other => u64::from(other),
    }
}

fn validate_family_binding(
    parent: &str,
    family: u32,
    context: &LayerEncodeContext<'_>,
) -> Result<Vec<Diagnostic>, CodecError> {
    let mut diagnostics = Vec::new();
    validate_raw_child_discriminator(
        parent,
        family_discriminator(family),
        context,
        &mut diagnostics,
    )?;
    let Some(child) = context.child else {
        return Ok(diagnostics);
    };
    if child.protocol_id().as_str() == "raw" {
        return Ok(diagnostics);
    }
    let Some(expected) = context
        .registry
        .discriminator_for(&protocol(parent), &binding_protocol(child))
    else {
        return Ok(diagnostics);
    };
    let actual = family_discriminator(family);
    if actual == expected.0 {
        return Ok(diagnostics);
    }
    let message = format!(
        "address family {family} selects discriminator {actual}, but child {} requires {}",
        child.protocol_id(),
        expected.0
    );
    if context.mode == crate::packet::build::BuildMode::Strict {
        return Err(invalid(parent, message));
    }
    diagnostics
        .push(Diagnostic::warning("build.capture_family_binding", message).at_field("family"));
    Ok(diagnostics)
}

impl LayerCodec for BsdNullCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("bsd_null")
    }

    fn aliases(&self) -> &'static [&'static str] {
        super::super::support::aliases(self.protocol_id().as_str())
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<BsdNull>()
            .ok_or_else(|| wrong_layer("bsd_null", layer))?;
        let prefix = match layer.byte_order {
            CaptureByteOrder::Little => layer.family.to_le_bytes(),
            CaptureByteOrder::Big => layer.family.to_be_bytes(),
        };
        let mut encoded = EncodedLayer::header(prefix.to_vec(), Box::new(layer.clone()));
        encoded.fields = null_layout();
        encoded.diagnostics = validate_family_binding("bsd_null", layer.family, context)?;
        Ok(encoded)
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        decode_family(input, FamilyHeader::Null)
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(BsdNull::default(), fields)
    }
}

impl LayerCodec for BsdLoopCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("bsd_loop")
    }

    fn aliases(&self) -> &'static [&'static str] {
        super::super::support::aliases(self.protocol_id().as_str())
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<BsdLoop>()
            .ok_or_else(|| wrong_layer("bsd_loop", layer))?;
        let mut encoded =
            EncodedLayer::header(layer.family.to_be_bytes().to_vec(), Box::new(layer.clone()));
        encoded.fields = loop_layout();
        encoded.diagnostics = validate_family_binding("bsd_loop", layer.family, context)?;
        Ok(encoded)
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        decode_family(input, FamilyHeader::Loop)
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(BsdLoop::default(), fields)
    }
}

fn decode_family(input: &[u8], header: FamilyHeader) -> Result<DecodedLayerValue, CodecError> {
    let name = match header {
        FamilyHeader::Null => "bsd_null",
        FamilyHeader::Loop => "bsd_loop",
    };
    if input.len() < 4 {
        return Err(truncated(name, 4, input.len()));
    }
    let bytes = [input[0], input[1], input[2], input[3]];
    let big = u32::from_be_bytes(bytes);
    let little = u32::from_le_bytes(bytes);
    let (family, byte_order) = match header {
        FamilyHeader::Loop => (big, CaptureByteOrder::Big),
        FamilyHeader::Null if matches!(little, 2 | 10 | 24 | 28 | 30) => {
            (little, CaptureByteOrder::Little)
        }
        FamilyHeader::Null => (big, CaptureByteOrder::Big),
    };
    let layer: Box<dyn Layer> = match header {
        FamilyHeader::Loop => Box::new(BsdLoop { family }),
        FamilyHeader::Null => Box::new(BsdNull { family, byte_order }),
    };
    Ok(DecodedLayerValue {
        layer,
        consumed: 4,
        payload_offset: 4,
        payload_len: input.len() - 4,
        next: vec![Discriminator(family_discriminator(family))],
        fields: match header {
            FamilyHeader::Loop => loop_layout(),
            FamilyHeader::Null => null_layout(),
        },
        diagnostics: Vec::new(),
        stop: input.len() == 4,
        network: None,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinuxSll {
    pub packet_type: u16,
    pub arp_hardware_type: u16,
    pub address_length: u16,
    pub address: [u8; 8],
    pub protocol: WireValue<u16>,
}

impl Default for LinuxSll {
    fn default() -> Self {
        Self {
            packet_type: 0,
            arp_hardware_type: 1,
            address_length: 6,
            address: [0; 8],
            protocol: WireValue::Auto,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinuxSll2 {
    pub protocol: WireValue<u16>,
    pub interface_index: u32,
    pub arp_hardware_type: u16,
    pub packet_type: u8,
    pub address_length: u8,
    pub address: [u8; 8],
}

impl Default for LinuxSll2 {
    fn default() -> Self {
        Self {
            protocol: WireValue::Auto,
            interface_index: 0,
            arp_hardware_type: 1,
            packet_type: 0,
            address_length: 6,
            address: [0; 8],
        }
    }
}

reflective_layer! {
    fn linux_sll_schema() => { protocol: protocol("linux_sll"), name: "Linux cooked capture v1" }
    impl LinuxSll {
        "protocol" => { kind: Unsigned, derived: true, required: false, description: "Protocol discriminator", get |layer| Some(reflect_get(&layer.protocol)), set |layer, value, name| reflect_set(&mut layer.protocol, linux_sll_schema(), name, value), layout: (14, 16) },
        "packet_type" => { kind: Unsigned, derived: false, required: true, description: "Packet direction/type", get |layer| Some(reflect_get(&layer.packet_type)), set |layer, value, name| reflect_set(&mut layer.packet_type, linux_sll_schema(), name, value), layout: (0, 2) },
        "arp_hardware_type" => { kind: Unsigned, derived: false, required: true, description: "ARP hardware type", get |layer| Some(reflect_get(&layer.arp_hardware_type)), set |layer, value, name| reflect_set(&mut layer.arp_hardware_type, linux_sll_schema(), name, value), layout: (2, 4) },
        "address_length" => { kind: Unsigned, derived: false, required: true, description: "Link address length", get |layer| Some(reflect_get(&layer.address_length)), set |layer, value, name| match value { FieldValue::Unsigned(value) => { layer.address_length = u16::try_from(value).ok().filter(|value| *value <= 8).ok_or_else(|| out_of_range(linux_sll_schema(), name))?; Ok(()) }, _ => Err(wrong_type(linux_sll_schema(), name, "unsigned")) }, layout: (4, 6) },
        "address" => { kind: Bytes, derived: false, required: false, description: "Eight-byte link address slot", get |layer| Some(reflect_get(&layer.address)), set |layer, value, name| reflect_set(&mut layer.address, linux_sll_schema(), name, value), layout: (6, 14) },
        normalize |layer| { layer.protocol.normalize(); }
    }
    layout fn linux_sll_layout();
}

reflective_layer! {
    fn linux_sll2_schema() => { protocol: protocol("linux_sll2"), name: "Linux cooked capture v2" }
    impl LinuxSll2 {
        "protocol" => { kind: Unsigned, derived: true, required: false, description: "Protocol discriminator", get |layer| Some(reflect_get(&layer.protocol)), set |layer, value, name| reflect_set(&mut layer.protocol, linux_sll2_schema(), name, value), layout: (0, 2) },
        "packet_type" => { kind: Unsigned, derived: false, required: true, description: "Packet direction/type", get |layer| Some(reflect_get(&layer.packet_type)), set |layer, value, name| reflect_set(&mut layer.packet_type, linux_sll2_schema(), name, value), layout: (10, 11) },
        "arp_hardware_type" => { kind: Unsigned, derived: false, required: true, description: "ARP hardware type", get |layer| Some(reflect_get(&layer.arp_hardware_type)), set |layer, value, name| reflect_set(&mut layer.arp_hardware_type, linux_sll2_schema(), name, value), layout: (8, 10) },
        "interface_index" => { kind: Unsigned, derived: false, required: false, description: "Interface index", get |layer| Some(reflect_get(&layer.interface_index)), set |layer, value, name| reflect_set(&mut layer.interface_index, linux_sll2_schema(), name, value), layout: (4, 8) },
        "address_length" => { kind: Unsigned, derived: false, required: true, description: "Link address length", get |layer| Some(reflect_get(&layer.address_length)), set |layer, value, name| match value { FieldValue::Unsigned(value) => { layer.address_length = u8::try_from(value).ok().filter(|value| *value <= 8).ok_or_else(|| out_of_range(linux_sll2_schema(), name))?; Ok(()) }, _ => Err(wrong_type(linux_sll2_schema(), name, "unsigned")) }, layout: (11, 12) },
        "address" => { kind: Bytes, derived: false, required: false, description: "Eight-byte link address slot", get |layer| Some(reflect_get(&layer.address)), set |layer, value, name| reflect_set(&mut layer.address, linux_sll2_schema(), name, value), layout: (12, 20) },
        normalize |layer| { layer.protocol.normalize(); }
    }
    layout fn linux_sll2_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct LinuxSllCodec;
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct LinuxSll2Codec;

impl LayerCodec for LinuxSllCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("linux_sll")
    }
    fn aliases(&self) -> &'static [&'static str] {
        super::super::support::aliases(self.protocol_id().as_str())
    }
    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<LinuxSll>()
            .ok_or_else(|| wrong_layer("linux_sll", layer))?;
        if layer.address_length > 8 {
            return Err(invalid("linux_sll", "address length exceeds slot"));
        }
        let mut diagnostics = Vec::new();
        let expectation = expected_discriminator("linux_sll", context, 0_u16);
        validate_auto_raw_discriminator(
            "linux_sll",
            "protocol",
            &layer.protocol,
            context,
            &mut diagnostics,
        )?;
        let (protocol_value, materialized_protocol) = resolve_u16(
            "linux_sll",
            "protocol",
            &layer.protocol,
            expectation,
            context.mode,
            &mut diagnostics,
        )?;
        validate_raw_child_discriminator(
            "linux_sll",
            u64::from(protocol_value),
            context,
            &mut diagnostics,
        )?;
        let mut prefix = Vec::with_capacity(16);
        prefix.extend_from_slice(&layer.packet_type.to_be_bytes());
        prefix.extend_from_slice(&layer.arp_hardware_type.to_be_bytes());
        prefix.extend_from_slice(&layer.address_length.to_be_bytes());
        prefix.extend_from_slice(&layer.address);
        prefix.extend_from_slice(&protocol_value.to_be_bytes());
        let mut materialized = layer.clone();
        materialized.protocol = materialized_protocol;
        Ok(EncodedLayer {
            prefix,
            suffix: Vec::new(),
            materialized: Box::new(materialized),
            fields: linux_sll_layout(),
            diagnostics,
        })
    }
    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < 16 {
            return Err(truncated("linux_sll", 16, input.len()));
        }
        let address_length = u16::from_be_bytes([input[4], input[5]]);
        if address_length > 8 {
            return Err(invalid("linux_sll", "address length exceeds slot"));
        }
        let mut address = [0; 8];
        address.copy_from_slice(&input[6..14]);
        let protocol_value = u16::from_be_bytes([input[14], input[15]]);
        Ok(DecodedLayerValue {
            layer: Box::new(LinuxSll {
                packet_type: u16::from_be_bytes([input[0], input[1]]),
                arp_hardware_type: u16::from_be_bytes([input[2], input[3]]),
                address_length,
                address,
                protocol: WireValue::Exact(protocol_value),
            }),
            consumed: 16,
            payload_offset: 16,
            payload_len: input.len() - 16,
            next: vec![Discriminator(protocol_value.into())],
            fields: linux_sll_layout(),
            diagnostics: Vec::new(),
            stop: input.len() == 16,
            network: None,
        })
    }
    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(LinuxSll::default(), fields)
    }
}

impl LayerCodec for LinuxSll2Codec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("linux_sll2")
    }
    fn aliases(&self) -> &'static [&'static str] {
        super::super::support::aliases(self.protocol_id().as_str())
    }
    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<LinuxSll2>()
            .ok_or_else(|| wrong_layer("linux_sll2", layer))?;
        if layer.address_length > 8 {
            return Err(invalid("linux_sll2", "address length exceeds slot"));
        }
        let mut diagnostics = Vec::new();
        let expectation = expected_discriminator("linux_sll2", context, 0_u16);
        validate_auto_raw_discriminator(
            "linux_sll2",
            "protocol",
            &layer.protocol,
            context,
            &mut diagnostics,
        )?;
        let (protocol_value, materialized_protocol) = resolve_u16(
            "linux_sll2",
            "protocol",
            &layer.protocol,
            expectation,
            context.mode,
            &mut diagnostics,
        )?;
        validate_raw_child_discriminator(
            "linux_sll2",
            u64::from(protocol_value),
            context,
            &mut diagnostics,
        )?;
        let mut prefix = Vec::with_capacity(20);
        prefix.extend_from_slice(&protocol_value.to_be_bytes());
        prefix.extend_from_slice(&[0, 0]);
        prefix.extend_from_slice(&layer.interface_index.to_be_bytes());
        prefix.extend_from_slice(&layer.arp_hardware_type.to_be_bytes());
        prefix.push(layer.packet_type);
        prefix.push(layer.address_length);
        prefix.extend_from_slice(&layer.address);
        let mut materialized = layer.clone();
        materialized.protocol = materialized_protocol;
        Ok(EncodedLayer {
            prefix,
            suffix: Vec::new(),
            materialized: Box::new(materialized),
            fields: linux_sll2_layout(),
            diagnostics,
        })
    }
    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < 20 {
            return Err(truncated("linux_sll2", 20, input.len()));
        }
        if input[2] != 0 || input[3] != 0 {
            return Err(invalid("linux_sll2", "reserved field is non-zero"));
        }
        if input[11] > 8 {
            return Err(invalid("linux_sll2", "address length exceeds slot"));
        }
        let protocol_value = u16::from_be_bytes([input[0], input[1]]);
        let mut address = [0; 8];
        address.copy_from_slice(&input[12..20]);
        Ok(DecodedLayerValue {
            layer: Box::new(LinuxSll2 {
                protocol: WireValue::Exact(protocol_value),
                interface_index: u32::from_be_bytes([input[4], input[5], input[6], input[7]]),
                arp_hardware_type: u16::from_be_bytes([input[8], input[9]]),
                packet_type: input[10],
                address_length: input[11],
                address,
            }),
            consumed: 20,
            payload_offset: 20,
            payload_len: input.len() - 20,
            next: vec![Discriminator(protocol_value.into())],
            fields: linux_sll2_layout(),
            diagnostics: Vec::new(),
            stop: input.len() == 20,
            network: None,
        })
    }
    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(LinuxSll2::default(), fields)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::SystemTime;

    use super::*;
    use crate::capture::{Frame, LinkType};
    use crate::packet::layer::Raw;
    use crate::packet::{
        Packet,
        build::{BuildContext, BuildOptions, Builder},
        decode::{DecodeOptions, Dissector},
        document::PacketDocument,
    };
    use crate::protocol::{
        builtin::registry as default_registry,
        network::{Ipv4, Ipv6},
    };

    fn ipv4_bytes() -> Vec<u8> {
        let registry = Arc::new(default_registry().unwrap());
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            source: "192.0.2.1".parse().unwrap(),
            destination: "198.51.100.2".parse().unwrap(),
            ..Ipv4::default()
        });
        Builder::new(registry)
            .build(packet, BuildContext::default(), BuildOptions::default())
            .unwrap()
            .bytes
            .to_vec()
    }

    #[test]
    fn truncated_loopback_header_reports_the_selected_protocol() {
        assert!(matches!(
            decode_family(&[0, 0, 0], FamilyHeader::Loop),
            Err(CodecError::Truncated {
                protocol: actual,
                needed: 4,
                available: 3,
            }) if actual == protocol("bsd_loop")
        ));
    }

    #[test]
    fn cooked_link_build_rejects_address_length_beyond_wire_slot() {
        let registry = Arc::new(default_registry().unwrap());
        let builder = Builder::new(registry);

        let mut sll = Packet::new();
        sll.push(LinuxSll {
            address_length: 9,
            ..LinuxSll::default()
        });
        assert!(
            builder
                .build(sll, BuildContext::default(), BuildOptions::default())
                .is_err()
        );

        let mut sll2 = Packet::new();
        sll2.push(LinuxSll2 {
            address_length: 9,
            ..LinuxSll2::default()
        });
        assert!(
            builder
                .build(sll2, BuildContext::default(), BuildOptions::default())
                .is_err()
        );
    }

    #[test]
    fn null_and_loop_endianness_decode_to_ipv4() {
        let registry = Arc::new(default_registry().unwrap());
        for (link_type, family) in [
            (LinkType::NULL, 2u32.to_le_bytes()),
            (LinkType::NULL, 2u32.to_be_bytes()),
            (LinkType::LOOP, 2u32.to_be_bytes()),
        ] {
            let mut frame = family.to_vec();
            frame.extend_from_slice(&ipv4_bytes());
            let decoded = Dissector::new(Arc::clone(&registry))
                .decode(
                    Frame::new(SystemTime::UNIX_EPOCH, link_type, frame).unwrap(),
                    DecodeOptions::default(),
                )
                .unwrap();
            assert!(decoded.packet.get::<Ipv4>().is_some());
        }
    }

    #[test]
    fn sll_and_sll2_use_their_protocol_offsets() {
        let registry = Arc::new(default_registry().unwrap());
        let ip = ipv4_bytes();
        let mut sll = vec![0, 0, 0, 1, 0, 6, 0, 1, 2, 3, 4, 5, 0, 0, 0x08, 0x00];
        sll.extend_from_slice(&ip);
        let mut sll2 = vec![
            0x08, 0x00, 0, 0, 0, 0, 0, 7, 0, 1, 0, 6, 0, 1, 2, 3, 4, 5, 0, 0,
        ];
        sll2.extend_from_slice(&ip);

        let first = Dissector::new(Arc::clone(&registry))
            .decode(
                Frame::new(SystemTime::UNIX_EPOCH, LinkType::LINUX_SLL, sll).unwrap(),
                DecodeOptions::default(),
            )
            .unwrap();
        let second = Dissector::new(registry)
            .decode(
                Frame::new(SystemTime::UNIX_EPOCH, LinkType::LINUX_SLL2, sll2).unwrap(),
                DecodeOptions::default(),
            )
            .unwrap();
        assert!(first.packet.get::<LinuxSll>().is_some());
        assert!(first.packet.get::<Ipv4>().is_some());
        assert_eq!(second.packet.get::<LinuxSll2>().unwrap().interface_index, 7);
        assert!(second.packet.get::<Ipv4>().is_some());
    }

    #[test]
    fn unknown_sll_protocols_rebuild_exactly_as_raw() {
        let registry = Arc::new(default_registry().unwrap());
        let builder = Builder::new(Arc::clone(&registry));
        for (root, mut frame) in [
            (
                "linux_sll",
                vec![0, 0, 0, 1, 0, 6, 0, 1, 2, 3, 4, 5, 0, 0, 0x12, 0x34],
            ),
            (
                "linux_sll2",
                vec![
                    0x12, 0x34, 0, 0, 0, 0, 0, 7, 0, 1, 0, 6, 0, 1, 2, 3, 4, 5, 0, 0,
                ],
            ),
        ] {
            frame.extend_from_slice(&[0xaa, 0xbb]);
            let decoded = Dissector::new(Arc::clone(&registry))
                .decode_with_root(frame.clone(), root.into(), DecodeOptions::default())
                .unwrap();
            assert!(decoded.packet.get::<Raw>().is_some());
            let document = PacketDocument::from_packet(&decoded.packet);
            let reloaded = document.to_packet(&registry, 64).unwrap();
            let rebuilt = builder
                .build(reloaded, BuildContext::default(), BuildOptions::default())
                .unwrap();
            assert_eq!(rebuilt.bytes.as_ref(), frame);
        }
    }

    #[test]
    fn strict_capture_family_must_match_typed_child() {
        let registry = Arc::new(default_registry().unwrap());
        let mut packet = Packet::new();
        packet.push(BsdLoop { family: 2 }).push(Ipv6 {
            source: "2001:db8::1".parse().unwrap(),
            destination: "2001:db8::2".parse().unwrap(),
            ..Ipv6::default()
        });

        assert!(
            Builder::new(registry)
                .build(packet, BuildContext::default(), BuildOptions::default())
                .is_err()
        );
    }

    #[test]
    fn big_endian_null_byte_order_survives_packet_documents() {
        let registry = Arc::new(default_registry().unwrap());
        let mut bytes = 2_u32.to_be_bytes().to_vec();
        bytes.extend_from_slice(&ipv4_bytes());
        let decoded = Dissector::new(Arc::clone(&registry))
            .decode_with_root(
                bytes.clone(),
                protocol("bsd_null"),
                DecodeOptions::default(),
            )
            .unwrap();
        assert_eq!(
            decoded.packet.get::<BsdNull>().unwrap().byte_order,
            CaptureByteOrder::Big
        );

        let document = PacketDocument::from_packet(&decoded.packet);
        let reloaded = document.to_packet(&registry, 64).unwrap();
        let rebuilt = Builder::new(registry)
            .build(reloaded, BuildContext::default(), BuildOptions::default())
            .unwrap();
        assert_eq!(rebuilt.bytes.as_ref(), bytes);
    }
}
