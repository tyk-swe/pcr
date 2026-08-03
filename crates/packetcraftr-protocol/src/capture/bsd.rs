// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use packetcraftr_packet::{
    codec::{
        CodecError, DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext,
        LayerEncodeContext,
    },
    diagnostic::Diagnostic,
    field::FieldValue,
    layer::{Layer, ProtocolId, reflect_get, reflect_set, reflective_layer},
    registry::Discriminator,
};

use crate::common::{
    binding_protocol, invalid, make_layer, out_of_range, protocol, truncated,
    validate_raw_child_discriminator, wrong_layer, wrong_type,
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
    layout pub(crate) fn loop_layout();
}

reflective_layer! {
    fn null_schema() => { protocol: protocol("bsd_null"), name: "BSD NULL" }
    impl BsdNull {
        "family" => { kind: Unsigned, derived: false, required: true, description: "Address-family discriminator", get |layer| Some(reflect_get(&layer.family)), set |layer, value, name| reflect_set(&mut layer.family, null_schema(), name, value), layout: (0, 4) },
        "byte_order" => { kind: Text, derived: false, required: true, description: "Host byte order used by the captured NULL header", get |layer| Some(FieldValue::Text(match layer.byte_order { CaptureByteOrder::Little => "little", CaptureByteOrder::Big => "big" }.to_owned())), set |layer, value, name| match value { FieldValue::Text(value) if value.eq_ignore_ascii_case("little") => { layer.byte_order = CaptureByteOrder::Little; Ok(()) }, FieldValue::Text(value) if value.eq_ignore_ascii_case("big") => { layer.byte_order = CaptureByteOrder::Big; Ok(()) }, FieldValue::Text(_) => Err(out_of_range(null_schema(), name)), _ => Err(wrong_type(null_schema(), name, "text")) }, layout: (0, 4) }
    }
    layout pub(crate) fn null_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct BsdNullCodec;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct BsdLoopCodec;

#[derive(Clone, Copy, Debug)]
pub(crate) enum FamilyHeader {
    Null,
    Loop,
}

pub(crate) fn family_discriminator(family: u32) -> u64 {
    match family {
        2 => 4,
        10 | 24 | 28 | 30 => 6,
        other => u64::from(other),
    }
}

pub(crate) fn validate_family_binding(
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
        .discriminator_for(parent, binding_protocol(child).as_str())
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
    if context.mode == packetcraftr_packet::build::BuildMode::Strict {
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
        crate::support::aliases(self.protocol_id().as_str())
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
        crate::support::aliases(self.protocol_id().as_str())
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

pub(crate) fn decode_family(
    input: &[u8],
    header: FamilyHeader,
) -> Result<DecodedLayerValue, CodecError> {
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
