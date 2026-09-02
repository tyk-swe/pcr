// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use crate::{
    codec::{DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    diagnostic::Diagnostic,
    field::FieldValue,
    layer::{Layer, reflective_layer},
    registry::Discriminator,
};

use crate::protocol::common::{
    binding_protocol, invalid, make_layer, out_of_range, protocol, truncated, typed_layer,
    validate_raw_child_discriminator, wrong_type,
};

use crate::protocol::BuiltinProtocol;

const NULL_NAME: &str = BuiltinProtocol::BsdNull.as_str();
const LOOP_NAME: &str = BuiltinProtocol::BsdLoop.as_str();

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ByteOrder {
    #[default]
    Little,
    Big,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BsdNull {
    pub family: u32,
    pub byte_order: ByteOrder,
}

impl Default for BsdNull {
    fn default() -> Self {
        Self {
            family: 2,
            byte_order: ByteOrder::Little,
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
    fn loop_schema() => { protocol: protocol(LOOP_NAME), name: "BSD LOOP" }
    impl BsdLoop {
        "family" => { kind: Unsigned, derived: false, required: true, description: "Address-family discriminator", reflect: family, layout: (0, 4) }
    }
    layout pub(crate) fn loop_layout();
}

reflective_layer! {
    fn null_schema() => { protocol: protocol(NULL_NAME), name: "BSD NULL" }
    impl BsdNull {
        "family" => { kind: Unsigned, derived: false, required: true, description: "Address-family discriminator", reflect: family, layout: (0, 4) },
        "byte_order" => { kind: Text, derived: false, required: true, description: "Host byte order used by the captured NULL header", get |layer| Some(FieldValue::Text(match layer.byte_order { ByteOrder::Little => "little", ByteOrder::Big => "big" }.to_owned())), set |layer, value, name| match value { FieldValue::Text(value) if value.eq_ignore_ascii_case("little") => { layer.byte_order = ByteOrder::Little; Ok(()) }, FieldValue::Text(value) if value.eq_ignore_ascii_case("big") => { layer.byte_order = ByteOrder::Big; Ok(()) }, FieldValue::Text(_) => Err(out_of_range(null_schema(), name)), _ => Err(wrong_type(null_schema(), name, "text")) }, layout: (0, 4) }
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
    parent: &'static str,
    family: u32,
    context: &LayerEncodeContext<'_>,
) -> Result<Vec<Diagnostic>, crate::codec::Error> {
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
    if BuiltinProtocol::Raw.identifies(child) {
        return Ok(diagnostics);
    }
    let Some(expected) = context
        .registry
        .discriminator_for(parent, binding_protocol(child))
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
    if context.mode == crate::codec::Mode::Strict {
        return Err(invalid(parent, message));
    }
    diagnostics
        .push(Diagnostic::warning("build.capture_family_binding", message).at_field("family"));
    Ok(diagnostics)
}

impl LayerCodec for BsdNullCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &null_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<BsdNull>(NULL_NAME, layer)?;
        let prefix = match layer.byte_order {
            ByteOrder::Little => layer.family.to_le_bytes(),
            ByteOrder::Big => layer.family.to_be_bytes(),
        };
        Ok(
            EncodedLayer::header(prefix.to_vec(), Box::new(layer.clone()))
                .with_fields(null_layout())
                .with_diagnostics(validate_family_binding(NULL_NAME, layer.family, context)?),
        )
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, crate::codec::Error> {
        decode_family(input, FamilyHeader::Null)
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(BsdNull::default(), fields)
    }
}

impl LayerCodec for BsdLoopCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &loop_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<BsdLoop>(LOOP_NAME, layer)?;
        Ok(
            EncodedLayer::header(layer.family.to_be_bytes().to_vec(), Box::new(layer.clone()))
                .with_fields(loop_layout())
                .with_diagnostics(validate_family_binding(LOOP_NAME, layer.family, context)?),
        )
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, crate::codec::Error> {
        decode_family(input, FamilyHeader::Loop)
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(BsdLoop::default(), fields)
    }
}

pub(crate) fn decode_family(
    input: &[u8],
    header: FamilyHeader,
) -> Result<DecodedLayerValue, crate::codec::Error> {
    let name = match header {
        FamilyHeader::Null => NULL_NAME,
        FamilyHeader::Loop => LOOP_NAME,
    };
    let Some(bytes) = input.first_chunk::<4>() else {
        return Err(truncated(name, 4, input.len()));
    };
    let big = u32::from_be_bytes(*bytes);
    let little = u32::from_le_bytes(*bytes);
    let (family, byte_order) = match header {
        FamilyHeader::Loop => (big, ByteOrder::Big),
        FamilyHeader::Null if matches!(little, 2 | 10 | 24 | 28 | 30) => {
            (little, ByteOrder::Little)
        }
        FamilyHeader::Null => (big, ByteOrder::Big),
    };
    let layer: Box<dyn Layer> = match header {
        FamilyHeader::Loop => Box::new(BsdLoop { family }),
        FamilyHeader::Null => Box::new(BsdNull { family, byte_order }),
    };
    Ok(DecodedLayerValue {
        layer,
        consumed: 4,
        payload_len: input.len().saturating_sub(4),
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
