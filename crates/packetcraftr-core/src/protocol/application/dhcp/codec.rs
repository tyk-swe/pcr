// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;

use super::{Error, Limit, Limits, MAX_DHCP_MESSAGE_BYTES};
use crate::{
    codec::{Decoded, EncodeContext, Encoded, SeededLayer},
    field,
    layer::Layer,
    layout::FieldLayout,
    protocol::common::{invalid, payload_without_padding, rejected, typed_layer},
};

pub(super) trait Message: Layer + Default + Sized + 'static {
    const NAME: &'static str;

    fn decode_wire(wire: Bytes) -> Result<Self, Error>;

    fn encode_wire(&self, limits: Limits) -> Result<Bytes, Error>;

    fn layout() -> Vec<FieldLayout>;
}

pub(super) fn encode<M: Message>(
    layer: &dyn Layer,
    payload: &[u8],
    context: &EncodeContext<'_>,
) -> Result<Encoded, crate::codec::Error> {
    if !payload_without_padding(M::NAME, payload, context)?.is_empty() {
        return Err(invalid(M::NAME, "DHCP is a complete UDP payload"));
    }
    let layer = typed_layer::<M>(M::NAME, layer)?;
    let wire = layer
        .encode_wire(Limits {
            max_message_bytes: context.remaining_packet_bytes.min(MAX_DHCP_MESSAGE_BYTES),
            ..Default::default()
        })
        .map_err(|error| rejected(M::NAME, error))?;
    let normalized = M::decode_wire(wire.clone()).map_err(|error| rejected(M::NAME, error))?;
    Ok(Encoded::header(wire.to_vec(), Box::new(normalized)).with_fields(M::layout()))
}

pub(super) fn decode<M: Message>(input: Bytes) -> Result<Decoded, crate::codec::Error> {
    let layer = M::decode_wire(input.clone()).map_err(|error| rejected(M::NAME, error))?;
    let mut decoded = Decoded::terminal(Box::new(layer), input.len());
    decoded.fields = M::layout();
    Ok(decoded)
}

pub(super) fn seed_layer<M: Message>(
    fields: &[(usize, &field::Value)],
) -> Result<Option<SeededLayer>, crate::codec::Error> {
    let wire = M::default()
        .schema()
        .field_index("wire")
        .expect("DHCP schema declares a wire field");
    let Some((_, value)) = fields.iter().find(|(index, _)| *index == wire) else {
        return Ok(Some(SeededLayer {
            layer: Box::new(M::default()),
            consumed: None,
        }));
    };
    let field::Value::Bytes(bytes) = value else {
        return Err(invalid(M::NAME, "wire must be retained bytes"));
    };
    let layer = M::decode_wire(bytes.clone()).map_err(|error| rejected(M::NAME, error))?;
    Ok(Some(SeededLayer {
        layer: Box::new(layer),
        consumed: Some(wire),
    }))
}

pub(super) fn finish_constructed<M: Message>(
    layer: &dyn Layer,
    fields: &[(usize, &field::Value)],
) -> Result<(), crate::codec::Error> {
    let schema = layer.schema();
    let (Some(options), Some(message_type)) = (
        schema.field_index("options"),
        schema.field_index("message_type"),
    ) else {
        return Ok(());
    };
    let supplied = |wanted: usize| {
        fields
            .iter()
            .find(|(index, _)| *index == wanted)
            .map(|(_, value)| *value)
    };
    if supplied(options).is_some()
        && let Some(supplied_type) = supplied(message_type)
        && layer.field_by_index(message_type).as_ref() != Some(supplied_type)
    {
        return Err(invalid(
            M::NAME,
            "message_type conflicts with supplied options",
        ));
    }
    Ok(())
}

macro_rules! dhcp_codec {
    ($codec:ident, $message:ty, $name:ident, |$input:ident| $accept:expr) => {
        impl super::super::codec::Message for $message {
            const NAME: &'static str = $name;

            fn decode_wire(wire: bytes::Bytes) -> Result<Self, super::super::Error> {
                Self::try_from(wire)
            }

            fn encode_wire(
                &self,
                limits: super::super::Limits,
            ) -> Result<bytes::Bytes, super::super::Error> {
                self.to_wire_with_limits(limits)
            }

            fn layout() -> Vec<crate::layout::FieldLayout> {
                layout()
            }
        }

        #[derive(Clone, Copy, Debug, Default)]
        pub(crate) struct $codec;

        impl crate::codec::Codec for $codec {
            fn protocol_id(&self) -> &'static crate::layer::Id {
                &schema().protocol
            }

            fn schema(&self) -> Option<&'static crate::layer::Schema> {
                Some(schema())
            }

            fn new_layer(&self) -> Result<Box<dyn crate::layer::Layer>, crate::codec::Error> {
                Ok(Box::new(<$message>::default()))
            }

            fn seed_layer(
                &self,
                fields: &[(usize, &crate::field::Value)],
            ) -> Result<Option<crate::codec::SeededLayer>, crate::codec::Error> {
                super::super::codec::seed_layer::<$message>(fields)
            }

            fn finish_constructed(
                &self,
                layer: &mut dyn crate::layer::Layer,
                fields: &[(usize, &crate::field::Value)],
            ) -> Result<(), crate::codec::Error> {
                super::super::codec::finish_constructed::<$message>(layer, fields)
            }

            fn accepts_decoded_protocol(&self, protocol: &crate::layer::Id) -> bool {
                protocol == self.protocol_id() || protocol == &crate::layer::Raw::ID
            }

            fn encode(
                &self,
                layer: &dyn crate::layer::Layer,
                payload: &[u8],
                context: &crate::codec::EncodeContext<'_>,
            ) -> Result<crate::codec::Encoded, crate::codec::Error> {
                super::super::codec::encode::<$message>(layer, payload, context)
            }

            fn decode(
                &self,
                $input: bytes::Bytes,
                _context: &crate::codec::DecodeContext<'_>,
            ) -> Result<crate::codec::Decoded, crate::codec::Error> {
                if !($accept) {
                    return Ok(crate::layer::Raw::decoded($input));
                }
                super::super::codec::decode::<$message>($input)
            }
        }
    };
}
pub(super) use dhcp_codec;

pub(super) struct Budget {
    pub(super) limits: Limits,
    options: usize,
}
impl Budget {
    pub(super) fn new(limits: Limits, length: usize) -> Result<Self, Error> {
        limits.validate()?;
        if length > limits.max_message_bytes {
            return Err(Error::Limit(Limit::MessageBytes));
        }
        Ok(Self { limits, options: 0 })
    }
    pub(super) fn option(&mut self, depth: usize) -> Result<(), Error> {
        if depth > self.limits.max_nesting {
            return Err(Error::Limit(Limit::OptionNesting));
        }
        if self.options >= self.limits.max_options {
            return Err(Error::Limit(Limit::OptionCount));
        }
        self.options += 1;
        Ok(())
    }
}
pub(super) fn take(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8], Error> {
    bytes
        .get(offset..offset.saturating_add(length))
        .ok_or(Error::Truncated {
            offset,
            needed: length,
            available: bytes.len().saturating_sub(offset),
        })
}
pub(super) fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    Ok(u16::from_be_bytes(
        take(bytes, offset, 2)?.try_into().expect("two bytes"),
    ))
}
pub(super) fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(
        take(bytes, offset, 4)?.try_into().expect("four bytes"),
    ))
}
pub(super) fn extend(output: &mut Vec<u8>, bytes: &[u8], maximum: usize) -> Result<(), Error> {
    if output.len().saturating_add(bytes.len()) > maximum {
        return Err(Error::Limit(Limit::EncodedBytes));
    }
    output.extend_from_slice(bytes);
    Ok(())
}
