// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Declarative reflection support for strongly typed packet layers.

use bytes::Bytes;

use super::{FieldError, LayerSchema};
use crate::packet::field::{FieldValue, WireValue};

/// Declares a layer's schema, getter/setter dispatch, and static layout names.
/// Encoding and decoding remain handwritten in protocol modules.
macro_rules! reflective_layer {
    (
        fn $schema:ident() => {
            protocol: $protocol:expr_2021,
            name: $layer_name:literal
        }
        impl $ty:ty {
            $(
                $field:literal $(| $alias:literal)* => {
                    kind: $kind:ident,
                    derived: $derived:literal,
                    required: $required:literal,
                    description: $description:literal,
                    get |$getter:ident| $get:expr_2021,
                    set |$setter:ident, $value:ident, $field_name:ident| $set:expr_2021
                    $(, layout: ($start:expr_2021, $end:expr_2021))?
                }
            ),* $(,)?
            $(normalize |$normalizer:ident| $normalize:block)?
        }
        layout fn $layout:ident($($layout_arg:ident: $layout_ty:ty),* $(,)?) ;
    ) => {
        fn $schema() -> &'static $crate::packet::layer::LayerSchema {
            static SCHEMA: std::sync::OnceLock<$crate::packet::layer::LayerSchema> =
                std::sync::OnceLock::new();
            static FIELDS: &[$crate::packet::layer::FieldSchema] = &[
                $(
                    $crate::packet::layer::FieldSchema {
                        name: $field,
                        kind: $crate::packet::field::FieldKind::$kind,
                        derived: $derived,
                        required: $required,
                        description: $description,
                    }
                ),*
            ];
            SCHEMA.get_or_init(|| $crate::packet::layer::LayerSchema {
                protocol: $protocol,
                name: $layer_name,
                fields: FIELDS,
            })
        }

        impl $crate::packet::layer::Layer for $ty {
            fn schema(&self) -> &'static $crate::packet::layer::LayerSchema {
                $schema()
            }

            fn clone_box(&self) -> Box<dyn $crate::packet::layer::Layer> {
                Box::new(self.clone())
            }

            fn as_any(&self) -> &dyn std::any::Any {
                self
            }

            fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
                self
            }

            fn field(&self, name: &str) -> Option<$crate::packet::field::FieldValue> {
                match name {
                    $(
                        $field $(| $alias)* => {
                            let $getter = self;
                            $get
                        }
                    ),*
                    _ => None,
                }
            }

            fn set_field(
                &mut self,
                name: &str,
                value: $crate::packet::field::FieldValue,
            ) -> Result<(), $crate::packet::layer::FieldError> {
                match name {
                    $(
                        $field $(| $alias)* => {
                            let $setter = self;
                            let $value = value;
                            let $field_name = name;
                            $set
                        }
                    ),*
                    _ => Err($crate::packet::layer::FieldError::UnknownField {
                        protocol: $schema().protocol.clone(),
                        field: name.to_owned(),
                    }),
                }
            }

            $(
                fn normalize(&mut self) {
                    let $normalizer = self;
                    $normalize
                }
            )?

            #[cfg(test)]
            fn declared_layout_fields(&self) -> Vec<&'static str> {
                vec![
                    $(
                        reflective_layer!(@layout_name $field $(, $start, $end)?)
                    ),*
                ].into_iter().flatten().collect()
            }
        }

        pub(crate) fn $layout($($layout_arg: $layout_ty),*)
            -> Vec<$crate::packet::layout::Field>
        {
            let mut fields: Vec<_> = vec![
                $(
                    reflective_layer!(@layout $field $(, $start, $end)?)
                ),*
            ].into_iter().flatten().collect();
            // Schema order is a public reflection contract, while layout
            // order follows wire position. Stable sorting preserves the
            // declaration order of fields sharing the same bytes.
            fields.sort_by_key(|field| field.range.start);
            fields
        }
    };
    (@layout $field:literal) => {
        None
    };
    (@layout $field:literal, $start:expr, $end:expr) => {
        Some($crate::packet::layout::Field {
            name: $field.to_owned(),
            range: $crate::packet::layout::Range::new($start, $end),
        })
    };
    (@layout_name $field:literal) => {
        None
    };
    (@layout_name $field:literal, $start:expr, $end:expr) => {
        Some($field)
    };
}

pub(crate) use reflective_layer;

pub(crate) enum ReflectiveFieldError {
    WrongType(&'static str),
    OutOfRange,
}

pub(crate) trait ReflectiveField: Sized {
    fn reflective_value(&self) -> FieldValue;
    fn set_reflective_value(&mut self, value: FieldValue) -> Result<(), ReflectiveFieldError>;
}

pub(crate) fn reflect_get<T: ReflectiveField>(value: &T) -> FieldValue {
    value.reflective_value()
}

pub(crate) fn reflect_set<T: ReflectiveField>(
    target: &mut T,
    schema: &'static LayerSchema,
    field: &str,
    value: FieldValue,
) -> Result<(), FieldError> {
    target
        .set_reflective_value(value)
        .map_err(|error| match error {
            ReflectiveFieldError::WrongType(expected) => FieldError::WrongType {
                protocol: schema.protocol.clone(),
                field: field.to_owned(),
                expected,
            },
            ReflectiveFieldError::OutOfRange => FieldError::OutOfRange {
                protocol: schema.protocol.clone(),
                field: field.to_owned(),
            },
        })
}

macro_rules! unsigned_reflective_field {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl ReflectiveField for $ty {
                fn reflective_value(&self) -> FieldValue {
                    (*self).into()
                }

                fn set_reflective_value(
                    &mut self,
                    value: FieldValue,
                ) -> Result<(), ReflectiveFieldError> {
                    let FieldValue::Unsigned(value) = value else {
                        return Err(ReflectiveFieldError::WrongType("unsigned"));
                    };
                    *self = <$ty>::try_from(value)
                        .map_err(|_| ReflectiveFieldError::OutOfRange)?;
                    Ok(())
                }
            }
        )+
    };
}

unsigned_reflective_field!(u8, u16, u32, u64, usize);

impl ReflectiveField for bool {
    fn reflective_value(&self) -> FieldValue {
        (*self).into()
    }

    fn set_reflective_value(&mut self, value: FieldValue) -> Result<(), ReflectiveFieldError> {
        let FieldValue::Bool(value) = value else {
            return Err(ReflectiveFieldError::WrongType("bool"));
        };
        *self = value;
        Ok(())
    }
}

impl ReflectiveField for String {
    fn reflective_value(&self) -> FieldValue {
        self.clone().into()
    }

    fn set_reflective_value(&mut self, value: FieldValue) -> Result<(), ReflectiveFieldError> {
        let FieldValue::Text(value) = value else {
            return Err(ReflectiveFieldError::WrongType("text"));
        };
        *self = value;
        Ok(())
    }
}

impl ReflectiveField for Bytes {
    fn reflective_value(&self) -> FieldValue {
        self.clone().into()
    }

    fn set_reflective_value(&mut self, value: FieldValue) -> Result<(), ReflectiveFieldError> {
        let FieldValue::Bytes(value) = value else {
            return Err(ReflectiveFieldError::WrongType("bytes"));
        };
        *self = value;
        Ok(())
    }
}

impl ReflectiveField for std::net::Ipv4Addr {
    fn reflective_value(&self) -> FieldValue {
        (*self).into()
    }

    fn set_reflective_value(&mut self, value: FieldValue) -> Result<(), ReflectiveFieldError> {
        let value = match value {
            FieldValue::Ipv4(value) => value,
            FieldValue::Text(value) => value
                .parse()
                .map_err(|_| ReflectiveFieldError::WrongType("ipv4"))?,
            _ => return Err(ReflectiveFieldError::WrongType("ipv4")),
        };
        *self = value;
        Ok(())
    }
}

impl ReflectiveField for std::net::Ipv6Addr {
    fn reflective_value(&self) -> FieldValue {
        (*self).into()
    }

    fn set_reflective_value(&mut self, value: FieldValue) -> Result<(), ReflectiveFieldError> {
        let value = match value {
            FieldValue::Ipv6(value) => value,
            FieldValue::Text(value) => value
                .parse()
                .map_err(|_| ReflectiveFieldError::WrongType("ipv6"))?,
            _ => return Err(ReflectiveFieldError::WrongType("ipv6")),
        };
        *self = value;
        Ok(())
    }
}

impl ReflectiveField for [u8; 6] {
    fn reflective_value(&self) -> FieldValue {
        FieldValue::Mac(*self)
    }

    fn set_reflective_value(&mut self, value: FieldValue) -> Result<(), ReflectiveFieldError> {
        let value = match value {
            FieldValue::Mac(value) => value,
            FieldValue::Text(value) => {
                let normalized = value.replace('-', ":");
                let mut output = [0_u8; 6];
                let mut parts = normalized.split(':');
                for byte in &mut output {
                    let Some(part) = parts.next() else {
                        return Err(ReflectiveFieldError::WrongType("mac address"));
                    };
                    if part.len() != 2 {
                        return Err(ReflectiveFieldError::WrongType("mac address"));
                    }
                    *byte = u8::from_str_radix(part, 16)
                        .map_err(|_| ReflectiveFieldError::WrongType("mac address"))?;
                }
                if parts.next().is_some() {
                    return Err(ReflectiveFieldError::WrongType("mac address"));
                }
                output
            }
            _ => return Err(ReflectiveFieldError::WrongType("mac address")),
        };
        *self = value;
        Ok(())
    }
}

impl ReflectiveField for [u8; 8] {
    fn reflective_value(&self) -> FieldValue {
        FieldValue::Bytes(Bytes::copy_from_slice(self))
    }

    fn set_reflective_value(&mut self, value: FieldValue) -> Result<(), ReflectiveFieldError> {
        let FieldValue::Bytes(value) = value else {
            return Err(ReflectiveFieldError::WrongType("eight bytes"));
        };
        if value.len() != self.len() {
            return Err(ReflectiveFieldError::WrongType("eight bytes"));
        }
        self.copy_from_slice(&value);
        Ok(())
    }
}

macro_rules! wire_reflective_field {
    ($ty:ty) => {
        impl ReflectiveField for WireValue<$ty> {
            fn reflective_value(&self) -> FieldValue {
                match self {
                    WireValue::Auto => FieldValue::Text("auto".to_owned()),
                    WireValue::Exact(value) => FieldValue::Unsigned(u64::from(*value)),
                    WireValue::Raw(value) => FieldValue::Bytes(value.clone()),
                }
            }

            fn set_reflective_value(
                &mut self,
                value: FieldValue,
            ) -> Result<(), ReflectiveFieldError> {
                *self = match value {
                    FieldValue::Text(value) if value.eq_ignore_ascii_case("auto") => {
                        WireValue::Auto
                    }
                    FieldValue::Unsigned(value) => WireValue::Exact(
                        <$ty>::try_from(value).map_err(|_| ReflectiveFieldError::OutOfRange)?,
                    ),
                    FieldValue::Bytes(value) => WireValue::Raw(value),
                    _ => {
                        return Err(ReflectiveFieldError::WrongType(
                            "unsigned, bytes, or 'auto'",
                        ));
                    }
                };
                Ok(())
            }
        }
    };
}

wire_reflective_field!(u8);
wire_reflective_field!(u16);
wire_reflective_field!(u32);
