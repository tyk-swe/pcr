// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Declarative reflection support for strongly typed packet layers.

use bytes::Bytes;

use super::{FieldError, Schema};
use crate::field::{FieldValue, WireValue, parse_mac};

/// Declares a layer's schema, getter/setter dispatch, and static layout.
/// Encoding and decoding remain handwritten in protocol modules.
///
/// Exported so sibling workspace crates can declare their own layers; it is not
/// part of the documented public API.
#[macro_export]
#[doc(hidden)]
macro_rules! reflective_layer {
    (
        fn $schema:ident() => {
            protocol: $protocol:expr_2021,
            name: $layer_name:literal
            $(, decode_only: $decode_only:literal)? $(,)?
        }
        impl $ty:ty {
            $(
                $field:literal $(| $alias:literal)* => {
                    kind: $kind:ident,
                    $(element: $element:ident,)?
                    tier: $tier:ident,
                    $(default: $default:literal,)?
                    $(max: $max:expr_2021,)?
                    description: $description:literal,
                    $(reflect: $member:ident)?
                    $(reflect_bounded: $bounded_member:ident, $maximum:tt)?
                    $(wire: $wire_member:ident)?
                    $(
                        get |$getter:ident| $get:expr_2021,
                        set |$setter:ident, $value:ident, $field_name:ident| $set:expr_2021
                    )?
                    $(, layout: ($start:expr_2021, $end:expr_2021))?
                }
            ),* $(,)?
        }
        layout $vis:vis fn $layout:ident($($layout_arg:ident: $layout_ty:ty),* $(,)?) ;
    ) => {
        fn $schema() -> &'static $crate::layer::Schema {
            static SCHEMA: std::sync::OnceLock<$crate::layer::Schema> =
                std::sync::OnceLock::new();
            SCHEMA.get_or_init(|| {
                let fields: Vec<$crate::layer::FieldSchema> = vec![
                    $(
                        $crate::layer::FieldSchema {
                            name: $field,
                            kind: $crate::field::FieldKind::$kind,
                            tier: $crate::layer::Tier::$tier,
                            default: $crate::reflective_layer!(@opt_str $($default)?),
                            aliases: &[$($alias),*],
                            element: $crate::reflective_layer!(@opt_kind $($element)?),
                            max: $crate::reflective_layer!(
                                @max $ty;
                                $(reflect $member)?
                                $(reflect_bounded $bounded_member, $maximum)?
                                $(wire $wire_member)?
                                $(explicit $max)?
                            ),
                            description: $description,
                        }
                    ),*
                ];
                let leaked_fields: &'static [$crate::layer::FieldSchema] =
                    Box::leak(fields.into_boxed_slice());
                $crate::layer::Schema {
                    protocol: $protocol,
                    name: $layer_name,
                    decode_only: false $(|| $decode_only)?,
                    fields: leaked_fields,
                }
            })
        }

        impl $crate::layer::Layer for $ty {
            fn schema(&self) -> &'static $crate::layer::Schema {
                $schema()
            }

            fn clone_box(&self) -> Box<dyn $crate::layer::Layer> {
                Box::new(self.clone())
            }

            fn as_any(&self) -> &dyn std::any::Any {
                self
            }

            fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
                self
            }

            fn field(&self, name: &str) -> Option<$crate::field::FieldValue> {
                match name {
                    $(
                        $field $(| $alias)* => $crate::reflective_layer!(
                            @get self;
                            $(reflect $member)?
                            $(reflect_bounded $bounded_member)?
                            $(wire $wire_member)?
                            $(explicit $getter => $get)?
                        ),
                    )*
                    _ => None,
                }
            }

            fn set_field(
                &mut self,
                name: &str,
                value: $crate::field::FieldValue,
            ) -> Result<(), $crate::layer::FieldError> {
                match name {
                    $(
                        $field $(| $alias)* => $crate::reflective_layer!(
                            @set self, value, name, $schema;
                            $(reflect $member)?
                            $(reflect_bounded $bounded_member, $maximum)?
                            $(wire $wire_member)?
                            $(explicit $setter, $value, $field_name => $set)?
                        ),
                    )*
                    _ => Err($crate::layer::FieldError::UnknownField {
                        protocol: $schema().protocol.clone(),
                        field: name.to_owned(),
                    }),
                }
            }

            fn wire_field(&self, name: &str) -> Option<$crate::field::WireValue<u64>> {
                match name {
                    $(
                        $field $(| $alias)* => $crate::reflective_layer!(
                            @wire self;
                            $(wire $wire_member)?
                        ),
                    )*
                    _ => None,
                }
            }
        }

        $vis fn $layout($($layout_arg: $layout_ty),*)
            -> Vec<$crate::layout::FieldLayout>
        {
            let mut fields: Vec<_> = vec![
                $(
                    $crate::reflective_layer!(@layout $field $(, $start, $end)?)
                ),*
            ].into_iter().flatten().collect();
            // Schema order is a public reflection contract, while layout
            // order follows wire position. Stable sorting preserves the
            // declaration order of fields sharing the same bytes.
            fields.sort_by_key(|field| field.range.start);
            fields
        }
    };
    (@opt_str $val:literal) => {
        Some($val)
    };
    (@opt_str) => {
        None
    };
    (@opt_kind $elem:ident) => {
        Some($crate::field::FieldKind::$elem)
    };
    (@opt_kind) => {
        None
    };
    (@max $ty:ty; reflect $member:ident) => {
        $crate::layer::reflective_max(|layer: &$ty| &layer.$member)
    };
    (@max $ty:ty; reflect_bounded $member:ident, $maximum:tt) => {
        u64::try_from($maximum).ok()
    };
    (@max $ty:ty; wire $member:ident) => {
        $crate::layer::reflective_max(|layer: &$ty| &layer.$member)
    };
    (@max $ty:ty; explicit $max:expr_2021) => {
        u64::try_from($max).ok()
    };
    (@max $ty:ty; explicit) => {
        None
    };
    (@max $ty:ty;) => {
        None
    };
    (@layout $field:literal) => {
        None
    };
    (@layout $field:literal, $start:expr, $end:expr) => {
        Some($crate::layout::FieldLayout {
            name: $field.to_owned(),
            range: $crate::layout::ByteRange::new($start, $end),
        })
    };
    (@get $layer:expr; reflect $member:ident) => {
        Some($crate::layer::reflect_get(&$layer.$member))
    };
    (@get $layer:expr; reflect_bounded $member:ident) => {
        Some($crate::layer::reflect_get(&$layer.$member))
    };
    (@get $layer:expr; wire $member:ident) => {
        Some($crate::layer::reflect_get(&$layer.$member))
    };
    (@get $layer:expr; explicit $getter:ident => $get:expr_2021) => {{
        let $getter = $layer;
        $get
    }};
    (@set $layer:expr, $value:expr, $name:expr, $schema:ident; reflect $member:ident) => {
        $crate::layer::reflect_set(&mut $layer.$member, $schema(), $name, $value)
    };
    (@set $layer:expr, $value:expr, $name:expr, $schema:ident;
        reflect_bounded $member:ident, $maximum:tt
    ) => {
        $crate::layer::reflect_set_bounded(
            &mut $layer.$member,
            $schema(),
            $name,
            $value,
            u64::from($maximum),
        )
    };
    (@set $layer:expr, $value:expr, $name:expr, $schema:ident; wire $member:ident) => {
        $crate::layer::reflect_set(&mut $layer.$member, $schema(), $name, $value)
    };
    (@set $layer:expr, $input:expr, $name:expr, $schema:ident;
        explicit $setter:ident, $value:ident, $field_name:ident => $set:expr_2021
    ) => {{
        let $setter = $layer;
        let $value = $input;
        let $field_name = $name;
        $set
    }};
    (@wire $layer:expr; wire $member:ident) => {
        Some(match &$layer.$member {
            $crate::field::WireValue::Auto => $crate::field::WireValue::Auto,
            $crate::field::WireValue::Exact(v) => $crate::field::WireValue::Exact(u64::from(*v)),
            $crate::field::WireValue::Raw(b) => $crate::field::WireValue::Raw(b.clone()),
        })
    };
    (@wire $layer:expr;) => {
        None
    };
}

#[doc(hidden)]
pub(crate) use reflective_layer;

pub enum ReflectiveFieldError {
    WrongType(&'static str),
    OutOfRange,
}

pub trait ReflectiveField: Sized {
    const MAX_VALUE: Option<u64> = None;

    fn reflective_value(&self) -> FieldValue;
    fn set_reflective_value(&mut self, value: FieldValue) -> Result<(), ReflectiveFieldError>;
}

pub fn reflective_max<L, T: ReflectiveField>(_: fn(&L) -> &T) -> Option<u64> {
    T::MAX_VALUE
}

pub fn reflect_get<T: ReflectiveField>(value: &T) -> FieldValue {
    value.reflective_value()
}

pub fn reflect_set<T: ReflectiveField>(
    target: &mut T,
    schema: &'static Schema,
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

/// Like [`reflect_set`], but additionally rejects unsigned values above a
/// wire-width maximum before delegating to the field's own conversion.
pub fn reflect_set_bounded<T: ReflectiveField>(
    target: &mut T,
    schema: &'static Schema,
    field: &str,
    value: FieldValue,
    maximum: u64,
) -> Result<(), FieldError> {
    if let FieldValue::Unsigned(value) = value
        && value > maximum
    {
        return Err(FieldError::OutOfRange {
            protocol: schema.protocol.clone(),
            field: field.to_owned(),
        });
    }
    reflect_set(target, schema, field, value)
}

macro_rules! unsigned_reflective_field {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl ReflectiveField for $ty {
                const MAX_VALUE: Option<u64> = Some(<$ty>::MAX as u64);

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

macro_rules! ip_reflective_field {
    ($ty:ty, $variant:ident, $expected:literal) => {
        impl ReflectiveField for $ty {
            fn reflective_value(&self) -> FieldValue {
                (*self).into()
            }

            fn set_reflective_value(
                &mut self,
                value: FieldValue,
            ) -> Result<(), ReflectiveFieldError> {
                *self = match value {
                    FieldValue::$variant(value) => value,
                    FieldValue::Text(value) => value
                        .parse()
                        .map_err(|_| ReflectiveFieldError::WrongType($expected))?,
                    _ => return Err(ReflectiveFieldError::WrongType($expected)),
                };
                Ok(())
            }
        }
    };
}

ip_reflective_field!(std::net::Ipv4Addr, Ipv4, "ipv4");
ip_reflective_field!(std::net::Ipv6Addr, Ipv6, "ipv6");

impl ReflectiveField for [u8; 6] {
    fn reflective_value(&self) -> FieldValue {
        FieldValue::Mac(*self)
    }

    fn set_reflective_value(&mut self, value: FieldValue) -> Result<(), ReflectiveFieldError> {
        let value = match value {
            FieldValue::Mac(value) => value,
            FieldValue::Text(value) => {
                parse_mac(&value).ok_or(ReflectiveFieldError::WrongType("mac address"))?
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
            const MAX_VALUE: Option<u64> = Some(<$ty>::MAX as u64);

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
