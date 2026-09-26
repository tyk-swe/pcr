// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Declarative reflection support for strongly typed packet layers.

use bytes::Bytes;

use super::Schema;
use crate::field::{self, FieldValue, WireValue, parse_mac};

/// Declares a layer's reflective schema, its [`Layer`](crate::layer::Layer)
/// implementation, and a function returning its static field layout.
///
/// Built-in and custom protocols use the same declaration. Encoding and
/// decoding stay handwritten in the protocol's
/// [`LayerCodec`](crate::codec::LayerCodec).
///
/// The declaration names the schema function and the layer's protocol
/// [`Id`](crate::layer::Id) and display name, then lists the fields in their
/// public schema order. Each field gives its
/// [`FieldKind`](crate::field::FieldKind) variant, whether it is derived by
/// the encoder or required when building, a description, optional nested
/// `children` schemas, and how it reflects:
///
/// - `reflect: member` reads and writes a struct member through
///   [`ReflectiveField`];
/// - `reflect_bounded: member, MAX` does the same but refuses unsigned values
///   above a wire-width maximum;
/// - `get |layer| expr, set |layer, value, name| expr` supplies handwritten
///   accessors, which usually call [`reflect_get`]
///   and [`reflect_set`].
///
/// A field may also give its byte range relative to the layer start with
/// `layout: (start, end)`; the declared layout function returns those ranges
/// in wire order. Aliases follow the field name as `"name" | "alias"`.
///
/// # Examples
///
/// ```
/// use packetcraftr_core::field::FieldValue;
/// use packetcraftr_core::layer::{Id, Layer};
/// use packetcraftr_core::layout::ByteRange;
/// use packetcraftr_core::reflective_layer;
///
/// #[derive(Clone, Debug, Default)]
/// struct Beacon {
///     interval: u16,
/// }
///
/// reflective_layer! {
///     fn beacon_schema() => { protocol: Id::new("beacon"), name: "Beacon" }
///     impl Beacon {
///         "interval" | "period" => {
///             kind: Unsigned, derived: false, required: true,
///             description: "Seconds between beacons",
///             reflect: interval,
///             layout: (0, 2)
///         }
///     }
///     layout fn beacon_layout();
/// }
///
/// let mut beacon = Beacon::default();
/// beacon.set_field("period", FieldValue::Unsigned(30)).unwrap();
/// assert_eq!(beacon.field("interval"), Some(FieldValue::Unsigned(30)));
/// // The member is a `u16`, so a wider value is refused and named.
/// assert!(beacon.set_field("interval", FieldValue::Unsigned(70_000)).is_err());
/// assert_eq!(beacon_layout()[0].range, ByteRange::new(0, 2));
/// ```
#[macro_export]
macro_rules! reflective_layer {
    (
        $schema_vis:vis fn $schema:ident() => {
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
                    $(children: $children:expr_2021,)?
                    $(reflect: $member:ident)?
                    $(reflect_bounded: $bounded_member:ident, $maximum:tt)?
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
        $schema_vis fn $schema() -> &'static $crate::layer::Schema {
            static SCHEMA: std::sync::OnceLock<$crate::layer::Schema> =
                std::sync::OnceLock::new();
            static FIELDS: &[$crate::layer::FieldSchema] = &[
                $(
                    $crate::layer::FieldSchema {
                        name: $field,
                        aliases: &[$($alias),*],
                        kind: $crate::field::FieldKind::$kind,
                        derived: $derived,
                        required: $required,
                        description: $description,
                        children: $crate::reflective_layer!(@children $($children)?),
                    }
                ),*
            ];
            SCHEMA.get_or_init(|| $crate::layer::Schema {
                protocol: $protocol,
                name: $layer_name,
                fields: FIELDS,
            })
        }

        impl $crate::layer::Layer for $ty {
            fn schema(&self) -> &'static $crate::layer::Schema {
                $schema()
            }

            fn clone_box(&self) -> Box<dyn $crate::layer::Layer> {
                Box::new(self.clone())
            }

            fn field(&self, name: &str) -> Option<$crate::field::FieldValue> {
                match name {
                    $(
                        $field $(| $alias)* => $crate::reflective_layer!(
                            @get self;
                            $(reflect $member)?
                            $(reflect_bounded $bounded_member)?
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
            ) -> Result<(), $crate::field::Error> {
                match name {
                    $(
                        $field $(| $alias)* => $crate::reflective_layer!(
                            @set self, value, name, $schema;
                            $(reflect $member)?
                            $(reflect_bounded $bounded_member, $maximum)?
                            $(explicit $setter, $value, $field_name => $set)?
                        ),
                    )*
                    _ => Err($crate::field::Error::UnknownField {
                        protocol: $schema().protocol,
                        field: name.to_owned(),
                    }),
                }
            }

        }

        $vis fn $layout($($layout_arg: $layout_ty),*)
            -> Vec<$crate::layout::FieldLayout>
        {
            let mut fields: Vec<$crate::layout::FieldLayout> = vec![
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
    (@children) => { &[] };
    (@children $children:expr) => { $children };
    (@layout $field:literal) => {
        None
    };
    (@layout $field:literal, $start:expr, $end:expr) => {
        Some($crate::layout::FieldLayout {
            name: $field,
            range: $crate::layout::ByteRange::new($start, $end),
        })
    };
    (@get $layer:expr; reflect $member:ident) => {
        Some($crate::layer::reflect_get(&$layer.$member))
    };
    (@get $layer:expr; reflect_bounded $member:ident) => {
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
    (@set $layer:expr, $input:expr, $name:expr, $schema:ident;
        explicit $setter:ident, $value:ident, $field_name:ident => $set:expr_2021
    ) => {{
        let $setter = $layer;
        let $value = $input;
        let $field_name = $name;
        $set
    }};
}

pub(crate) use reflective_layer;

/// Why a reflective setter refused a value, before the field name and
/// protocol that [`reflect_set`] attaches are known.
///
/// A refusal is not an error on its own: [`reflect_set`] turns it into a
/// [`field::Error`] once the field is known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// The value is not of the named kind.
    WrongType(&'static str),
    /// The value has the right kind but does not fit the member.
    OutOfRange,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongType(expected) => write!(formatter, "value is not {expected}"),
            Self::OutOfRange => formatter.write_str("value is outside the field's range"),
        }
    }
}

/// A layer member that converts to and from a reflected [`FieldValue`].
///
/// Implemented for the unsigned integers, `i8`, `bool`, `String`, [`Bytes`],
/// IPv4 and IPv6 addresses, six-byte MAC and eight-byte arrays, and
/// [`WireValue`] over the unsigned integers. A custom member type implements
/// it to be declared with `reflect:` in
/// [`reflective_layer!`](crate::reflective_layer).
pub trait ReflectiveField: Sized {
    /// The member as a reflected value.
    fn reflective_value(&self) -> FieldValue;
    /// Replaces the member with `value`, or says why it cannot hold it.
    fn set_reflective_value(&mut self, value: FieldValue) -> Result<(), Refusal>;
}

/// Reads a reflective member; the getter counterpart of [`reflect_set`] for
/// handwritten accessors.
pub fn reflect_get<T: ReflectiveField>(value: &T) -> FieldValue {
    value.reflective_value()
}

/// Writes a reflective member, turning a [`Refusal`] into a [`field::Error`]
/// that names `field` in `schema`'s protocol.
pub fn reflect_set<T: ReflectiveField>(
    target: &mut T,
    schema: &'static Schema,
    field: &str,
    value: FieldValue,
) -> Result<(), field::Error> {
    target
        .set_reflective_value(value)
        .map_err(|error| match error {
            Refusal::WrongType(expected) => field::Error::WrongType {
                protocol: schema.protocol,
                field: field.to_owned(),
                expected,
            },
            Refusal::OutOfRange => field::Error::OutOfRange {
                protocol: schema.protocol,
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
) -> Result<(), field::Error> {
    if let FieldValue::Unsigned(value) = value
        && value > maximum
    {
        return Err(field::Error::OutOfRange {
            protocol: schema.protocol,
            field: field.to_owned(),
        });
    }
    reflect_set(target, schema, field, value)
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
                ) -> Result<(), Refusal> {
                    let FieldValue::Unsigned(value) = value else {
                        return Err(Refusal::WrongType("unsigned"));
                    };
                    *self = <$ty>::try_from(value)
                        .map_err(|_| Refusal::OutOfRange)?;
                    Ok(())
                }
            }
        )+
    };
}

unsigned_reflective_field!(u8, u16, u32, u64, usize);

impl ReflectiveField for i8 {
    fn reflective_value(&self) -> FieldValue {
        FieldValue::Signed(i64::from(*self))
    }

    fn set_reflective_value(&mut self, value: FieldValue) -> Result<(), Refusal> {
        let value = match value {
            FieldValue::Signed(value) => value,
            FieldValue::Unsigned(value) => i64::try_from(value).map_err(|_| Refusal::OutOfRange)?,
            _ => return Err(Refusal::WrongType("signed")),
        };
        *self = Self::try_from(value).map_err(|_| Refusal::OutOfRange)?;
        Ok(())
    }
}

impl ReflectiveField for bool {
    fn reflective_value(&self) -> FieldValue {
        (*self).into()
    }

    fn set_reflective_value(&mut self, value: FieldValue) -> Result<(), Refusal> {
        let FieldValue::Bool(value) = value else {
            return Err(Refusal::WrongType("bool"));
        };
        *self = value;
        Ok(())
    }
}

impl ReflectiveField for String {
    fn reflective_value(&self) -> FieldValue {
        self.clone().into()
    }

    fn set_reflective_value(&mut self, value: FieldValue) -> Result<(), Refusal> {
        let FieldValue::Text(value) = value else {
            return Err(Refusal::WrongType("text"));
        };
        *self = value;
        Ok(())
    }
}

impl ReflectiveField for Bytes {
    fn reflective_value(&self) -> FieldValue {
        self.clone().into()
    }

    fn set_reflective_value(&mut self, value: FieldValue) -> Result<(), Refusal> {
        let FieldValue::Bytes(value) = value else {
            return Err(Refusal::WrongType("bytes"));
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

            fn set_reflective_value(&mut self, value: FieldValue) -> Result<(), Refusal> {
                *self = match value {
                    FieldValue::$variant(value) => value,
                    FieldValue::Text(value) => {
                        value.parse().map_err(|_| Refusal::WrongType($expected))?
                    }
                    _ => return Err(Refusal::WrongType($expected)),
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

    fn set_reflective_value(&mut self, value: FieldValue) -> Result<(), Refusal> {
        let value = match value {
            FieldValue::Mac(value) => value,
            FieldValue::Text(value) => {
                parse_mac(&value).ok_or(Refusal::WrongType("mac address"))?
            }
            _ => return Err(Refusal::WrongType("mac address")),
        };
        *self = value;
        Ok(())
    }
}

impl ReflectiveField for [u8; 8] {
    fn reflective_value(&self) -> FieldValue {
        FieldValue::Bytes(Bytes::copy_from_slice(self))
    }

    fn set_reflective_value(&mut self, value: FieldValue) -> Result<(), Refusal> {
        let FieldValue::Bytes(value) = value else {
            return Err(Refusal::WrongType("eight bytes"));
        };
        if value.len() != self.len() {
            return Err(Refusal::WrongType("eight bytes"));
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

            fn set_reflective_value(&mut self, value: FieldValue) -> Result<(), Refusal> {
                *self = match value {
                    FieldValue::Text(value) if value.eq_ignore_ascii_case("auto") => {
                        WireValue::Auto
                    }
                    FieldValue::Unsigned(value) => {
                        WireValue::Exact(<$ty>::try_from(value).map_err(|_| Refusal::OutOfRange)?)
                    }
                    FieldValue::Bytes(value) => WireValue::Raw(value),
                    _ => {
                        return Err(Refusal::WrongType("unsigned, bytes, or 'auto'"));
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
