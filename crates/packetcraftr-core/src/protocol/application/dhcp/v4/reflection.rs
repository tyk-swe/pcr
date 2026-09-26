// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use super::{Dhcpv4, Option4, Value4};
use crate::{
    field::{FieldKind, FieldValue},
    layer::{FieldError, FieldSchema, reflect_set, reflective_layer},
    protocol::{
        BuiltinProtocol,
        common::{
            out_of_range, read_only,
            structured::{Object, list, member, object},
            wrong_type,
        },
    },
};
use bytes::Bytes;
const VALUE_FIELDS: &[FieldSchema] = &[
    member("message_type", FieldKind::Unsigned, &[]),
    member("address", FieldKind::Ipv4, &[]),
    member("addresses", FieldKind::List, &[]),
    member("seconds", FieldKind::Unsigned, &[]),
    member("number", FieldKind::Unsigned, &[]),
    member("codes", FieldKind::Bytes, &[]),
    member("text", FieldKind::Bytes, &[]),
    member("hardware_type", FieldKind::Unsigned, &[]),
    member("identifier", FieldKind::Bytes, &[]),
    member("overload", FieldKind::Unsigned, &[]),
    member("data", FieldKind::Bytes, &[]),
];
const OPTION_FIELDS: &[FieldSchema] = &[
    member("code", FieldKind::Unsigned, &[]),
    member("value", FieldKind::Object, VALUE_FIELDS),
];
fn options_value(options: &[Option4]) -> FieldValue {
    FieldValue::List(
        options
            .iter()
            .map(|option| {
                object([
                    ("code", option.code.into()),
                    (
                        "value",
                        match &option.value {
                            Value4::MessageType(value) => {
                                object([("message_type", (*value).into())])
                            }
                            Value4::Address(value) => object([("address", (*value).into())]),
                            Value4::Addresses(values) => object([(
                                "addresses",
                                FieldValue::List(
                                    values.iter().map(|value| (*value).into()).collect(),
                                ),
                            )]),
                            Value4::Seconds(value) => object([("seconds", (*value).into())]),
                            Value4::Number(value) => object([("number", (*value).into())]),
                            Value4::Codes(value) => object([("codes", value.clone().into())]),
                            Value4::Text(value) => object([("text", value.clone().into())]),
                            Value4::ClientIdentifier {
                                hardware_type,
                                identifier,
                            } => object([
                                ("hardware_type", (*hardware_type).into()),
                                ("identifier", identifier.clone().into()),
                            ]),
                            Value4::Overload(value) => object([("overload", (*value).into())]),
                            Value4::Raw(value) => object([("data", value.clone().into())]),
                        },
                    ),
                ])
            })
            .collect(),
    )
}
fn parse_options(value: FieldValue, field: &str) -> Result<Vec<Option4>, FieldError> {
    list(value, 4096, schema(), field)?
        .into_iter()
        .map(|value| {
            let mut option = Object::new(value, schema(), field)?;
            let code = option.required_value::<u8>("code")?;
            let mut value = Object::new(option.required("value")?, schema(), field)?;
            option.finish()?;
            let data = if value.contains("data") {
                Value4::Raw(value.required_value("data")?)
            } else {
                match code {
                    53 => Value4::MessageType(value.required_value("message_type")?),
                    52 => Value4::Overload(value.required_value("overload")?),
                    1 | 16 | 28 | 32 | 50 | 54 => Value4::Address(
                        value.required_with("address", std::net::Ipv4Addr::UNSPECIFIED)?,
                    ),
                    3..=11 | 41 | 42 | 44 | 45 | 48 | 49 | 65 | 68..=76 => Value4::Addresses(
                        list(value.required("addresses")?, 63, schema(), field)?
                            .into_iter()
                            .map(|value| {
                                let mut address = std::net::Ipv4Addr::UNSPECIFIED;
                                reflect_set(&mut address, schema(), field, value)?;
                                Ok(address)
                            })
                            .collect::<Result<_, FieldError>>()?,
                    ),
                    24 | 35 | 38 | 51 | 58 | 59 => {
                        Value4::Seconds(value.required_value("seconds")?)
                    }
                    13 | 22 | 26 | 57 => Value4::Number(value.required_value("number")?),
                    55 => Value4::Codes(value.required_value("codes")?),
                    12 | 14 | 15 | 17 | 18 | 40 | 56 | 60 | 64 | 66 | 67 => {
                        Value4::Text(value.required_value("text")?)
                    }
                    61 => Value4::ClientIdentifier {
                        hardware_type: value.required_value("hardware_type")?,
                        identifier: value.required_value("identifier")?,
                    },
                    _ => {
                        return Err(wrong_type(
                            schema(),
                            field,
                            "unknown option value with data bytes",
                        ));
                    }
                }
            };
            value.finish()?;
            let option = Option4 { code, value: data };
            option.data().map_err(|_| out_of_range(schema(), field))?;
            Ok(option)
        })
        .collect()
}
fn fixed<const N: usize>(
    target: &mut [u8; N],
    value: FieldValue,
    field: &str,
) -> Result<(), FieldError> {
    let FieldValue::Bytes(value) = value else {
        return Err(wrong_type(schema(), field, "bytes"));
    };
    if value.len() > N {
        return Err(out_of_range(schema(), field));
    }
    target.fill(0);
    target[..value.len()].copy_from_slice(&value);
    Ok(())
}
fn message_type(layer: &mut Dhcpv4, value: FieldValue, field: &str) -> Result<(), FieldError> {
    let mut number = 0u8;
    reflect_set(&mut number, schema(), field, value)?;
    if let Some(option) = layer.options.iter_mut().find(|option| option.code == 53) {
        *option = Option4::message_type(number);
    } else {
        layer.options.push(Option4::message_type(number));
    }
    Ok(())
}
reflective_layer! {
    pub(super) fn schema() => {protocol:crate::layer::Id::new(BuiltinProtocol::Dhcpv4.as_str()),name:"DHCPv4"}
    impl Dhcpv4 {
        "operation" | "op" => {kind:Unsigned,derived:false,required:false,description:"BOOTP message operation",reflect:operation,layout:(0,1)},
        "hardware_type" => {kind:Unsigned,derived:false,required:false,description:"Hardware address type",reflect:hardware_type,layout:(1,2)},
        "hardware_length" => {kind:Unsigned,derived:false,required:false,description:"Meaningful hardware address bytes",reflect:hardware_length,layout:(2,3)},
        "hops" => {kind:Unsigned,derived:false,required:false,description:"Relay hop count",reflect:hops,layout:(3,4)},
        "transaction_id" | "xid" => {kind:Unsigned,derived:false,required:false,description:"Transaction identity",reflect:transaction_id,layout:(4,8)},
        "seconds" => {kind:Unsigned,derived:false,required:false,description:"Elapsed client seconds",reflect:seconds,layout:(8,10)},
        "flags" => {kind:Unsigned,derived:false,required:false,description:"Exact flags including the broadcast bit",reflect:flags,layout:(10,12)},
        "client_address" | "ciaddr" => {kind:Ipv4,derived:false,required:false,description:"Client address",reflect:client_address,layout:(12,16)},
        "your_address" | "yiaddr" => {kind:Ipv4,derived:false,required:false,description:"Assigned address",reflect:your_address,layout:(16,20)},
        "server_address" | "siaddr" => {kind:Ipv4,derived:false,required:false,description:"Next bootstrap server",reflect:server_address,layout:(20,24)},
        "gateway_address" | "giaddr" => {kind:Ipv4,derived:false,required:false,description:"Relay address",reflect:gateway_address,layout:(24,28)},
        "client_hardware_address" | "chaddr" => {kind:Bytes,derived:false,required:false,description:"Sixteen fixed hardware-address bytes; shorter inputs are padded",get |layer| Some(Bytes::copy_from_slice(&layer.client_hardware_address).into()),set |layer,value,name| fixed(&mut layer.client_hardware_address,value,name),layout:(28,44)},
        "server_name" | "sname" => {kind:Bytes,derived:false,required:false,description:"Exact server-name backing field",get |layer| Some(Bytes::copy_from_slice(&layer.server_name).into()),set |layer,value,name| fixed(&mut layer.server_name,value,name),layout:(44,108)},
        "boot_file" | "file" => {kind:Bytes,derived:false,required:false,description:"Exact boot-file backing field",get |layer| Some(Bytes::copy_from_slice(&layer.boot_file).into()),set |layer,value,name| fixed(&mut layer.boot_file,value,name),layout:(108,236)},
        "message_type" => {kind:Unsigned,derived:false,required:false,description:"First parsed DHCP option 53 message type",get |layer| layer.message_type().map(Into::into),set |layer,value,name| message_type(layer,value,name)},
        "options" => {kind:List,derived:false,required:false,description:"Ordered primary options",children:OPTION_FIELDS,get |layer| Some(options_value(&layer.options)),set |layer,value,name| {layer.options=parse_options(value,name)?;Ok(())}},
        "file_options" => {kind:List,derived:false,required:false,description:"Options in the overloaded boot-file area",children:OPTION_FIELDS,get |layer| Some(options_value(&layer.file_options)),set |layer,value,name| {layer.file_options=parse_options(value,name)?;Ok(())}},
        "server_name_options" => {kind:List,derived:false,required:false,description:"Options in the overloaded server-name area",children:OPTION_FIELDS,get |layer| Some(options_value(&layer.server_name_options)),set |layer,value,name| {layer.server_name_options=parse_options(value,name)?;Ok(())}},
        "wire" => {kind:Bytes,derived:false,required:false,description:"Retained complete DHCP wire",get |layer| (!layer.wire.is_empty()).then(||layer.wire.clone().into()),set |_layer,_value,name| read_only(schema(),name)}
    }
    layout pub(super) fn layout();
}
