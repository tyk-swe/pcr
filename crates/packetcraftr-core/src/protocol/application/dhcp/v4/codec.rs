// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use bytes::Bytes;

use super::super::codec::{self as shared, Budget, Message, extend, take, u16_at, u32_at};
use super::super::{Error, Limit, Limits};
use super::reflection::{layout, schema};
use super::{Dhcpv4, Kind4, Option4, Value4};
use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    field::FieldValue,
    layer::{Id, Layer, Raw, Schema},
    layout::FieldLayout,
    protocol::BuiltinProtocol,
};

const NAME: &str = BuiltinProtocol::Dhcpv4.as_str();
const MAGIC_COOKIE: &[u8; 4] = b"\x63\x82\x53\x63";

impl TryFrom<Bytes> for Dhcpv4 {
    type Error = Error;

    fn try_from(wire: Bytes) -> Result<Self, Self::Error> {
        Self::from_wire_with_limits(wire, Limits::default())
    }
}

impl TryFrom<Vec<u8>> for Dhcpv4 {
    type Error = Error;

    fn try_from(wire: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(Bytes::from(wire))
    }
}

impl TryFrom<&[u8]> for Dhcpv4 {
    type Error = Error;

    fn try_from(wire: &[u8]) -> Result<Self, Self::Error> {
        Budget::new(Limits::default(), wire.len())?;
        Self::try_from(Bytes::copy_from_slice(wire))
    }
}

impl Dhcpv4 {
    pub fn from_wire_with_limits(wire: impl Into<Bytes>, limits: Limits) -> Result<Self, Error> {
        let wire = wire.into();
        let mut budget = Budget::new(limits, wire.len())?;
        take(&wire, 0, 240)?;
        if &wire[236..240] != MAGIC_COOKIE {
            return Err(Error::Invalid("DHCPv4 magic cookie"));
        }
        if wire[2] > 16 {
            return Err(Error::Invalid("hardware address length exceeds chaddr"));
        }
        let (options, trailing) = decode_options(&wire.slice(240..), &mut budget)?;
        let overload = overload(&options)?;
        let file_options = if overload & 1 != 0 {
            decode_options(&wire.slice(108..236), &mut budget)?.0
        } else {
            Vec::new()
        };
        let server_name_options = if overload & 2 != 0 {
            decode_options(&wire.slice(44..108), &mut budget)?.0
        } else {
            Vec::new()
        };
        let address = |offset| {
            Ipv4Addr::from(<[u8; 4]>::try_from(&wire[offset..offset + 4]).expect("fixed address"))
        };
        Ok(Self {
            operation: wire[0],
            hardware_type: wire[1],
            hardware_length: wire[2],
            hops: wire[3],
            transaction_id: u32_at(&wire, 4)?,
            seconds: u16_at(&wire, 8)?,
            flags: u16_at(&wire, 10)?,
            client_address: address(12),
            your_address: address(16),
            server_address: address(20),
            gateway_address: address(24),
            client_hardware_address: wire[28..44].try_into().expect("fixed chaddr"),
            server_name: wire[44..108].try_into().expect("fixed sname"),
            boot_file: wire[108..236].try_into().expect("fixed file"),
            options,
            file_options,
            server_name_options,
            trailing,
            wire,
        })
    }
    pub fn to_wire(&self) -> Result<Bytes, Error> {
        self.to_wire_with_limits(Limits::default())
    }
    pub fn to_wire_with_limits(&self, limits: Limits) -> Result<Bytes, Error> {
        if !self.wire.is_empty()
            && Self::from_wire_with_limits(self.wire.clone(), limits)
                .is_ok_and(|original| original == *self)
        {
            return Ok(self.wire.clone());
        }
        if self.hardware_length > 16 {
            return Err(Error::Invalid("hardware address length exceeds chaddr"));
        }
        let mut budget = Budget::new(limits, 240)?;
        let maximum = budget.limits.max_message_bytes;
        if self
            .options
            .len()
            .saturating_add(self.file_options.len())
            .saturating_add(self.server_name_options.len())
            > budget.limits.max_options
        {
            return Err(Error::Limit(Limit::OptionCount));
        }
        let mut primary = self.options.clone();
        let existing = overload(&primary)?;
        let needed = u8::from(!self.file_options.is_empty())
            | (u8::from(!self.server_name_options.is_empty()) << 1);
        if existing != 0 && needed & !existing != 0 {
            return Err(Error::Invalid(
                "overload option disagrees with option areas",
            ));
        }
        if existing == 0 && needed != 0 {
            primary.push(Option4 {
                code: 52,
                value: Value4::Overload(needed),
            });
        }
        let overload = existing | needed;
        let mut output = Vec::new();
        extend(
            &mut output,
            &[
                self.operation,
                self.hardware_type,
                self.hardware_length,
                self.hops,
            ],
            maximum,
        )?;
        extend(&mut output, &self.transaction_id.to_be_bytes(), maximum)?;
        extend(&mut output, &self.seconds.to_be_bytes(), maximum)?;
        extend(&mut output, &self.flags.to_be_bytes(), maximum)?;
        for address in [
            self.client_address,
            self.your_address,
            self.server_address,
            self.gateway_address,
        ] {
            extend(&mut output, &address.octets(), maximum)?;
        }
        extend(&mut output, &self.client_hardware_address, maximum)?;
        let mut sname = self.server_name;
        let mut file = self.boot_file;
        if overload & 1 != 0 {
            let encoded = encode_options(&self.file_options, &mut budget, 128)?;
            file[..encoded.len()].copy_from_slice(&encoded);
        }
        if overload & 2 != 0 {
            let encoded = encode_options(&self.server_name_options, &mut budget, 64)?;
            sname[..encoded.len()].copy_from_slice(&encoded);
        }
        extend(&mut output, &sname, maximum)?;
        extend(&mut output, &file, maximum)?;
        extend(&mut output, MAGIC_COOKIE, maximum)?;
        let encoded = encode_options(&primary, &mut budget, maximum.saturating_sub(output.len()))?;
        extend(&mut output, &encoded, maximum)?;
        extend(&mut output, &self.trailing, maximum)?;
        let wire: Bytes = output.into();
        Self::from_wire_with_limits(wire.clone(), limits)?;
        Ok(wire)
    }
}
impl Option4 {
    pub fn data(&self) -> Result<Bytes, Error> {
        let mut output = Vec::new();
        match (&self.value, Kind4::of(self.code)) {
            (Value4::MessageType(value), Some(Kind4::MessageType)) => output.push(*value),
            (Value4::Address(value), Some(Kind4::Address)) => {
                output.extend_from_slice(&value.octets());
            }
            (Value4::Addresses(values), Some(Kind4::Addresses)) => {
                if values.is_empty() || values.len() > 63 {
                    return Err(Error::Limit(Limit::Ipv4OptionAddresses));
                }
                for value in values {
                    output.extend_from_slice(&value.octets());
                }
            }
            (Value4::Seconds(value), Some(Kind4::Seconds)) => {
                output.extend_from_slice(&value.to_be_bytes());
            }
            (Value4::Number(value), Some(Kind4::Number)) => {
                output.extend_from_slice(&value.to_be_bytes());
            }
            (Value4::Codes(value), Some(Kind4::Codes))
            | (Value4::Text(value), Some(Kind4::Text)) => {
                extend(&mut output, value, 255)?;
            }
            (
                Value4::ClientIdentifier {
                    hardware_type,
                    identifier,
                },
                Some(Kind4::ClientIdentifier),
            ) => {
                if identifier.is_empty() {
                    return Err(Error::Invalid("empty client identifier"));
                }
                output.push(*hardware_type);
                extend(&mut output, identifier, 255)?;
            }
            (Value4::Overload(value), Some(Kind4::Overload)) if (1..=3).contains(value) => {
                output.push(*value);
            }
            (Value4::Raw(value), _) if !matches!(self.code, 0 | 255) => {
                extend(&mut output, value, 255)?;
            }
            _ => {
                return Err(Error::Invalid(
                    "DHCPv4 option code and typed value disagree",
                ));
            }
        }
        if output.len() > 255 {
            return Err(Error::Limit(Limit::Dhcpv4OptionBytes));
        }
        Ok(output.into())
    }
}
/// Noncanonical fixed-width bodies remain raw, including pieces of RFC 3396 concatenated options.
fn value(code: u8, data: Bytes) -> Value4 {
    match (Kind4::of(code), data.len()) {
        (Some(Kind4::MessageType), 1) => Value4::MessageType(data[0]),
        (Some(Kind4::Overload), 1) if (1..=3).contains(&data[0]) => Value4::Overload(data[0]),
        (Some(Kind4::Address), 4) => {
            Value4::Address(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
        }
        (Some(Kind4::Addresses), n) if n > 0 && n % 4 == 0 => Value4::Addresses(
            data.as_chunks::<4>()
                .0
                .iter()
                .map(|b| Ipv4Addr::new(b[0], b[1], b[2], b[3]))
                .collect(),
        ),
        (Some(Kind4::Seconds), 4) => Value4::Seconds(u32::from_be_bytes(
            data.as_ref().try_into().expect("four bytes"),
        )),
        (Some(Kind4::Number), 2) => Value4::Number(u16::from_be_bytes(
            data.as_ref().try_into().expect("two bytes"),
        )),
        (Some(Kind4::Codes), _) => Value4::Codes(data),
        (Some(Kind4::Text), _) => Value4::Text(data),
        (Some(Kind4::ClientIdentifier), n) if n >= 2 => Value4::ClientIdentifier {
            hardware_type: data[0],
            identifier: data.slice(1..),
        },
        _ => Value4::Raw(data),
    }
}
fn decode_options(bytes: &Bytes, budget: &mut Budget) -> Result<(Vec<Option4>, Bytes), Error> {
    let mut position = 0;
    let mut options = Vec::new();
    while position < bytes.len() {
        let code = bytes[position];
        position += 1;
        if code == 0 {
            continue;
        }
        if code == 255 {
            return Ok((options, bytes.slice(position..)));
        }
        budget.option(0)?;
        let length = usize::from(*take(bytes, position, 1)?.first().expect("one byte"));
        position += 1;
        take(bytes, position, length)?;
        options.push(Option4 {
            code,
            value: value(code, bytes.slice(position..position + length)),
        });
        position += length;
    }
    Err(Error::Invalid("DHCPv4 option area has no end marker"))
}
fn encode_options(
    options: &[Option4],
    budget: &mut Budget,
    maximum: usize,
) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    for option in options {
        budget.option(0)?;
        let data = option.data()?;
        extend(&mut output, &[option.code, data.len() as u8], maximum)?;
        extend(&mut output, &data, maximum)?;
    }
    extend(&mut output, &[255], maximum)?;
    Ok(output)
}

fn overload(options: &[Option4]) -> Result<u8, Error> {
    let mut found = options.iter().filter(|option| option.code == 52);
    let Some(first) = found.next() else {
        return Ok(0);
    };
    if found.next().is_some() {
        return Err(Error::Invalid("ambiguous repeated overload option"));
    }
    Ok(if let Value4::Overload(value) = first.value {
        value
    } else {
        0
    })
}

impl Message for Dhcpv4 {
    const NAME: &'static str = NAME;

    fn decode_wire(wire: Bytes) -> Result<Self, Error> {
        Self::try_from(wire)
    }

    fn encode_wire(&self, limits: Limits) -> Result<Bytes, Error> {
        self.to_wire_with_limits(limits)
    }

    fn layout() -> Vec<FieldLayout> {
        layout()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Dhcpv4Codec;

impl LayerCodec for Dhcpv4Codec {
    fn protocol_id(&self) -> &'static Id {
        &schema().protocol
    }

    fn published_schema(&self) -> Option<&'static Schema> {
        Some(schema())
    }

    fn accepts_decoded_protocol(&self, protocol: &Id) -> bool {
        matches!(protocol.as_str(), NAME | "raw")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        shared::encode::<Dhcpv4>(layer, payload, context)
    }

    fn decode(
        &self,
        input: Bytes,
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        if input.get(236..240) != Some(MAGIC_COOKIE.as_slice()) {
            return Ok(Raw::decoded(input));
        }
        shared::decode::<Dhcpv4>(input)
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        shared::make_layer::<Dhcpv4>(fields)
    }
}

#[cfg(test)]
mod tests {
    use std::mem::discriminant;

    use super::super::super::MAX_OPTIONS;
    use super::*;
    use crate::field;
    use crate::protocol::common::structured::object;

    const ADDRESS: &[u8] = &[1, 16, 28, 32, 50, 54];
    const ADDRESSES: &[u8] = &[
        3, 4, 5, 6, 7, 8, 9, 10, 11, 41, 42, 44, 45, 48, 49, 65, 68, 69, 70, 71, 72, 73, 74, 75, 76,
    ];
    const SECONDS: &[u8] = &[24, 35, 38, 51, 58, 59];
    const NUMBER: &[u8] = &[13, 22, 26, 57];
    const TEXT: &[u8] = &[12, 14, 15, 17, 18, 40, 56, 60, 64, 66, 67];

    fn typed() -> Vec<(u8, Value4, Vec<u8>)> {
        let mut typed = vec![
            (52, Value4::Overload(3), vec![3]),
            (53, Value4::MessageType(5), vec![5]),
            (
                55,
                Value4::Codes(Bytes::from_static(&[1, 3, 6])),
                vec![1, 3, 6],
            ),
            (
                61,
                Value4::ClientIdentifier {
                    hardware_type: 1,
                    identifier: Bytes::from_static(&[2, 0, 0, 0, 0, 1]),
                },
                vec![1, 2, 0, 0, 0, 0, 1],
            ),
        ];
        for &code in ADDRESS {
            typed.push((
                code,
                Value4::Address(Ipv4Addr::new(192, 0, 2, code)),
                vec![192, 0, 2, code],
            ));
        }
        for &code in ADDRESSES {
            typed.push((
                code,
                Value4::Addresses(vec![
                    Ipv4Addr::new(192, 0, 2, code),
                    Ipv4Addr::new(198, 51, 100, code),
                ]),
                vec![192, 0, 2, code, 198, 51, 100, code],
            ));
        }
        for &code in SECONDS {
            let seconds = 0x0102_0300 + u32::from(code);
            typed.push((
                code,
                Value4::Seconds(seconds),
                seconds.to_be_bytes().to_vec(),
            ));
        }
        for &code in NUMBER {
            let number = 0x0100 + u16::from(code);
            typed.push((code, Value4::Number(number), number.to_be_bytes().to_vec()));
        }
        for &code in TEXT {
            let text = format!("t{code}").into_bytes();
            typed.push((code, Value4::Text(Bytes::from(text.clone())), text));
        }
        typed
    }

    fn typed_options() -> Vec<Option4> {
        typed()
            .into_iter()
            .map(|(code, value, _)| Option4 { code, value })
            .collect()
    }

    #[test]
    fn typed_option_codes_encode_to_their_wire_bytes_and_decode_back() {
        let mut expected = Vec::new();
        for (code, value, data) in typed() {
            let option = Option4 {
                code,
                value: value.clone(),
            };
            assert_eq!(option.data().unwrap().as_ref(), data, "code {code}");
            assert_eq!(super::value(code, Bytes::from(data.clone())), value);
            expected.extend([code, data.len() as u8]);
            expected.extend(data);
        }
        expected.push(255);
        let message = Dhcpv4 {
            options: typed_options(),
            ..Default::default()
        };
        let wire = message.to_wire().unwrap();
        assert_eq!(&wire[240..], expected);
        let parsed = Dhcpv4::try_from(wire).unwrap();
        assert_eq!(parsed.options, message.options);
    }

    #[test]
    fn option_data_accepts_only_the_value_kind_of_its_code() {
        let samples = typed();
        let mut values = vec![Value4::Raw(Bytes::from_static(&[1, 2]))];
        for (_, value, _) in &samples {
            if !values
                .iter()
                .any(|seen| discriminant(seen) == discriminant(value))
            {
                values.push(value.clone());
            }
        }
        for code in 0..=255 {
            let kind = samples
                .iter()
                .find(|(sample, ..)| *sample == code)
                .map(|(_, value, _)| discriminant(value));
            for value in &values {
                let accepted = match value {
                    Value4::Raw(_) => !matches!(code, 0 | 255),
                    _ => kind == Some(discriminant(value)),
                };
                let result = Option4 {
                    code,
                    value: value.clone(),
                }
                .data();
                if accepted {
                    assert!(result.is_ok(), "code {code} with {value:?}");
                } else {
                    assert_eq!(
                        result,
                        Err(Error::Invalid(
                            "DHCPv4 option code and typed value disagree"
                        )),
                        "code {code} with {value:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn option_data_keeps_its_length_and_range_limits() {
        let data = |code, value| Option4 { code, value }.data();
        let bytes = |length: usize| Bytes::from(vec![7; length]);
        let addresses = |count: usize| Value4::Addresses(vec![Ipv4Addr::LOCALHOST; count]);
        assert_eq!(data(12, Value4::Text(bytes(255))).unwrap().len(), 255);
        assert_eq!(data(55, Value4::Codes(bytes(255))).unwrap().len(), 255);
        assert_eq!(data(222, Value4::Raw(bytes(255))).unwrap().len(), 255);
        for (code, value) in [
            (12, Value4::Text(bytes(256))),
            (55, Value4::Codes(bytes(256))),
            (222, Value4::Raw(bytes(256))),
        ] {
            assert_eq!(data(code, value), Err(Error::Limit(Limit::EncodedBytes)));
        }
        assert_eq!(data(3, addresses(63)).unwrap().len(), 252);
        for count in [0, 64] {
            assert_eq!(
                data(3, addresses(count)),
                Err(Error::Limit(Limit::Ipv4OptionAddresses))
            );
        }
        let identifier = |length| Value4::ClientIdentifier {
            hardware_type: 1,
            identifier: bytes(length),
        };
        assert_eq!(data(61, identifier(254)).unwrap().len(), 255);
        assert_eq!(
            data(61, identifier(255)),
            Err(Error::Limit(Limit::EncodedBytes))
        );
        assert_eq!(
            data(61, identifier(0)),
            Err(Error::Invalid("empty client identifier"))
        );
        for overload in [0, 4] {
            assert_eq!(
                data(52, Value4::Overload(overload)),
                Err(Error::Invalid(
                    "DHCPv4 option code and typed value disagree"
                ))
            );
        }
    }

    #[test]
    fn decoding_keeps_options_that_do_not_fit_their_kind_raw() {
        for (code, sample, _) in typed() {
            for length in 0..=9 {
                let data = Bytes::from(vec![1; length]);
                let fits = match sample {
                    Value4::MessageType(_) | Value4::Overload(_) => length == 1,
                    Value4::Address(_) | Value4::Seconds(_) => length == 4,
                    Value4::Addresses(_) => length > 0 && length % 4 == 0,
                    Value4::Number(_) => length == 2,
                    Value4::Codes(_) | Value4::Text(_) => true,
                    Value4::ClientIdentifier { .. } => length >= 2,
                    Value4::Raw(_) => unreachable!("typed samples are never raw"),
                };
                let decoded = super::value(code, data.clone());
                if fits {
                    assert_eq!(
                        discriminant(&decoded),
                        discriminant(&sample),
                        "code {code}, {length} bytes"
                    );
                } else {
                    assert_eq!(decoded, Value4::Raw(data), "code {code}, {length} bytes");
                }
            }
        }
        for overload in [0, 4, 255] {
            let data = Bytes::from(vec![overload]);
            assert_eq!(super::value(52, data.clone()), Value4::Raw(data));
        }
        let known: Vec<u8> = typed().into_iter().map(|(code, ..)| code).collect();
        for code in (0..=255).filter(|code| !known.contains(code)) {
            for length in 0..=5 {
                let data = Bytes::from(vec![1; length]);
                assert_eq!(super::value(code, data.clone()), Value4::Raw(data));
            }
        }
    }

    #[test]
    fn concatenated_pieces_of_a_fixed_width_option_stay_separate_raw_options() {
        let mut wire = Dhcpv4::default().to_wire().unwrap()[..240].to_vec();
        wire.extend([1, 2, 192, 0, 1, 2, 2, 1, 12, 1, b'a', 12, 1, b'b', 255]);
        let parsed = Dhcpv4::try_from(wire).unwrap();
        assert_eq!(
            parsed.options,
            [
                Option4::raw(1, Bytes::from_static(&[192, 0])),
                Option4::raw(1, Bytes::from_static(&[2, 1])),
                Option4 {
                    code: 12,
                    value: Value4::Text(Bytes::from_static(b"a"))
                },
                Option4 {
                    code: 12,
                    value: Value4::Text(Bytes::from_static(b"b"))
                },
            ]
        );
    }

    fn reflected_keys(value: &Value4) -> &'static [&'static str] {
        match value {
            Value4::MessageType(_) => &["message_type"],
            Value4::Address(_) => &["address"],
            Value4::Addresses(_) => &["addresses"],
            Value4::Seconds(_) => &["seconds"],
            Value4::Number(_) => &["number"],
            Value4::Codes(_) => &["codes"],
            Value4::Text(_) => &["text"],
            Value4::ClientIdentifier { .. } => &["hardware_type", "identifier"],
            Value4::Overload(_) => &["overload"],
            Value4::Raw(_) => &["data"],
        }
    }

    #[test]
    fn reflected_options_keep_their_keys_and_round_trip_for_every_typed_code() {
        let mut options = typed_options();
        options.push(Option4::raw(222, Bytes::from_static(&[0xff, 0, 1])));
        options.push(Option4::raw(1, Bytes::from_static(&[192, 0])));
        let layer = Dhcpv4 {
            options: options.clone(),
            ..Default::default()
        };
        let reflected = layer.field("options").unwrap();
        let FieldValue::List(items) = &reflected else {
            panic!("options reflect as a list");
        };
        assert_eq!(items.len(), options.len());
        for (item, option) in items.iter().zip(&options) {
            let FieldValue::Object(entry) = item else {
                panic!("an option reflects as an object");
            };
            assert_eq!(entry["code"], FieldValue::Unsigned(u64::from(option.code)));
            let FieldValue::Object(value) = &entry["value"] else {
                panic!("an option value reflects as an object");
            };
            assert_eq!(
                value.keys().map(String::as_str).collect::<Vec<_>>(),
                reflected_keys(&option.value),
                "code {}",
                option.code
            );
        }
        let mut restored = Dhcpv4::default();
        restored.set_field("options", reflected).unwrap();
        assert_eq!(restored.options, options);
    }

    fn parsed(entries: Vec<FieldValue>) -> Result<Vec<Option4>, field::Error> {
        let mut layer = Dhcpv4::default();
        layer.set_field("options", FieldValue::List(entries))?;
        Ok(layer.options)
    }

    fn entry(code: u8, value: FieldValue) -> FieldValue {
        object([("code", code.into()), ("value", value)])
    }

    fn one(code: u8, value: FieldValue) -> Result<Vec<Option4>, field::Error> {
        parsed(vec![entry(code, value)])
    }

    fn data_bytes(length: usize) -> FieldValue {
        Bytes::from(vec![7; length]).into()
    }

    #[test]
    fn reflected_options_are_parsed_by_the_kind_of_their_code() {
        assert_eq!(
            one(222, object([("data", data_bytes(2))])).unwrap(),
            [Option4::raw(222, Bytes::from(vec![7; 2]))]
        );
        assert_eq!(
            one(1, object([("data", data_bytes(2))])).unwrap(),
            [Option4::raw(1, Bytes::from(vec![7; 2]))]
        );
        assert!(matches!(
            one(222, object([("seconds", 1u32.into())])),
            Err(field::Error::WrongType { field, expected, .. })
                if field == "options" && expected == "unknown option value with data bytes"
        ));
        assert!(matches!(
            one(1, object([("text", data_bytes(1))])),
            Err(field::Error::MissingRequired { field, .. }) if field == "options.address"
        ));
        assert!(matches!(
            one(61, object([("identifier", data_bytes(1))])),
            Err(field::Error::MissingRequired { field, .. }) if field == "options.hardware_type"
        ));
        assert!(matches!(
            one(53, object([("message_type", 1u8.into()), ("text", data_bytes(1))])),
            Err(field::Error::UnknownField { field, .. }) if field == "options.text"
        ));
        assert!(matches!(
            one(53, object([("message_type", 256u16.into())])),
            Err(field::Error::OutOfRange { field, .. }) if field == "options.message_type"
        ));
    }

    #[test]
    fn reflected_options_that_cannot_be_encoded_are_out_of_range() {
        let addresses = |count: usize| {
            object([(
                "addresses",
                FieldValue::List(vec![Ipv4Addr::LOCALHOST.into(); count]),
            )])
        };
        assert_eq!(one(3, addresses(63)).unwrap().len(), 1);
        for (code, value) in [
            (0, object([("data", data_bytes(1))])),
            (52, object([("overload", 4u8.into())])),
            (3, addresses(0)),
            (3, addresses(64)),
            (12, object([("text", data_bytes(256))])),
            (55, object([("codes", data_bytes(256))])),
            (
                61,
                object([("hardware_type", 1u8.into()), ("identifier", data_bytes(0))]),
            ),
        ] {
            assert!(
                matches!(
                    one(code, value),
                    Err(field::Error::OutOfRange { field, .. }) if field == "options"
                ),
                "code {code}"
            );
        }
        let option = entry(200, object([("data", data_bytes(0))]));
        assert_eq!(
            parsed(vec![option.clone(); MAX_OPTIONS]).unwrap().len(),
            MAX_OPTIONS
        );
        assert!(matches!(
            parsed(vec![option; MAX_OPTIONS + 1]),
            Err(field::Error::OutOfRange { field, .. }) if field == "options"
        ));
    }
}
