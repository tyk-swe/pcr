// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::Bytes;

use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    diagnostic::{Diagnostic, VRRP_CHECKSUM},
    field::{FieldValue, WireValue},
    layer::{Layer, Raw, reflective_layer},
    layout::FieldLayout,
};

use super::{ip_protocol, resolve_envelope};
use crate::protocol::common::{
    ValueExpectation, checksum, checksum_parts, ensure_encode_budget, invalid, make_layer,
    out_of_range, payload_without_padding, protocol, resolve_u8, resolve_u16, strict_or_diagnostic,
    transport_checksum, transport_checksum_parts, truncated, typed_layer, wrong_type,
};

use crate::protocol::BuiltinProtocol;

const NAME: &str = BuiltinProtocol::Vrrp.as_str();

const VRRP_HEADER_LEN: usize = 8;
/// Version 2 messages end with two words of authentication data.
const V2_AUTH_LEN: usize = 8;
/// The count of addresses is one octet.
const MAX_ADDRESSES: usize = 255;
const IPV4_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 18);
const IPV6_GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x12);
const REQUIRED_HOP_LIMIT: u8 = 255;
const MAX_ADVERT_INTERVAL: u16 = 0x0fff;
const MAX_RESERVED: u8 = 0x0f;

/// Virtual Router Redundancy Protocol (RFC 3768, RFC 5798), IP protocol 112.
///
/// `version` selects the layout of bytes four and five: version 2 carries
/// `auth_type` and `advert_interval` (seconds), version 3 carries four
/// `reserved` bits and `max_advert_interval` (centiseconds). The fields of the
/// other version are not written. Addresses are IPv4 for version 2 and take
/// the family of the enclosing IP header for version 3. `auth_data` holds
/// whatever follows the address list: eight bytes in a version 2 message,
/// normally nothing in version 3. `None` builds that default (eight zero bytes
/// in version 2); `Some` is written as given, so a decoded message with a
/// short or missing trailer rebuilds to the same bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vrrp {
    pub version: u8,
    pub vrrp_type: u8,
    pub vrid: u8,
    pub priority: u8,
    pub count_ip: WireValue<u8>,
    pub auth_type: u8,
    pub advert_interval: u8,
    pub reserved: u8,
    pub max_advert_interval: u16,
    pub checksum: WireValue<u16>,
    pub addresses: Vec<IpAddr>,
    pub auth_data: Option<Bytes>,
}

impl Default for Vrrp {
    fn default() -> Self {
        Self {
            version: 3,
            vrrp_type: 1,
            vrid: 1,
            priority: 100,
            count_ip: WireValue::Auto,
            auth_type: 0,
            advert_interval: 1,
            reserved: 0,
            max_advert_interval: 100,
            checksum: WireValue::Auto,
            addresses: Vec::new(),
            auth_data: None,
        }
    }
}

fn addresses_value(addresses: &[IpAddr]) -> FieldValue {
    FieldValue::List(
        addresses
            .iter()
            .map(|address| match address {
                IpAddr::V4(address) => FieldValue::Ipv4(*address),
                IpAddr::V6(address) => FieldValue::Ipv6(*address),
            })
            .collect(),
    )
}

fn set_addresses(
    layer: &mut Vrrp,
    value: FieldValue,
    name: &str,
) -> Result<(), crate::field::Error> {
    let FieldValue::List(values) = value else {
        return Err(wrong_type(vrrp_schema(), name, "list"));
    };
    if values.len() > MAX_ADDRESSES {
        return Err(out_of_range(vrrp_schema(), name));
    }
    layer.addresses = values
        .into_iter()
        .map(|value| match value {
            FieldValue::Ipv4(address) => Ok(IpAddr::V4(address)),
            FieldValue::Ipv6(address) => Ok(IpAddr::V6(address)),
            FieldValue::Text(text) => text
                .parse()
                .map_err(|_| wrong_type(vrrp_schema(), name, "list of IP addresses")),
            _ => Err(wrong_type(vrrp_schema(), name, "list of IP addresses")),
        })
        .collect::<Result<_, _>>()?;
    Ok(())
}

fn set_auth_data(
    layer: &mut Vrrp,
    value: FieldValue,
    name: &str,
) -> Result<(), crate::field::Error> {
    let FieldValue::Bytes(bytes) = value else {
        return Err(wrong_type(vrrp_schema(), name, "bytes"));
    };
    layer.auth_data = Some(bytes);
    Ok(())
}

reflective_layer! {
    fn vrrp_schema() => { protocol: protocol(NAME), name: "VRRP" }
    impl Vrrp {
        "version" => {
            kind: Unsigned, derived: false, required: true,
            description: "VRRP version (high nibble of the first octet)",
            reflect: version,
            layout: (0, 1)
        },
        "type" => {
            kind: Unsigned, derived: false, required: true,
            description: "VRRP message type (low nibble; 1 is an advertisement)",
            reflect: vrrp_type,
            layout: (0, 1)
        },
        "vrid" => {
            kind: Unsigned, derived: false, required: true,
            description: "Virtual router identifier",
            reflect: vrid,
            layout: (1, 2)
        },
        "priority" => {
            kind: Unsigned, derived: false, required: true,
            description: "Sender priority",
            reflect: priority,
            layout: (2, 3)
        },
        "count_ip" => {
            kind: Unsigned, derived: true, required: false,
            description: "Number of virtual router addresses",
            reflect: count_ip,
            layout: (3, 4)
        },
        "auth_type" => {
            kind: Unsigned, derived: false, required: false,
            description: "Authentication type (version 2)",
            reflect: auth_type,
            layout: (4, 5)
        },
        "advert_interval" => {
            kind: Unsigned, derived: false, required: false,
            description: "Advertisement interval in seconds (version 2)",
            reflect: advert_interval,
            layout: (5, 6)
        },
        "reserved" => {
            kind: Unsigned, derived: false, required: false,
            description: "Reserved bits before the interval (version 3)",
            reflect: reserved,
            layout: (4, 6)
        },
        "max_advert_interval" => {
            kind: Unsigned, derived: false, required: false,
            description: "Maximum advertisement interval in centiseconds (version 3)",
            reflect: max_advert_interval,
            layout: (4, 6)
        },
        "checksum" => {
            kind: Unsigned, derived: true, required: false,
            description: "VRRP checksum",
            reflect: checksum,
            layout: (6, 8)
        },
        "addresses" => {
            kind: List, derived: false, required: false,
            description: "Virtual router addresses",
            get |layer| Some(addresses_value(&layer.addresses)),
            set |layer, value, name| set_addresses(layer, value, name),
            layout: (8, addresses_end)
        },
        "auth_data" => {
            kind: Bytes, derived: false, required: false,
            description: "Bytes after the address list (version 2 authentication data)",
            get |layer| layer.auth_data.clone().map(FieldValue::Bytes),
            set |layer, value, name| set_auth_data(layer, value, name),
            layout: (addresses_end, message_end)
        },
    }
    layout fn vrrp_base_layout(addresses_end: usize, message_end: usize);
}

/// Only the interval fields of the message's own version occupy bytes.
fn vrrp_layout(version: u8, addresses_end: usize, message_end: usize) -> Vec<FieldLayout> {
    let other_version: &[&str] = if version == 2 {
        &["reserved", "max_advert_interval"]
    } else {
        &["auth_type", "advert_interval"]
    };
    let mut fields = vrrp_base_layout(addresses_end, message_end);
    fields.retain(|field| !other_version.contains(&field.name));
    fields
}

fn address_len(ipv6: bool) -> usize {
    if ipv6 { 16 } else { 4 }
}

fn push_address(bytes: &mut Vec<u8>, address: IpAddr) {
    match address {
        IpAddr::V4(address) => bytes.extend_from_slice(&address.octets()),
        IpAddr::V6(address) => bytes.extend_from_slice(&address.octets()),
    }
}

fn read_address(bytes: &[u8], ipv6: bool) -> Option<IpAddr> {
    if ipv6 {
        <[u8; 16]>::try_from(bytes)
            .ok()
            .map(|octets| IpAddr::V6(Ipv6Addr::from(octets)))
    } else {
        <[u8; 4]>::try_from(bytes)
            .ok()
            .map(|octets| IpAddr::V4(Ipv4Addr::from(octets)))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct VrrpCodec;

impl LayerCodec for VrrpCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &vrrp_schema().protocol
    }

    fn accepts_decoded_protocol(&self, protocol: &crate::layer::Id) -> bool {
        matches!(protocol.as_str(), "vrrp" | "raw")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<Vrrp>(NAME, layer)?;
        let version = layer.version;
        if !matches!(version, 2 | 3) {
            return Err(invalid(
                NAME,
                format!("VRRP version {version} has no encoding; use 2 or 3"),
            ));
        }
        if layer.vrrp_type > MAX_RESERVED {
            return Err(invalid(NAME, "VRRP type does not fit four bits"));
        }
        let envelope = resolve_envelope(NAME, context)?;
        let ipv6 = envelope.source.is_ipv6();
        let mut diagnostics = Vec::new();
        if version == 2 && ipv6 {
            // Decoding accepts this shape, so permissive builds keep it.
            strict_or_diagnostic(
                NAME,
                "build.vrrp_version",
                "version",
                "VRRP version 2 is IPv4-only",
                context,
                &mut diagnostics,
            )?;
        }
        // Version 2 addresses are IPv4 whatever carries them.
        let address_ipv6 = version == 3 && ipv6;
        if layer
            .addresses
            .iter()
            .any(|address| address.is_ipv6() != address_ipv6)
        {
            return Err(invalid(
                NAME,
                "VRRP addresses must be IPv4 in version 2 and match the IP version of the enclosing header in version 3",
            ));
        }
        let count = u8::try_from(layer.addresses.len()).map_err(|_| {
            invalid(
                NAME,
                format!("VRRP carries at most {MAX_ADDRESSES} addresses"),
            )
        })?;
        let addresses_len = layer
            .addresses
            .len()
            .checked_mul(address_len(address_ipv6))
            .ok_or_else(|| invalid(NAME, "address list length overflow"))?;
        let expected_auth = if version == 2 { V2_AUTH_LEN } else { 0 };
        let auth_data = layer
            .auth_data
            .clone()
            .unwrap_or_else(|| Bytes::from(vec![0; expected_auth]));
        let contribution = VRRP_HEADER_LEN
            .checked_add(addresses_len)
            .and_then(|length| length.checked_add(auth_data.len()))
            .ok_or_else(|| invalid(NAME, "message length overflow"))?;
        ensure_encode_budget(NAME, contribution, context)?;

        let (count_ip, materialized_count) = resolve_u8(
            NAME,
            "count_ip",
            &layer.count_ip,
            ValueExpectation::Required(count),
            context.mode,
            &mut diagnostics,
        )?;
        let interval_word = if version == 2 {
            [layer.auth_type, layer.advert_interval]
        } else {
            if layer.reserved > MAX_RESERVED || layer.max_advert_interval > MAX_ADVERT_INTERVAL {
                return Err(invalid(
                    NAME,
                    "VRRP version 3 reserved bits and interval do not fit 4 and 12 bits",
                ));
            }
            (u16::from(layer.reserved) << 12 | layer.max_advert_interval).to_be_bytes()
        };
        if auth_data.len() != expected_auth {
            strict_or_diagnostic(
                NAME,
                "build.vrrp_auth_data",
                "auth_data",
                format!(
                    "VRRP version {version} carries {expected_auth} bytes after the addresses, not {}",
                    auth_data.len()
                ),
                context,
                &mut diagnostics,
            )?;
        }

        let covered_payload = payload_without_padding(NAME, payload, context)?;
        let mut prefix = Vec::with_capacity(contribution);
        prefix.push(version << 4 | layer.vrrp_type);
        prefix.extend_from_slice(&[layer.vrid, layer.priority, count_ip]);
        prefix.extend_from_slice(&interval_word);
        prefix.extend_from_slice(&[0, 0]);
        for address in &layer.addresses {
            push_address(&mut prefix, *address);
        }
        prefix.extend_from_slice(&auth_data);
        let expected = if version == 2 {
            checksum_parts(&[&prefix, covered_payload])
        } else {
            transport_checksum_parts(
                NAME,
                envelope,
                ip_protocol::VRRP,
                &[&prefix, covered_payload],
            )?
        };
        let (checksum, materialized_checksum) = resolve_u16(
            NAME,
            "checksum",
            &layer.checksum,
            ValueExpectation::Required(expected),
            context.mode,
            &mut diagnostics,
        )?;
        prefix[6..8].copy_from_slice(&checksum.to_be_bytes());

        let mut materialized = layer.clone();
        materialized.count_ip = materialized_count;
        materialized.auth_data = Some(auth_data);
        materialized.checksum = materialized_checksum;
        let addresses_end = VRRP_HEADER_LEN.saturating_add(addresses_len);
        Ok(EncodedLayer::header(prefix, Box::new(materialized))
            .with_fields(vrrp_layout(version, addresses_end, contribution))
            .with_diagnostics(diagnostics))
    }

    fn decode(
        &self,
        input: Bytes,
        context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        let Some(&first) = input.first() else {
            return Err(truncated(NAME, VRRP_HEADER_LEN, 0));
        };
        let version = first >> 4;
        if !matches!(version, 2 | 3) {
            return Ok(Raw::decoded(input));
        }
        let Some(header) = input.first_chunk::<VRRP_HEADER_LEN>() else {
            return Err(truncated(NAME, VRRP_HEADER_LEN, input.len()));
        };
        let count = usize::from(header[3]);
        let body = &input[VRRP_HEADER_LEN..];

        let ipv6 = match (version, context.network) {
            (2, _) => false,
            (_, Some(network)) => network.destination.is_ipv6(),
            // without an IP header only the length can tell the families apart
            (_, None) => count > 0 && body.len() == count.saturating_mul(16),
        };
        let size = address_len(ipv6);
        // The declared count splits the body: up to `count` complete addresses
        // first, then whatever remains is the version 2 authentication data —
        // possibly short or absent in a truncated frame.
        let present = count.min(body.len() / size).min(MAX_ADDRESSES);
        let mut addresses = Vec::with_capacity(present);
        for bytes in body[..present * size].chunks_exact(size) {
            addresses.extend(read_address(bytes, ipv6));
        }
        let addresses_end = VRRP_HEADER_LEN + present * size;
        let auth_data = input.slice(addresses_end..);

        let mut diagnostics = Vec::new();
        let checksum_failed = if version == 2 {
            checksum(&input) != 0
        } else {
            match context.network {
                Some(network) => transport_checksum(NAME, network, ip_protocol::VRRP, &input)? != 0,
                None => false,
            }
        };
        if checksum_failed {
            diagnostics.push(
                Diagnostic::warning(VRRP_CHECKSUM, "VRRP checksum mismatch").at_field("checksum"),
            );
        }
        if context
            .hop_limit
            .is_some_and(|limit| limit != REQUIRED_HOP_LIMIT)
        {
            diagnostics.push(Diagnostic::warning(
                "decode.vrrp_ttl",
                format!("VRRP advertisement arrived with TTL or hop limit other than {REQUIRED_HOP_LIMIT}"),
            ));
        }
        if version == 2
            && context
                .network
                .is_some_and(|network| network.destination.is_ipv6())
        {
            diagnostics.push(
                Diagnostic::warning(
                    "decode.vrrp_version",
                    "VRRP version 2 is IPv4-only; its addresses are read as IPv4",
                )
                .at_field("version"),
            );
        }
        if let Some(network) = context.network {
            let expected: IpAddr = if network.destination.is_ipv6() {
                IPV6_GROUP.into()
            } else {
                IPV4_GROUP.into()
            };
            if network.destination != expected {
                diagnostics.push(Diagnostic::warning(
                    "decode.vrrp_destination",
                    format!("VRRP advertisement is not addressed to {expected}"),
                ));
            }
        }
        if present != count {
            diagnostics.push(
                Diagnostic::warning(
                    "decode.vrrp_count",
                    format!(
                        "count_ip is {count} but the message holds {present} complete addresses"
                    ),
                )
                .at_field("count_ip"),
            );
        }
        let expected_auth = if version == 2 { V2_AUTH_LEN } else { 0 };
        if auth_data.len() != expected_auth {
            diagnostics.push(
                Diagnostic::warning(
                    "decode.vrrp_length",
                    format!(
                        "{} bytes follow the addresses; version {version} carries {expected_auth}",
                        auth_data.len()
                    ),
                )
                .at_field("auth_data"),
            );
        }

        let interval = u16::from_be_bytes([header[4], header[5]]);
        let (auth_type, advert_interval, reserved, max_advert_interval) = if version == 2 {
            (header[4], header[5], 0, 0)
        } else {
            (0, 0, (interval >> 12) as u8, interval & MAX_ADVERT_INTERVAL)
        };
        Ok(DecodedLayer {
            layer: Box::new(Vrrp {
                version,
                vrrp_type: first & MAX_RESERVED,
                vrid: header[1],
                priority: header[2],
                count_ip: WireValue::Exact(header[3]),
                auth_type,
                advert_interval,
                reserved,
                max_advert_interval,
                checksum: WireValue::Exact(u16::from_be_bytes([header[6], header[7]])),
                addresses,
                auth_data: Some(auth_data),
            }),
            consumed: input.len(),
            payload_len: 0,
            next: Vec::new(),
            fields: vrrp_layout(version, addresses_end, input.len()),
            diagnostics,
            stop: true,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Vrrp::default(), fields)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::NetworkEnvelope;

    fn decode(
        input: &[u8],
        network: Option<NetworkEnvelope>,
        hop_limit: Option<u8>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        let registry = crate::protocol::builtin::registry();
        VrrpCodec.decode(
            Bytes::copy_from_slice(input),
            &LayerDecodeContext {
                parent: None,
                registry: &registry,
                network,
                hop_limit,
                discriminator: None,
            },
        )
    }

    fn codes(decoded: &DecodedLayer) -> Vec<&'static str> {
        decoded
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code)
            .collect()
    }

    fn v2_message() -> Vec<u8> {
        let mut message = vec![0x21, 7, 120, 1, 0, 1, 0, 0];
        message.extend_from_slice(&[192, 0, 2, 100]);
        message.extend_from_slice(&[0; 8]);
        message
    }

    #[test]
    fn short_inputs_are_truncated_and_huge_counts_stay_bounded() {
        for (input, available) in [(&[][..], 0), (&[0x31, 1, 1, 1, 0, 0, 0][..], 7)] {
            assert!(
                matches!(
                    decode(input, None, None),
                    Err(crate::codec::Error::Truncated { needed: 8, available: found, .. })
                        if found == available
                ),
                "{available}"
            );
        }
        // 255 announced addresses, none present
        let decoded = decode(&[0x31, 1, 1, 255, 0, 100, 0, 0], None, None).expect("decodes");
        let layer = decoded.layer.downcast_ref::<Vrrp>().expect("VRRP");
        assert!(layer.addresses.is_empty());
        assert_eq!(layer.count_ip, WireValue::Exact(255));
        assert_eq!(codes(&decoded), ["decode.vrrp_count"]);
    }

    #[test]
    fn a_version_2_count_reads_declared_addresses_before_a_short_trailer() {
        // one declared address and no trailer: the four bytes are the address,
        // and the missing authentication data is diagnosed on its own
        let mut message = v2_message()[..12].to_vec();
        let sum = checksum(&message);
        message[6..8].copy_from_slice(&sum.to_be_bytes());
        let decoded = decode(&message, None, None).expect("decodes");
        let layer = decoded.layer.downcast_ref::<Vrrp>().expect("VRRP");
        assert_eq!(layer.addresses, [IpAddr::from([192, 0, 2, 100])]);
        assert_eq!(layer.auth_data.as_deref(), Some(&[][..]));
        let length = decoded
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "decode.vrrp_length")
            .expect("length diagnostic");
        assert_eq!(
            length.message,
            "0 bytes follow the addresses; version 2 carries 8"
        );

        // a trailer that fits is authentication data; a partial one is diagnosed
        let mut short = v2_message();
        short.truncate(short.len() - 4);
        let sum = checksum(&short);
        short[6..8].copy_from_slice(&sum.to_be_bytes());
        let decoded = decode(&short, None, None).expect("decodes");
        let layer = decoded.layer.downcast_ref::<Vrrp>().expect("VRRP");
        assert_eq!(layer.addresses, [IpAddr::from([192, 0, 2, 100])]);
        assert_eq!(layer.auth_data.as_deref(), Some(&short[12..]));
        assert_eq!(codes(&decoded), ["decode.vrrp_length"]);
    }
}
