// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv6Addr;
use std::str::FromStr;

use super::error::{SpecError, SpecResult};

use crate::domain::request::Ipv6Request;

use super::utils::parse_hex_bytes;

#[derive(Debug, Clone, Default)]
pub(crate) struct Ipv6Spec {
    pub exthdrs: Vec<Ipv6ExtHeader>,
}

impl Ipv6Spec {
    pub(crate) fn from_request(request: &Ipv6Request) -> SpecResult<Self> {
        let mut headers = Vec::new();
        for entry in &request.extensions {
            let descriptor = entry.trim();
            if descriptor.is_empty() {
                return Err(SpecError::EmptyIpv6ExtensionDescriptor);
            }
            headers.push(parse_ipv6_ext_header(descriptor)?);
        }
        validate_ipv6_ext_chain(&headers)?;
        Ok(Self { exthdrs: headers })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Ipv6ExtHeader {
    HopByHop {
        options: Vec<u8>,
    },
    DestinationOptions {
        options: Vec<u8>,
    },
    Routing {
        routing_type: u8,
        segments: Vec<Ipv6Addr>,
        data: Option<u32>,
    },
}

// RFC 8200 section 4.4 limits routing headers to at most 23 segments to keep the
// header within the maximum IPv6 payload length. However, we allow up to 127
// segments to support larger headers if needed.
pub(crate) const MAX_ROUTING_SEGMENTS: usize = 127;
const MAX_IPV6_OPTIONS_HEADER_LEN: usize = 2048;

pub(crate) fn parse_ipv6_ext_header(raw: &str) -> SpecResult<Ipv6ExtHeader> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(SpecError::EmptyIpv6ExtensionDescriptor);
    }

    let (kind, params) = match raw.split_once(':') {
        Some((kind, params)) => (kind.trim().to_ascii_lowercase(), Some(params.trim())),
        None => (raw.to_ascii_lowercase(), None),
    };

    match kind.as_str() {
        "hopopts" | "hopopt" | "hop-by-hop" | "hop" => {
            let options = parse_ipv6_options_payload("hop-by-hop", params)?;
            Ok(Ipv6ExtHeader::HopByHop { options })
        }
        "destopts" | "destopt" | "destination" | "dest" => {
            let options = parse_ipv6_options_payload("destination", params)?;
            Ok(Ipv6ExtHeader::DestinationOptions { options })
        }
        "routing" | "route" => {
            let (routing_type, data, segments) = parse_ipv6_routing_descriptor(params)?;
            Ok(Ipv6ExtHeader::Routing {
                routing_type,
                segments,
                data,
            })
        }
        other => Err(SpecError::UnknownIpv6ExtensionHeader {
            header: other.to_string(),
        }),
    }
}

fn parse_ipv6_options_payload(kind: &str, params: Option<&str>) -> SpecResult<Vec<u8>> {
    let Some(raw) = params else {
        return Ok(Vec::new());
    };

    if raw.is_empty() {
        return Ok(Vec::new());
    }

    let value = if let Some((key, value)) = raw.split_once('=') {
        if !key.eq_ignore_ascii_case("options") {
            return Err(SpecError::UnknownIpv6ExtensionParameter {
                parameter: key.to_string(),
                descriptor: kind.to_string(),
            });
        }
        value
    } else {
        raw
    };

    parse_hex_bytes(value).map_err(|source| SpecError::Ipv6ExtensionPayloadParse {
        kind: kind.to_string(),
        source: Box::new(source),
    })
}

fn parse_ipv6_routing_descriptor(
    params: Option<&str>,
) -> SpecResult<(u8, Option<u32>, Vec<Ipv6Addr>)> {
    let Some(raw) = params else {
        return Err(SpecError::MissingIpv6RoutingSegments);
    };

    let (routing_type, data, segments_raw) = parse_routing_descriptor_params(raw)?;
    let segments = parse_routing_segments(&segments_raw)?;
    Ok((routing_type, data, segments))
}

fn parse_routing_descriptor_params(raw: &str) -> SpecResult<(u8, Option<u32>, String)> {
    if !raw.contains('=') {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(SpecError::MissingIpv6RoutingSegments);
        }
        return Ok((0, None, trimmed.to_string()));
    }

    let mut routing_type = 0u8;
    let mut data: Option<u32> = None;
    let mut segments_value: Option<String> = None;
    let mut tokens = raw
        .split([';', ','])
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .peekable();

    while let Some(token) = tokens.next() {
        if let Some((key, value)) = token.split_once('=') {
            let key_lower = key.trim().to_ascii_lowercase();
            let value = value.trim();
            match key_lower.as_str() {
                "type" | "routing_type" => {
                    routing_type =
                        value
                            .parse::<u8>()
                            .map_err(|source| SpecError::Ipv6RoutingTypeParse {
                                value: value.to_string(),
                                source,
                            })?;
                }
                "data" | "reserved" => {
                    let val = if value.starts_with("0x") || value.starts_with("0X") {
                        u32::from_str_radix(&value[2..], 16)
                    } else {
                        value.parse::<u32>()
                    };
                    data = Some(val.map_err(|source| SpecError::Ipv6RoutingTypeParse {
                        value: value.to_string(),
                        source,
                    })?);
                }
                "segments" => {
                    let collected = collect_segment_tokens(value, &mut tokens);
                    segments_value = Some(collected);
                }
                other => {
                    return Err(SpecError::UnknownIpv6RoutingParameter {
                        parameter: other.to_string(),
                    });
                }
            }
        } else {
            append_segment_token(&mut segments_value, token)?;
        }
    }

    let Some(segments_raw) = segments_value else {
        return Err(SpecError::MissingIpv6RoutingSegments);
    };

    Ok((routing_type, data, segments_raw))
}

fn collect_segment_tokens<'a, I>(initial: &str, tokens: &mut std::iter::Peekable<I>) -> String
where
    I: Iterator<Item = &'a str>,
{
    let mut collected = initial.trim().to_string();
    while let Some(next) = tokens.peek() {
        if next.contains('=') {
            break;
        }
        // Safety: We just peeked Some, so next() is guaranteed to be Some.
        if let Some(extra) = tokens.next() {
            let extra = extra.trim();
            if extra.is_empty() {
                continue;
            }
            if !collected.is_empty() {
                collected.push(';');
            }
            collected.push_str(extra);
        }
    }
    collected
}

fn append_segment_token(segments_value: &mut Option<String>, token: &str) -> SpecResult<()> {
    let Some(existing) = segments_value.as_mut() else {
        return Err(SpecError::UnknownIpv6RoutingParameter {
            parameter: token.to_string(),
        });
    };

    if !existing.is_empty() {
        existing.push(';');
    }
    existing.push_str(token);
    Ok(())
}

pub(crate) fn parse_routing_segments(segments_raw: &str) -> SpecResult<Vec<Ipv6Addr>> {
    let mut segments = Vec::new();
    for segment in segments_raw
        .split([';', '|', ' ', ','])
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let addr =
            Ipv6Addr::from_str(segment).map_err(|source| SpecError::Ipv6RoutingSegmentParse {
                segment: segment.to_string(),
                source,
            })?;
        if addr.is_multicast()
            || addr.is_loopback()
            || addr.is_unspecified()
            || addr.to_ipv4().is_some()
        {
            return Err(SpecError::Ipv6RoutingSegmentSpecialAddress { address: addr });
        }
        segments.push(addr);
    }

    if segments.is_empty() {
        return Err(SpecError::Ipv6RoutingSegmentsEmpty);
    }
    if segments.len() > MAX_ROUTING_SEGMENTS {
        return Err(SpecError::Ipv6RoutingSegmentsTooMany {
            max_segments: MAX_ROUTING_SEGMENTS,
        });
    }

    Ok(segments)
}

pub(crate) fn validate_ipv6_ext_chain(headers: &[Ipv6ExtHeader]) -> SpecResult<()> {
    let mut hop_seen = false;
    let mut routing_seen = false;
    let mut dest_count = 0usize;
    let mut total_length = 0usize;

    for (index, header) in headers.iter().enumerate() {
        let header_len = match header {
            Ipv6ExtHeader::HopByHop { options } => {
                measure_ipv6_options_header("Hop-by-Hop", options)?
            }
            Ipv6ExtHeader::DestinationOptions { options } => {
                measure_ipv6_options_header("Destination", options)?
            }
            Ipv6ExtHeader::Routing { segments, .. } => 8 + segments.len() * 16,
        };
        total_length = total_length
            .checked_add(header_len)
            .ok_or(SpecError::Ipv6ExtensionLengthOverflow)?;

        match header {
            Ipv6ExtHeader::HopByHop { .. } => {
                if hop_seen {
                    return Err(SpecError::Ipv6HopByHopDuplicate);
                }
                if index != 0 {
                    return Err(SpecError::Ipv6HopByHopNotFirst);
                }
                hop_seen = true;
            }
            Ipv6ExtHeader::DestinationOptions { .. } => {
                dest_count += 1;
                if dest_count > 2 {
                    return Err(SpecError::Ipv6DestinationOptionsTooMany);
                }
            }
            Ipv6ExtHeader::Routing { .. } => {
                if routing_seen {
                    return Err(SpecError::Ipv6RoutingDuplicate);
                }
                routing_seen = true;
            }
        }
    }

    if total_length > u16::MAX as usize {
        return Err(SpecError::Ipv6ExtensionPayloadTooLarge);
    }

    Ok(())
}

fn measure_ipv6_options_header(header: &'static str, options: &[u8]) -> SpecResult<usize> {
    let mut total = options
        .len()
        .checked_add(2)
        .ok_or(SpecError::Ipv6ExtensionLengthOverflow)?;
    if total < 8 {
        total = 8;
    }
    let remainder = total % 8;
    if remainder != 0 {
        total = total
            .checked_add(8 - remainder)
            .ok_or(SpecError::Ipv6ExtensionLengthOverflow)?;
    }
    if total > MAX_IPV6_OPTIONS_HEADER_LEN {
        return Err(SpecError::Ipv6OptionsHeaderTooLong {
            header,
            length: total,
            max: MAX_IPV6_OPTIONS_HEADER_LEN,
        });
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::request::Ipv6Request;

    #[test]
    fn parse_ipv6_ext_header_accepts_hop_options_hex() {
        let header = parse_ipv6_ext_header("hopopts:options=01 02 0a").unwrap();

        assert_eq!(
            header,
            Ipv6ExtHeader::HopByHop {
                options: vec![1, 2, 10]
            }
        );
    }

    #[test]
    fn parse_ipv6_ext_header_accepts_destination_options_alias() {
        let header = parse_ipv6_ext_header("dest:0x0a0b").unwrap();

        assert_eq!(
            header,
            Ipv6ExtHeader::DestinationOptions {
                options: vec![0x0a, 0x0b]
            }
        );
    }

    #[test]
    fn parse_ipv6_ext_header_accepts_simple_routing_segments() {
        let header = parse_ipv6_ext_header("route:2001:db8::1;2001:db8::2").unwrap();

        assert_eq!(
            header,
            Ipv6ExtHeader::Routing {
                routing_type: 0,
                segments: vec![
                    "2001:db8::1".parse().unwrap(),
                    "2001:db8::2".parse().unwrap()
                ],
                data: None,
            }
        );
    }

    #[test]
    fn parse_ipv6_ext_header_accepts_keyed_routing_descriptor() {
        let header =
            parse_ipv6_ext_header("routing:type=4,data=0x10,segments=2001:db8::5,2001:db8::6")
                .unwrap();

        assert_eq!(
            header,
            Ipv6ExtHeader::Routing {
                routing_type: 4,
                segments: vec![
                    "2001:db8::5".parse().unwrap(),
                    "2001:db8::6".parse().unwrap()
                ],
                data: Some(0x10),
            }
        );
    }

    #[test]
    fn parse_ipv6_ext_header_rejects_empty_and_unknown_headers() {
        assert!(matches!(
            parse_ipv6_ext_header(" ").unwrap_err(),
            SpecError::EmptyIpv6ExtensionDescriptor
        ));
        assert!(matches!(
            parse_ipv6_ext_header("bogus").unwrap_err(),
            SpecError::UnknownIpv6ExtensionHeader { .. }
        ));
    }

    #[test]
    fn parse_ipv6_ext_header_rejects_unknown_options_parameter() {
        let err = parse_ipv6_ext_header("hopopts:data=00").unwrap_err();

        assert!(matches!(
            err,
            SpecError::UnknownIpv6ExtensionParameter { .. }
        ));
    }

    #[test]
    fn parse_ipv6_ext_header_wraps_bad_options_hex() {
        let err = parse_ipv6_ext_header("dest:0x0").unwrap_err();

        assert!(matches!(err, SpecError::Ipv6ExtensionPayloadParse { .. }));
    }

    #[test]
    fn parse_routing_segments_rejects_empty_special_and_too_many() {
        assert!(matches!(
            parse_routing_segments("").unwrap_err(),
            SpecError::Ipv6RoutingSegmentsEmpty
        ));
        assert!(matches!(
            parse_routing_segments("::1").unwrap_err(),
            SpecError::Ipv6RoutingSegmentSpecialAddress { .. }
        ));

        let too_many = (0..=MAX_ROUTING_SEGMENTS)
            .map(|idx| format!("2001:db8::{idx:x}"))
            .collect::<Vec<_>>()
            .join(";");
        assert!(matches!(
            parse_routing_segments(&too_many).unwrap_err(),
            SpecError::Ipv6RoutingSegmentsTooMany {
                max_segments: MAX_ROUTING_SEGMENTS
            }
        ));
    }

    #[test]
    fn validate_ipv6_ext_chain_accepts_ordered_unique_headers() {
        let headers = vec![
            Ipv6ExtHeader::HopByHop { options: vec![] },
            Ipv6ExtHeader::Routing {
                routing_type: 0,
                segments: vec!["2001:db8::1".parse().unwrap()],
                data: None,
            },
            Ipv6ExtHeader::DestinationOptions {
                options: vec![0, 1],
            },
        ];

        validate_ipv6_ext_chain(&headers).unwrap();
    }

    #[test]
    fn validate_ipv6_ext_chain_rejects_hop_by_hop_not_first() {
        let err = validate_ipv6_ext_chain(&[
            Ipv6ExtHeader::DestinationOptions { options: vec![] },
            Ipv6ExtHeader::HopByHop { options: vec![] },
        ])
        .unwrap_err();

        assert!(matches!(err, SpecError::Ipv6HopByHopNotFirst));
    }

    #[test]
    fn validate_ipv6_ext_chain_rejects_duplicate_hop_by_hop() {
        let err = validate_ipv6_ext_chain(&[
            Ipv6ExtHeader::HopByHop { options: vec![] },
            Ipv6ExtHeader::HopByHop { options: vec![] },
        ])
        .unwrap_err();

        assert!(matches!(err, SpecError::Ipv6HopByHopDuplicate));
    }

    #[test]
    fn validate_ipv6_ext_chain_rejects_too_many_destination_headers() {
        let err = validate_ipv6_ext_chain(&[
            Ipv6ExtHeader::DestinationOptions { options: vec![] },
            Ipv6ExtHeader::DestinationOptions { options: vec![] },
            Ipv6ExtHeader::DestinationOptions { options: vec![] },
        ])
        .unwrap_err();

        assert!(matches!(err, SpecError::Ipv6DestinationOptionsTooMany));
    }

    #[test]
    fn validate_ipv6_ext_chain_rejects_duplicate_routing_header() {
        let routing = Ipv6ExtHeader::Routing {
            routing_type: 0,
            segments: vec!["2001:db8::1".parse().unwrap()],
            data: None,
        };
        let err = validate_ipv6_ext_chain(&[routing.clone(), routing]).unwrap_err();

        assert!(matches!(err, SpecError::Ipv6RoutingDuplicate));
    }

    #[test]
    fn validate_ipv6_ext_chain_rejects_oversized_options_header() {
        let err = validate_ipv6_ext_chain(&[Ipv6ExtHeader::HopByHop {
            options: vec![0; 2047],
        }])
        .unwrap_err();

        assert!(matches!(
            err,
            SpecError::Ipv6OptionsHeaderTooLong {
                header: "Hop-by-Hop",
                ..
            }
        ));
    }

    #[test]
    fn ipv6_spec_from_request_parses_and_validates_chain() {
        let spec = Ipv6Spec::from_request(&Ipv6Request {
            extensions: vec![
                "hop".to_string(),
                "routing:segments=2001:db8::1".to_string(),
                "dest:aa".to_string(),
            ],
        })
        .unwrap();

        assert_eq!(spec.exthdrs.len(), 3);
    }

    #[test]
    fn ipv6_spec_from_request_rejects_blank_descriptor() {
        let err = Ipv6Spec::from_request(&Ipv6Request {
            extensions: vec![" ".to_string()],
        })
        .unwrap_err();

        assert!(matches!(err, SpecError::EmptyIpv6ExtensionDescriptor));
    }
}
