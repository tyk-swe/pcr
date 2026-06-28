use std::net::Ipv6Addr;
use std::str::FromStr;

use super::error::{SpecError, SpecResult};

use crate::engine::request::Ipv6Request;

use super::utils::parse_hex_bytes;

#[derive(Debug, Clone, Default)]
pub struct Ipv6Spec {
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
pub enum Ipv6ExtHeader {
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
pub const MAX_ROUTING_SEGMENTS: usize = 127;

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
            Ipv6ExtHeader::HopByHop { options } | Ipv6ExtHeader::DestinationOptions { options } => {
                let mut total = options.len() + 2;
                if total < 8 {
                    total = 8;
                }
                let remainder = total % 8;
                if remainder == 0 {
                    total
                } else {
                    total + (8 - remainder)
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::request::Ipv6Request;

    #[test]
    fn parse_option_header_aliases() {
        for variant in ["hop", "hopopts", "hopopt", "hop-by-hop"] {
            let header = parse_ipv6_ext_header(variant).unwrap();
            assert!(matches!(header, Ipv6ExtHeader::HopByHop { .. }));
        }

        for variant in ["dest", "destopts", "destopt", "destination"] {
            let header = parse_ipv6_ext_header(variant).unwrap();
            assert!(matches!(header, Ipv6ExtHeader::DestinationOptions { .. }));
        }
    }

    #[test]
    fn parse_routing_header_forms() {
        for (raw, expected_type, expected_segments) in [
            ("routing:2001:db8::1", 0, 1),
            ("routing:2001:db8::1;2001:db8::2;2001:db8::3", 0, 3),
            ("routing:type=2,segments=2001:db8::1", 2, 1),
            ("routing:2001:db8::1 2001:db8::2", 0, 2),
        ] {
            let header = parse_ipv6_ext_header(raw).unwrap();
            match header {
                Ipv6ExtHeader::Routing {
                    routing_type,
                    segments,
                    data,
                } => {
                    assert_eq!(routing_type, expected_type, "{raw}");
                    assert_eq!(segments.len(), expected_segments, "{raw}");
                    assert!(data.is_none(), "{raw}");
                }
                _ => panic!("Expected Routing header"),
            }
        }
    }

    #[test]
    fn parse_routing_segments_rejects_special_addresses() {
        for raw in ["ff02::1", "::1", "::"] {
            let result = parse_routing_segments(raw);
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                SpecError::Ipv6RoutingSegmentSpecialAddress { .. }
            ));
        }
    }

    #[test]
    fn parse_routing_segments_empty_error() {
        let result = parse_routing_segments("");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpecError::Ipv6RoutingSegmentsEmpty
        ));
    }

    #[test]
    fn parse_routing_segments_too_many() {
        let segments: Vec<String> = (1..=128).map(|i| format!("2001:db8::{:x}", i)).collect();
        let joined = segments.join(";");
        let result = parse_routing_segments(&joined);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpecError::Ipv6RoutingSegmentsTooMany { .. }
        ));
    }

    #[test]
    fn parse_routing_segments_max_allowed() {
        let segments: Vec<String> = (1..=127).map(|i| format!("2001:db8::{:x}", i)).collect();
        let joined = segments.join(";");
        let result = parse_routing_segments(&joined);
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.len(), 127);
    }

    #[test]
    fn parse_ipv6_ext_header_empty_error() {
        let result = parse_ipv6_ext_header("");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpecError::EmptyIpv6ExtensionDescriptor
        ));
    }

    #[test]
    fn parse_ipv6_ext_header_unknown() {
        let result = parse_ipv6_ext_header("unknown");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpecError::UnknownIpv6ExtensionHeader { .. }
        ));
    }

    #[test]
    fn parse_routing_missing_segments() {
        let result = parse_ipv6_ext_header("routing");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpecError::MissingIpv6RoutingSegments
        ));
    }

    #[test]
    fn validate_hopbyhop_must_be_first() {
        let headers = vec![
            parse_ipv6_ext_header("dest").unwrap(),
            parse_ipv6_ext_header("hop").unwrap(),
        ];
        let result = validate_ipv6_ext_chain(&headers);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpecError::Ipv6HopByHopNotFirst
        ));
    }

    #[test]
    fn validate_hopbyhop_duplicate() {
        let headers = vec![
            parse_ipv6_ext_header("hop").unwrap(),
            parse_ipv6_ext_header("hop").unwrap(),
        ];
        let result = validate_ipv6_ext_chain(&headers);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpecError::Ipv6HopByHopDuplicate
        ));
    }

    #[test]
    fn validate_routing_duplicate() {
        let headers = vec![
            parse_ipv6_ext_header("routing:2001:db8::1").unwrap(),
            parse_ipv6_ext_header("routing:2001:db8::2").unwrap(),
        ];
        let result = validate_ipv6_ext_chain(&headers);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpecError::Ipv6RoutingDuplicate
        ));
    }

    #[test]
    fn validate_destination_options_too_many() {
        let headers = vec![
            parse_ipv6_ext_header("dest").unwrap(),
            parse_ipv6_ext_header("dest").unwrap(),
            parse_ipv6_ext_header("dest").unwrap(),
        ];
        let result = validate_ipv6_ext_chain(&headers);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpecError::Ipv6DestinationOptionsTooMany
        ));
    }

    #[test]
    fn validate_destination_options_two_allowed() {
        let headers = vec![
            parse_ipv6_ext_header("dest").unwrap(),
            parse_ipv6_ext_header("dest").unwrap(),
        ];
        let result = validate_ipv6_ext_chain(&headers);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_valid_chain() {
        let headers = vec![
            parse_ipv6_ext_header("hop").unwrap(),
            parse_ipv6_ext_header("dest").unwrap(),
            parse_ipv6_ext_header("routing:2001:db8::1").unwrap(),
            parse_ipv6_ext_header("dest").unwrap(),
        ];
        let result = validate_ipv6_ext_chain(&headers);
        assert!(result.is_ok());
    }

    #[test]
    fn ipv6_spec_with_extensions() {
        let options = Ipv6Request {
            extensions: vec!["hop".to_string(), "routing:2001:db8::1".to_string()],
        };
        let spec = Ipv6Spec::from_request(&options).unwrap();
        assert_eq!(spec.exthdrs.len(), 2);
    }

    #[test]
    fn ipv6_spec_rejects_empty_descriptor() {
        let options = Ipv6Request {
            extensions: vec!["".to_string()],
        };
        let result = Ipv6Spec::from_request(&options);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpecError::EmptyIpv6ExtensionDescriptor
        ));
    }

    #[test]
    fn hopbyhop_with_hex_payload() {
        let header = parse_ipv6_ext_header("hop:0102030405").unwrap();
        match header {
            Ipv6ExtHeader::HopByHop { options } => {
                assert_eq!(options, vec![0x01, 0x02, 0x03, 0x04, 0x05]);
            }
            _ => panic!("Expected HopByHop header"),
        }
    }

    #[test]
    fn destination_with_options_param() {
        let header = parse_ipv6_ext_header("dest:options=aabbccdd").unwrap();
        match header {
            Ipv6ExtHeader::DestinationOptions { options } => {
                assert_eq!(options, vec![0xaa, 0xbb, 0xcc, 0xdd]);
            }
            _ => panic!("Expected DestinationOptions header"),
        }
    }

    #[test]
    fn ipv6_routing_header_parsing_limits() {
        // Try to parse 24 segments - should be allowed now (up to 127)
        let segments: Vec<String> = (1..=24).map(|i| format!("2001:db8::{:x}", i)).collect();
        let descriptor = format!("routing:{}", segments.join(";"));
        let result = parse_ipv6_ext_header(&descriptor);
        assert!(result.is_ok());

        // Try to parse 128 segments - should fail
        let segments: Vec<String> = (1..=128).map(|i| format!("2001:db8::{:x}", i)).collect();
        let descriptor = format!("routing:{}", segments.join(";"));
        let result = parse_ipv6_ext_header(&descriptor);
        assert!(result.is_err());
        match result {
            Err(SpecError::Ipv6RoutingSegmentsTooMany { max_segments }) => {
                assert_eq!(max_segments, 127);
            }
            _ => panic!(
                "Expected Ipv6RoutingSegmentsTooMany error, got {:?}",
                result
            ),
        }
    }

    #[test]
    fn ipv6_routing_header_data_field() {
        // Test parsing "data" field
        let descriptor = "routing:data=0x12345678,segments=2001:db8::1";
        let result = parse_ipv6_ext_header(descriptor).unwrap();

        match result {
            Ipv6ExtHeader::Routing { data, .. } => {
                assert_eq!(data, Some(0x12345678));
            }
            _ => panic!("Expected Routing header"),
        }

        // Test parsing "reserved" alias
        let descriptor = "routing:reserved=0x87654321,segments=2001:db8::1";
        let result = parse_ipv6_ext_header(descriptor).unwrap();

        match result {
            Ipv6ExtHeader::Routing { data, .. } => {
                assert_eq!(data, Some(0x87654321));
            }
            _ => panic!("Expected Routing header"),
        }

        // Test parsing decimal
        let descriptor = "routing:data=12345,segments=2001:db8::1";
        let result = parse_ipv6_ext_header(descriptor).unwrap();

        match result {
            Ipv6ExtHeader::Routing { data, .. } => {
                assert_eq!(data, Some(12345));
            }
            _ => panic!("Expected Routing header"),
        }
    }
}

#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn parser_accepts_valid_routing_strings(
            count in 1usize..20usize
        ) {
            // Construct a valid string
            // routing:2001:db8::1;2001:db8::2...
            let mut s = String::from("routing:");
            for i in 0..count {
                if i > 0 { s.push(';'); }
                s.push_str(&format!("2001:db8::{:x}", i + 1));
            }

            let res = parse_ipv6_ext_header(&s);
            prop_assert!(res.is_ok(), "Failed to parse valid string: {}", s);
        }

        #[test]
        fn parser_accepts_valid_hex_options(
            bytes in prop::collection::vec(any::<u8>(), 0..100)
        ) {
            let hex_str: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
            let input = format!("hop:options={}", hex_str);

            let res = parse_ipv6_ext_header(&input);
            prop_assert!(res.is_ok(), "Failed to parse valid hop options: {}", input);

            if let Ok(Ipv6ExtHeader::HopByHop { options }) = res {
                prop_assert_eq!(options, bytes);
            }
        }
    }
}
