// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv6Addr;

use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};

use crate::engine::spec::{Ipv6ExtHeader, MAX_ROUTING_SEGMENTS};
use crate::network::sender::error::Ipv6Error;

type Ipv6Result<T> = std::result::Result<T, Ipv6Error>;

pub(super) fn split_fragment_extension_headers(
    headers: &[Ipv6ExtHeader],
) -> (&[Ipv6ExtHeader], &[Ipv6ExtHeader]) {
    let mut index = headers.len();
    while index > 0 {
        if matches!(headers[index - 1], Ipv6ExtHeader::DestinationOptions { .. }) {
            index -= 1;
        } else {
            break;
        }
    }

    if index == headers.len() {
        (headers, &[])
    } else {
        (&headers[..index], &headers[index..])
    }
}

pub(super) fn encode_extension_headers(
    headers: &[Ipv6ExtHeader],
    terminal: IpNextHeaderProtocol,
    final_destination: Ipv6Addr,
) -> Ipv6Result<(Vec<u8>, IpNextHeaderProtocol)> {
    if headers.is_empty() {
        return Ok((Vec::new(), terminal));
    }

    let len = measure_extension_headers(headers, final_destination)?;
    let mut buffer = vec![0u8; len];
    let next = write_extension_headers(headers, terminal, final_destination, &mut buffer)?;
    Ok((buffer, next))
}

pub(crate) fn routing_initial_destination(
    headers: &[Ipv6ExtHeader],
    default: Ipv6Addr,
) -> Ipv6Addr {
    first_routing_segment(headers).unwrap_or(default)
}

fn first_routing_segment(headers: &[Ipv6ExtHeader]) -> Option<Ipv6Addr> {
    headers.iter().find_map(|header| match header {
        Ipv6ExtHeader::Routing { segments, .. } => segments.first().copied(),
        _ => None,
    })
}

pub(super) fn measure_extension_headers(
    headers: &[Ipv6ExtHeader],
    final_destination: Ipv6Addr,
) -> Ipv6Result<usize> {
    let mut total = 0usize;
    for header in headers {
        total = total
            .checked_add(measure_single_extension_header(header, final_destination)?)
            .ok_or(Ipv6Error::ExtensionLengthOverflow)?;
    }
    Ok(total)
}

pub(super) fn write_extension_headers(
    headers: &[Ipv6ExtHeader],
    terminal: IpNextHeaderProtocol,
    final_destination: Ipv6Addr,
    buffer: &mut [u8],
) -> Ipv6Result<IpNextHeaderProtocol> {
    if headers.is_empty() {
        return Ok(terminal);
    }

    let mut offset = 0;
    let first_next_header = get_header_protocol(&headers[0]);

    for (i, header) in headers.iter().enumerate() {
        let next_proto = if i + 1 < headers.len() {
            get_header_protocol(&headers[i + 1])
        } else {
            terminal
        };

        let len = measure_single_extension_header(header, final_destination)?;
        let region = &mut buffer[offset..offset + len];
        write_single_extension_header(header, next_proto, final_destination, region)?;
        offset += len;
    }

    Ok(first_next_header)
}

pub(super) fn get_header_protocol(header: &Ipv6ExtHeader) -> IpNextHeaderProtocol {
    match header {
        Ipv6ExtHeader::HopByHop { .. } => IpNextHeaderProtocols::Hopopt,
        Ipv6ExtHeader::DestinationOptions { .. } => IpNextHeaderProtocols::Ipv6Opts,
        Ipv6ExtHeader::Routing { .. } => IpNextHeaderProtocols::Ipv6Route,
    }
}

fn measure_single_extension_header(
    header: &Ipv6ExtHeader,
    final_destination: Ipv6Addr,
) -> Ipv6Result<usize> {
    match header {
        Ipv6ExtHeader::HopByHop { options } => measure_options_header(options),
        Ipv6ExtHeader::DestinationOptions { options } => measure_options_header(options),
        Ipv6ExtHeader::Routing { segments, .. } => {
            measure_routing_header(segments, final_destination)
        }
    }
}

fn write_single_extension_header(
    header: &Ipv6ExtHeader,
    next_header: IpNextHeaderProtocol,
    final_destination: Ipv6Addr,
    buffer: &mut [u8],
) -> Ipv6Result<()> {
    match header {
        Ipv6ExtHeader::HopByHop { options } => write_options_header(options, next_header, buffer),
        Ipv6ExtHeader::DestinationOptions { options } => {
            write_options_header(options, next_header, buffer)
        }
        Ipv6ExtHeader::Routing {
            routing_type,
            segments,
            data,
        } => write_routing_header(
            *routing_type,
            segments,
            *data,
            next_header,
            final_destination,
            buffer,
        ),
    }
}

fn measure_options_header(options: &[u8]) -> Ipv6Result<usize> {
    let mut total_len = options.len() + 2;
    if total_len < 8 {
        total_len = 8;
    }
    let len = round_up_to_multiple_of_eight(total_len)?;
    if len > 2048 {
        return Err(Ipv6Error::OptionsTooLong);
    }
    Ok(len)
}

fn write_options_header(
    options: &[u8],
    next_header: IpNextHeaderProtocol,
    buffer: &mut [u8],
) -> Ipv6Result<()> {
    let total_len = buffer.len();
    let units = total_len / 8;
    if units == 0 || units > 256 {
        return Err(Ipv6Error::OptionsTooLong);
    }
    let hdr_ext_len = (units - 1) as u8;

    buffer[0] = next_header.0;
    buffer[1] = hdr_ext_len;
    buffer[2..2 + options.len()].copy_from_slice(options);
    buffer[(2 + options.len())..total_len].fill(0);
    Ok(())
}

fn measure_routing_header(segments: &[Ipv6Addr], final_destination: Ipv6Addr) -> Ipv6Result<usize> {
    if segments.is_empty() {
        return Err(Ipv6Error::RoutingMissingSegment);
    }
    if segments.len() > MAX_ROUTING_SEGMENTS {
        return Err(Ipv6Error::RoutingTooManySegments {
            max: MAX_ROUTING_SEGMENTS,
            count: segments.len(),
        });
    }

    let mut count = segments.len() - 1; // segments[1..]
    if let Some(last_segment) = segments.last() {
        if *last_segment != final_destination {
            count += 1;
        }
    }

    let total_len = 8 + count * 16;
    let units = total_len / 8;
    if units == 0 || units > 256 {
        return Err(Ipv6Error::RoutingTooLong);
    }
    Ok(total_len)
}

fn write_routing_header(
    routing_type: u8,
    segments: &[Ipv6Addr],
    data: Option<u32>,
    next_header: IpNextHeaderProtocol,
    final_destination: Ipv6Addr,
    buffer: &mut [u8],
) -> Ipv6Result<()> {
    if segments.is_empty() {
        return Err(Ipv6Error::RoutingMissingSegment);
    }

    let total_len = buffer.len();
    let units = total_len / 8;
    let hdr_ext_len = (units - 1) as u8;

    let mut path_len = segments.len() - 1;
    if let Some(last_segment) = segments.last() {
        if *last_segment != final_destination {
            path_len += 1;
        }
    }

    buffer[0] = next_header.0;
    buffer[1] = hdr_ext_len;
    buffer[2] = routing_type;
    buffer[3] = path_len as u8; // Segments Left
                                // Use user data or Reserved (0)
    let reserved = data.unwrap_or(0);
    buffer[4..8].copy_from_slice(&reserved.to_be_bytes());

    let mut offset = 8;
    for segment in segments.iter().skip(1) {
        buffer[offset..offset + 16].copy_from_slice(&segment.octets());
        offset += 16;
    }
    if let Some(last_segment) = segments.last() {
        if *last_segment != final_destination {
            buffer[offset..offset + 16].copy_from_slice(&final_destination.octets());
        }
    }

    Ok(())
}

fn round_up_to_multiple_of_eight(value: usize) -> Ipv6Result<usize> {
    let remainder = value % 8;
    if remainder == 0 {
        return Ok(value);
    }
    value
        .checked_add(8 - remainder)
        .ok_or(Ipv6Error::ExtensionLengthOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_options_header_bytes(options: &[u8]) -> Ipv6Result<Vec<u8>> {
        let len = measure_options_header(options)?;
        let mut buffer = vec![0u8; len];
        write_options_header(options, IpNextHeaderProtocol(0), &mut buffer)?;
        Ok(buffer)
    }

    fn encode_routing_header_bytes(
        routing_type: u8,
        segments: &[Ipv6Addr],
        final_destination: Ipv6Addr,
    ) -> Ipv6Result<Vec<u8>> {
        let len = measure_routing_header(segments, final_destination)?;
        let mut buffer = vec![0u8; len];
        write_routing_header(
            routing_type,
            segments,
            None,
            IpNextHeaderProtocol(0),
            final_destination,
            &mut buffer,
        )?;
        Ok(buffer)
    }

    #[test]
    fn round_up_to_multiple_of_eight_already_multiple() {
        assert_eq!(round_up_to_multiple_of_eight(0).unwrap(), 0);
        assert_eq!(round_up_to_multiple_of_eight(8).unwrap(), 8);
        assert_eq!(round_up_to_multiple_of_eight(16).unwrap(), 16);
        assert_eq!(round_up_to_multiple_of_eight(24).unwrap(), 24);
        assert_eq!(round_up_to_multiple_of_eight(64).unwrap(), 64);
    }

    #[test]
    fn round_up_to_multiple_of_eight_rounds_up() {
        assert_eq!(round_up_to_multiple_of_eight(1).unwrap(), 8);
        assert_eq!(round_up_to_multiple_of_eight(7).unwrap(), 8);
        assert_eq!(round_up_to_multiple_of_eight(9).unwrap(), 16);
        assert_eq!(round_up_to_multiple_of_eight(15).unwrap(), 16);
        assert_eq!(round_up_to_multiple_of_eight(17).unwrap(), 24);
        assert_eq!(round_up_to_multiple_of_eight(23).unwrap(), 24);
    }

    #[test]
    fn round_up_to_multiple_of_eight_with_midpoints() {
        assert_eq!(round_up_to_multiple_of_eight(4).unwrap(), 8);
        assert_eq!(round_up_to_multiple_of_eight(12).unwrap(), 16);
        assert_eq!(round_up_to_multiple_of_eight(20).unwrap(), 24);
    }

    #[test]
    fn round_up_to_multiple_of_eight_overflow() {
        let result = round_up_to_multiple_of_eight(usize::MAX - 3);
        assert!(matches!(result, Err(Ipv6Error::ExtensionLengthOverflow)));
    }

    #[test]
    fn split_fragment_extension_headers_no_destination_options() {
        let headers = vec![
            Ipv6ExtHeader::HopByHop {
                options: vec![1, 2],
            },
            Ipv6ExtHeader::Routing {
                routing_type: 0,
                segments: vec![Ipv6Addr::LOCALHOST],
                data: None,
            },
        ];

        let (per_fragment, trailing) = split_fragment_extension_headers(&headers);

        assert_eq!(per_fragment.len(), 2);
        assert_eq!(trailing.len(), 0);
    }

    #[test]
    fn split_fragment_extension_headers_with_trailing_destination_options() {
        let headers = vec![
            Ipv6ExtHeader::HopByHop {
                options: vec![1, 2],
            },
            Ipv6ExtHeader::DestinationOptions {
                options: vec![3, 4],
            },
        ];

        let (per_fragment, trailing) = split_fragment_extension_headers(&headers);

        assert_eq!(per_fragment.len(), 1);
        assert_eq!(trailing.len(), 1);
        assert!(matches!(per_fragment[0], Ipv6ExtHeader::HopByHop { .. }));
        assert!(matches!(
            trailing[0],
            Ipv6ExtHeader::DestinationOptions { .. }
        ));
    }

    #[test]
    fn split_fragment_extension_headers_all_destination_options() {
        let headers = vec![
            Ipv6ExtHeader::DestinationOptions {
                options: vec![1, 2],
            },
            Ipv6ExtHeader::DestinationOptions {
                options: vec![3, 4],
            },
        ];

        let (per_fragment, trailing) = split_fragment_extension_headers(&headers);

        assert_eq!(per_fragment.len(), 0);
        assert_eq!(trailing.len(), 2);
    }

    #[test]
    fn split_fragment_extension_headers_empty() {
        let headers: Vec<Ipv6ExtHeader> = vec![];

        let (per_fragment, trailing) = split_fragment_extension_headers(&headers);

        assert_eq!(per_fragment.len(), 0);
        assert_eq!(trailing.len(), 0);
    }

    #[test]
    fn split_fragment_extension_headers_complex_sequence() {
        let headers = vec![
            Ipv6ExtHeader::HopByHop {
                options: vec![1, 2],
            },
            Ipv6ExtHeader::Routing {
                routing_type: 0,
                segments: vec![Ipv6Addr::LOCALHOST],
                data: None,
            },
            Ipv6ExtHeader::DestinationOptions {
                options: vec![3, 4],
            },
            Ipv6ExtHeader::DestinationOptions {
                options: vec![5, 6],
            },
        ];

        let (per_fragment, trailing) = split_fragment_extension_headers(&headers);

        assert_eq!(per_fragment.len(), 2);
        assert_eq!(trailing.len(), 2);
    }

    #[test]
    fn routing_initial_destination_no_routing_header() {
        let headers: Vec<Ipv6ExtHeader> = vec![];
        let default = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        let result = routing_initial_destination(&headers, default);

        assert_eq!(result, default);
    }

    #[test]
    fn routing_initial_destination_with_routing_header() {
        let first_segment = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 100);
        let headers = vec![Ipv6ExtHeader::Routing {
            routing_type: 0,
            segments: vec![first_segment, Ipv6Addr::LOCALHOST],
            data: None,
        }];
        let default = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        let result = routing_initial_destination(&headers, default);

        assert_eq!(result, first_segment);
    }

    #[test]
    fn routing_initial_destination_with_other_headers() {
        let headers = vec![
            Ipv6ExtHeader::HopByHop {
                options: vec![1, 2],
            },
            Ipv6ExtHeader::DestinationOptions {
                options: vec![3, 4],
            },
        ];
        let default = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        let result = routing_initial_destination(&headers, default);

        assert_eq!(result, default);
    }

    #[test]
    fn first_routing_segment_finds_segment() {
        let target = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 42);
        let headers = vec![
            Ipv6ExtHeader::HopByHop {
                options: vec![1, 2],
            },
            Ipv6ExtHeader::Routing {
                routing_type: 0,
                segments: vec![target, Ipv6Addr::LOCALHOST],
                data: None,
            },
        ];

        let result = first_routing_segment(&headers);

        assert_eq!(result, Some(target));
    }

    #[test]
    fn first_routing_segment_returns_none_when_no_routing() {
        let headers = vec![Ipv6ExtHeader::HopByHop {
            options: vec![1, 2],
        }];

        let result = first_routing_segment(&headers);

        assert_eq!(result, None);
    }

    #[test]
    fn first_routing_segment_returns_none_when_empty() {
        let headers: Vec<Ipv6ExtHeader> = vec![];

        let result = first_routing_segment(&headers);

        assert_eq!(result, None);
    }

    #[test]
    fn encode_options_header_bytes_pads_to_minimum() {
        let options = vec![];

        let result = encode_options_header_bytes(&options).unwrap();

        assert_eq!(result.len(), 8);
        assert_eq!(result[1], 0); // hdr_ext_len for 8 bytes
    }

    #[test]
    fn encode_options_header_bytes_pads_to_multiple_of_eight() {
        let options = vec![1, 2, 3]; // 3 bytes + 2 header = 5, rounds to 8

        let result = encode_options_header_bytes(&options).unwrap();

        assert_eq!(result.len(), 8);
        assert_eq!(result[2], 1);
        assert_eq!(result[3], 2);
        assert_eq!(result[4], 3);
    }

    #[test]
    fn encode_options_header_bytes_with_exact_multiple() {
        let options = vec![1, 2, 3, 4, 5, 6]; // 6 bytes + 2 header = 8

        let result = encode_options_header_bytes(&options).unwrap();

        assert_eq!(result.len(), 8);
        assert_eq!(result[1], 0); // hdr_ext_len
    }

    #[test]
    fn encode_options_header_bytes_larger_payload() {
        let options = vec![1, 2, 3, 4, 5, 6, 7, 8, 9]; // 9 + 2 = 11, rounds to 16

        let result = encode_options_header_bytes(&options).unwrap();

        assert_eq!(result.len(), 16);
        assert_eq!(result[1], 1); // hdr_ext_len for 16 bytes
    }

    #[test]
    fn encode_routing_header_bytes_single_segment() {
        let segments = vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)];
        let final_dest = Ipv6Addr::LOCALHOST;

        let result = encode_routing_header_bytes(0, &segments, final_dest).unwrap();

        // path = [final_dest], since len=1, no reversed segments
        // total_len = 8 + 1 * 16 = 24
        assert_eq!(result.len(), 24);
        assert_eq!(result[2], 0); // routing_type
        assert_eq!(result[3], 1); // segments_left
    }

    #[test]
    fn encode_routing_header_bytes_multiple_segments() {
        let segments = vec![
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3),
        ];
        let final_dest = Ipv6Addr::LOCALHOST;

        let result = encode_routing_header_bytes(0, &segments, final_dest).unwrap();

        // path = [segments[1], segments[2], final_dest]
        // total_len = 8 + 3 * 16 = 56
        assert_eq!(result.len(), 56);
        assert_eq!(result[3], 3); // segments_left
    }

    #[test]
    fn encode_routing_header_bytes_avoids_duplicate_final_destination() {
        let final_dest = Ipv6Addr::LOCALHOST;
        let segments = vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), final_dest];

        let result = encode_routing_header_bytes(0, &segments, final_dest).unwrap();

        // path should include only the remaining segment (final_dest) once.
        assert_eq!(result[3], 1); // segments_left

        let encoded_dest = Ipv6Addr::from(u128::from_be_bytes(
            result[8..24].try_into().expect("address bytes"),
        ));
        assert_eq!(encoded_dest, final_dest);
    }

    #[test]
    fn encode_routing_header_bytes_rejects_empty_segments() {
        let segments: Vec<Ipv6Addr> = vec![];
        let final_dest = Ipv6Addr::LOCALHOST;

        let result = encode_routing_header_bytes(0, &segments, final_dest);

        assert!(matches!(result, Err(Ipv6Error::RoutingMissingSegment)));
    }

    #[test]
    fn encode_routing_header_bytes_rejects_too_many_segments() {
        let segments = vec![Ipv6Addr::LOCALHOST; MAX_ROUTING_SEGMENTS + 1];
        let final_dest = Ipv6Addr::LOCALHOST;

        let result = encode_routing_header_bytes(0, &segments, final_dest);

        assert!(matches!(
            result,
            Err(Ipv6Error::RoutingTooManySegments { .. })
        ));
    }

    #[test]
    fn round_up_to_multiple_of_eight_large_values() {
        assert_eq!(round_up_to_multiple_of_eight(1000).unwrap(), 1000);
        assert_eq!(round_up_to_multiple_of_eight(1001).unwrap(), 1008);
        assert_eq!(round_up_to_multiple_of_eight(1007).unwrap(), 1008);
    }

    #[test]
    fn split_fragment_extension_headers_single_element() {
        let headers = vec![Ipv6ExtHeader::HopByHop {
            options: vec![1, 2],
        }];

        let (per_fragment, trailing) = split_fragment_extension_headers(&headers);

        assert_eq!(per_fragment.len(), 1);
        assert_eq!(trailing.len(), 0);
    }

    #[test]
    fn encode_routing_header_bytes_verifies_segment_order() {
        let s1 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let s2 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let s3 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3);
        let segments = vec![s1, s2, s3];
        let final_dest = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 99);

        let result = encode_routing_header_bytes(0, &segments, final_dest).unwrap();

        // Expected order in packet: [s2, s3, final_dest]
        // Because s1 is the destination in the IPv6 header.
        // Segments Left should be 3.

        assert_eq!(result[3], 3); // Segments Left

        // Header is 8 bytes.
        // Address 1 at offset 8. Should be s2.
        let addr1_bytes = &result[8..24];
        let addr1 = Ipv6Addr::from(u128::from_be_bytes(addr1_bytes.try_into().unwrap()));

        // Address 2 at offset 24. Should be s3.
        let addr2_bytes = &result[24..40];
        let addr2 = Ipv6Addr::from(u128::from_be_bytes(addr2_bytes.try_into().unwrap()));

        // Address 3 at offset 40. Should be final_dest.
        let addr3_bytes = &result[40..56];
        let addr3 = Ipv6Addr::from(u128::from_be_bytes(addr3_bytes.try_into().unwrap()));

        assert_eq!(addr1, s2, "First address in RH should be S2");
        assert_eq!(addr2, s3, "Second address in RH should be S3");
        assert_eq!(
            addr3, final_dest,
            "Third address in RH should be Final Dest"
        );
    }
}
