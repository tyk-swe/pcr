// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv6Addr;

use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};

use crate::domain::spec::{Ipv6ExtHeader, MAX_ROUTING_SEGMENTS};
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
    use crate::domain::spec::Ipv6ExtHeader;

    fn addr(value: u16) -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, value)
    }

    #[test]
    fn split_fragment_extension_headers_moves_trailing_destination_options_after_fragment() {
        let headers = vec![
            Ipv6ExtHeader::HopByHop { options: vec![] },
            Ipv6ExtHeader::DestinationOptions { options: vec![1] },
            Ipv6ExtHeader::DestinationOptions { options: vec![2] },
        ];

        let (before, after) = split_fragment_extension_headers(&headers);

        assert_eq!(before, &headers[..1]);
        assert_eq!(after, &headers[1..]);
    }

    #[test]
    fn split_fragment_extension_headers_keeps_non_trailing_destination_options_before_fragment() {
        let headers = vec![
            Ipv6ExtHeader::DestinationOptions { options: vec![1] },
            Ipv6ExtHeader::Routing {
                routing_type: 0,
                segments: vec![addr(1)],
                data: None,
            },
        ];

        let (before, after) = split_fragment_extension_headers(&headers);

        assert_eq!(before, headers.as_slice());
        assert!(after.is_empty());
    }

    #[test]
    fn get_header_protocol_maps_supported_extension_headers() {
        assert_eq!(
            get_header_protocol(&Ipv6ExtHeader::HopByHop { options: vec![] }),
            IpNextHeaderProtocols::Hopopt
        );
        assert_eq!(
            get_header_protocol(&Ipv6ExtHeader::DestinationOptions { options: vec![] }),
            IpNextHeaderProtocols::Ipv6Opts
        );
        assert_eq!(
            get_header_protocol(&Ipv6ExtHeader::Routing {
                routing_type: 0,
                segments: vec![addr(1)],
                data: None,
            }),
            IpNextHeaderProtocols::Ipv6Route
        );
    }

    #[test]
    fn encode_extension_headers_returns_terminal_for_empty_chain() {
        let (bytes, next) =
            encode_extension_headers(&[], IpNextHeaderProtocols::Udp, addr(10)).unwrap();

        assert!(bytes.is_empty());
        assert_eq!(next, IpNextHeaderProtocols::Udp);
    }

    #[test]
    fn options_header_uses_minimum_eight_byte_encoding() {
        let headers = [Ipv6ExtHeader::HopByHop { options: vec![] }];

        let (bytes, next) =
            encode_extension_headers(&headers, IpNextHeaderProtocols::Tcp, addr(10)).unwrap();

        assert_eq!(next, IpNextHeaderProtocols::Hopopt);
        assert_eq!(bytes.len(), 8);
        assert_eq!(bytes[0], IpNextHeaderProtocols::Tcp.0);
        assert_eq!(bytes[1], 0);
        assert_eq!(&bytes[2..], &[0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn options_header_copies_options_and_zero_pads_to_eight_bytes() {
        let headers = [Ipv6ExtHeader::DestinationOptions {
            options: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11],
        }];

        let (bytes, _) =
            encode_extension_headers(&headers, IpNextHeaderProtocols::Udp, addr(10)).unwrap();

        assert_eq!(bytes.len(), 16);
        assert_eq!(&bytes[2..9], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11]);
        assert!(bytes[9..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn routing_initial_destination_uses_first_routing_segment() {
        let headers = [Ipv6ExtHeader::Routing {
            routing_type: 0,
            segments: vec![addr(1), addr(2)],
            data: None,
        }];

        assert_eq!(routing_initial_destination(&headers, addr(99)), addr(1));
    }

    #[test]
    fn routing_initial_destination_uses_default_without_routing_header() {
        let headers = [Ipv6ExtHeader::HopByHop { options: vec![] }];

        assert_eq!(routing_initial_destination(&headers, addr(99)), addr(99));
    }

    #[test]
    fn routing_header_omits_extra_final_destination_when_last_segment_is_final() {
        let headers = [Ipv6ExtHeader::Routing {
            routing_type: 4,
            segments: vec![addr(1), addr(2)],
            data: Some(0x11223344),
        }];

        let (bytes, next) =
            encode_extension_headers(&headers, IpNextHeaderProtocols::Tcp, addr(2)).unwrap();

        assert_eq!(next, IpNextHeaderProtocols::Ipv6Route);
        assert_eq!(bytes.len(), 24);
        assert_eq!(bytes[0], IpNextHeaderProtocols::Tcp.0);
        assert_eq!(bytes[2], 4);
        assert_eq!(bytes[3], 1);
        assert_eq!(&bytes[4..8], &0x11223344u32.to_be_bytes());
        assert_eq!(&bytes[8..24], &addr(2).octets());
    }

    #[test]
    fn routing_header_appends_final_destination_when_last_segment_differs() {
        let headers = [Ipv6ExtHeader::Routing {
            routing_type: 4,
            segments: vec![addr(1), addr(2)],
            data: None,
        }];

        let (bytes, _) =
            encode_extension_headers(&headers, IpNextHeaderProtocols::Tcp, addr(3)).unwrap();

        assert_eq!(bytes.len(), 40);
        assert_eq!(bytes[3], 2);
        assert_eq!(&bytes[8..24], &addr(2).octets());
        assert_eq!(&bytes[24..40], &addr(3).octets());
    }

    #[test]
    fn routing_header_rejects_missing_segments() {
        let err = measure_extension_headers(
            &[Ipv6ExtHeader::Routing {
                routing_type: 0,
                segments: vec![],
                data: None,
            }],
            addr(1),
        )
        .unwrap_err();

        assert!(matches!(err, Ipv6Error::RoutingMissingSegment));
    }

    #[test]
    fn routing_header_rejects_too_many_segments() {
        let err = measure_extension_headers(
            &[Ipv6ExtHeader::Routing {
                routing_type: 0,
                segments: (0..=MAX_ROUTING_SEGMENTS)
                    .map(|idx| addr(idx as u16))
                    .collect(),
                data: None,
            }],
            addr(1),
        )
        .unwrap_err();

        assert!(matches!(
            err,
            Ipv6Error::RoutingTooManySegments {
                max: MAX_ROUTING_SEGMENTS,
                count
            } if count == MAX_ROUTING_SEGMENTS + 1
        ));
    }

    #[test]
    fn options_header_rejects_payloads_that_exceed_limit_after_padding() {
        let err = measure_extension_headers(
            &[Ipv6ExtHeader::HopByHop {
                options: vec![0; 2047],
            }],
            addr(1),
        )
        .unwrap_err();

        assert!(matches!(err, Ipv6Error::OptionsTooLong));
    }
}
