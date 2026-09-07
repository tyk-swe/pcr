// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv4Addr;

use super::error::Error;

#[derive(Default)]
pub(super) struct ParsedIpv4SourceRoutes {
    pub(super) declared: Vec<Ipv4Addr>,
    pub(super) remaining: Vec<Ipv4Addr>,
}

impl ParsedIpv4SourceRoutes {
    pub(super) fn final_destination(&self, header_destination: Ipv4Addr) -> Ipv4Addr {
        self.remaining.last().copied().unwrap_or(header_destination)
    }
}

pub(crate) fn ipv4_source_route_destination(
    header_destination: Ipv4Addr,
    options: &[u8],
) -> Result<Ipv4Addr, Error> {
    Ok(parse_ipv4_source_routes(options)?.final_destination(header_destination))
}

pub(super) fn parse_ipv4_source_routes(options: &[u8]) -> Result<ParsedIpv4SourceRoutes, Error> {
    if options.len() > 40 {
        return Err(Error::Ipv4OptionsTooLong);
    }
    let mut routes = ParsedIpv4SourceRoutes::default();
    let mut cursor = 0usize;
    while cursor < options.len() {
        let Some(&kind) = options.get(cursor) else {
            break;
        };
        match kind {
            0 => break,
            1 => cursor = cursor.saturating_add(1),
            option => {
                let length = options
                    .get(cursor.saturating_add(1))
                    .copied()
                    .map(usize::from)
                    .ok_or(Error::Ipv4OptionMissingLength)?;
                if length < 2 {
                    return Err(Error::Ipv4OptionLength { option, length });
                }
                let end = cursor
                    .checked_add(length)
                    .filter(|end| *end <= options.len())
                    .ok_or(Error::Ipv4OptionTruncated { option })?;
                if matches!(option, 131 | 137) {
                    if length < 3 || !length.saturating_sub(3).is_multiple_of(4) {
                        return Err(Error::Ipv4SourceRouteLength { option, length });
                    }
                    // cursor + 2 < end <= options.len() because length >= 3
                    let pointer = usize::from(options[cursor + 2]);
                    if pointer < 4
                        || pointer > length.saturating_add(1)
                        || !pointer.saturating_sub(4).is_multiple_of(4)
                    {
                        return Err(Error::Ipv4SourceRoutePointer { option, pointer });
                    }
                    // The validated option length covers whole IPv4 addresses.
                    for address in options[cursor + 3..end].as_chunks::<4>().0 {
                        routes.declared.push(Ipv4Addr::from(*address));
                    }
                    // The validated pointer selects an address boundary within the option.
                    for address in options[cursor + pointer - 1..end].as_chunks::<4>().0 {
                        routes.remaining.push(Ipv4Addr::from(*address));
                    }
                }
                cursor = end;
            }
        }
    }
    Ok(routes)
}
