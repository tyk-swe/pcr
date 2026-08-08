// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv4Addr;

use super::error::SemanticError;

#[derive(Default)]
pub(super) struct ParsedIpv4SourceRoutes {
    pub(super) declared: Vec<Ipv4Addr>,
    pub(super) remaining: Vec<Ipv4Addr>,
}

pub(super) fn parse_ipv4_source_routes(
    options: &[u8],
) -> Result<ParsedIpv4SourceRoutes, SemanticError> {
    if options.len() > 40 {
        return Err(SemanticError::new(
            "IPv4 option bytes exceed the 40-byte header limit",
        ));
    }
    let mut routes = ParsedIpv4SourceRoutes::default();
    let mut cursor = 0usize;
    while cursor < options.len() {
        match options[cursor] {
            0 => break,
            1 => cursor += 1,
            option => {
                let length = options
                    .get(cursor + 1)
                    .copied()
                    .map(usize::from)
                    .ok_or_else(|| SemanticError::new("IPv4 option is missing its length byte"))?;
                if length < 2 {
                    return Err(SemanticError::new(format!(
                        "IPv4 option {option} has invalid length {length}"
                    )));
                }
                let end = cursor
                    .checked_add(length)
                    .filter(|end| *end <= options.len())
                    .ok_or_else(|| {
                        SemanticError::new(format!("IPv4 option {option} is truncated"))
                    })?;
                if matches!(option, 131 | 137) {
                    if length < 3 || !(length - 3).is_multiple_of(4) {
                        return Err(SemanticError::new(format!(
                            "IPv4 source-route option {option} has invalid length {length}"
                        )));
                    }
                    let pointer = usize::from(options[cursor + 2]);
                    if pointer < 4 || pointer > length + 1 || !(pointer - 4).is_multiple_of(4) {
                        return Err(SemanticError::new(format!(
                            "IPv4 source-route option {option} has invalid pointer {pointer}"
                        )));
                    }
                    for address in options[cursor + 3..end].chunks_exact(4) {
                        routes.declared.push(Ipv4Addr::new(
                            address[0], address[1], address[2], address[3],
                        ));
                    }
                    for address in options[cursor + pointer - 1..end].chunks_exact(4) {
                        routes.remaining.push(Ipv4Addr::new(
                            address[0], address[1], address[2], address[3],
                        ));
                    }
                }
                cursor = end;
            }
        }
    }
    Ok(routes)
}
