// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Child selection shared by the port-based transports.

use crate::registry::Discriminator;

/// Turns an ordered port pair into the child discriminators a transport
/// offers, in dissection order.
///
/// `ports` is the pair the transport prefers, most preferred first. Each
/// non-zero port appears once, in that order, and the zero fallback that
/// reaches `raw` is always last: a zero port never shadows it.
pub(super) fn child_discriminators(ports: [u16; 2]) -> Vec<Discriminator> {
    let mut next = Vec::with_capacity(3);
    for port in ports {
        let discriminator = Discriminator(u64::from(port));
        if port != 0 && !next.contains(&discriminator) {
            next.push(discriminator);
        }
    }
    next.push(Discriminator(0));
    next
}
