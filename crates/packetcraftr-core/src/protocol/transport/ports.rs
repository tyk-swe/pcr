// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::registry::Discriminator;

/// Offers each nonzero port once, in preference order, followed by the zero/raw
/// fallback. A zero port never shadows that fallback.
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
