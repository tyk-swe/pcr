// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::output;
use crate::rendering::optional_display;

/// One text row per route.
pub(super) fn route_line(route: &output::network::Decision) -> String {
    format!(
        "{} (index {}): source={} mtu={} capability={} link_type={}",
        route.interface.name,
        route.interface.index,
        optional_display(route.selected_source.or(route.preferred_source)),
        route.mtu,
        route.capability,
        route.link_type
    )
}
