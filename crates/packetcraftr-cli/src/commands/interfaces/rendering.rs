// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::output;
use crate::rendering::optional_display;

/// One text row per interface, spelling every field the JSON document carries.
pub(super) fn interface_line(interface: &output::network::Interface) -> String {
    let timestamp_types = interface.timestamp_types.as_deref().map(|types| {
        if types.is_empty() {
            return "none".to_owned();
        }
        types
            .iter()
            .map(|timestamp_type| {
                let name = timestamp_type.name.as_deref().unwrap_or("<unnamed>");
                // Types outside the representable clock domains cannot be
                // selected for capture.
                if timestamp_type.source.is_some() {
                    name.to_owned()
                } else {
                    format!("{name}(unselectable)")
                }
            })
            .collect::<Vec<_>>()
            .join(",")
    });
    let types_field = timestamp_types
        .map(|types| format!(" timestamp_types={types}"))
        .unwrap_or_default();
    format!(
        "{} (index {}): {} mtu={} capability={} link_type={} mac={} flags={} description={}{}",
        interface.name,
        interface.index,
        interface.addresses.join(", "),
        optional_display(interface.mtu),
        interface.capability,
        interface.link_type,
        optional_display(interface.mac.as_deref()),
        interface_flags(&interface.flags),
        optional_display(interface.description.as_deref()),
        types_field,
    )
}

/// The set flags as one comma-separated word, so text stays greppable while
/// JSON keeps the structured object.
pub(super) fn interface_flags(flags: &crate::output::network::Flags) -> String {
    let mut set = Vec::new();
    if flags.up {
        set.push("up");
    }
    if flags.broadcast {
        set.push("broadcast");
    }
    if flags.loopback {
        set.push("loopback");
    }
    if flags.point_to_point {
        set.push("point_to_point");
    }
    if flags.multicast {
        set.push("multicast");
    }
    if set.is_empty() {
        return "none".to_owned();
    }
    set.join(",")
}
