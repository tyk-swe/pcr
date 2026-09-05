// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::output::contract::Format;

use packetcraftr::{netio as net, output};

use crate::errors::CliError;
use crate::rendering::optional_display;
use crate::system::{InterfaceSelector, select_interfaces};

pub(super) const AFTER_LONG_HELP: &str = r#"Examples:
  packetcraftr interfaces
  packetcraftr interfaces --interface lo
  packetcraftr --output json interfaces"#;

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Only list the interface with this name or numeric index.
    #[arg(long, value_name = "NAME_OR_INDEX")]
    pub(crate) interface: Option<String>,
}

pub(super) fn run(arguments: Args, format: Format) -> Result<(), CliError> {
    let selector = InterfaceSelector::parse_optional(arguments.interface.as_deref())?;
    let interfaces = select_interfaces(&net::interface::SystemProvider, selector.as_ref())?;
    let result = output::interfaces::Report::new(interfaces);
    super::render_aggregate_rows(
        output::contract::Command::Interfaces,
        format,
        &result,
        &result.interfaces,
        interface_line,
    )
}

/// One text row per interface, spelling every field the JSON document carries.
fn interface_line(interface: &output::network::Interface) -> String {
    format!(
        "{} (index {}): {} mtu={} capability={} link_type={} mac={} flags={} description={}",
        interface.name,
        interface.index,
        interface.addresses.join(", "),
        optional_display(interface.mtu),
        interface.capability,
        interface.link_type,
        optional_display(interface.mac.as_deref()),
        interface_flags(&interface.flags),
        optional_display(interface.description.as_deref()),
    )
}

/// The set flags as one comma-separated word, so text stays greppable while
/// JSON keeps the structured object.
fn interface_flags(flags: &output::network::Flags) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    struct FixtureProvider;

    impl net::interface::Provider for FixtureProvider {
        fn interfaces(&self) -> Result<Vec<net::interface::Info>, net::Error> {
            Ok(vec![
                net::interface::Info {
                    id: net::interface::Id {
                        name: "fixture0".to_owned(),
                        index: 9,
                    },
                    description: Some("first fixture".to_owned()),
                    mac_address: None,
                    addresses: Vec::new(),
                    flags: net::interface::Flags {
                        up: true,
                        loopback: true,
                        ..net::interface::Flags::default()
                    },
                    mtu: Some(1_500),
                    capability: net::link::Capability::Layer2AndLayer3,
                    link_type: packetcraftr::core::frame::LinkType::ETHERNET,
                },
                net::interface::Info {
                    id: net::interface::Id {
                        name: "fixture1".to_owned(),
                        index: 10,
                    },
                    description: None,
                    mac_address: None,
                    addresses: Vec::new(),
                    flags: net::interface::Flags::default(),
                    mtu: None,
                    capability: net::link::Capability::Layer2AndLayer3,
                    link_type: packetcraftr::core::frame::LinkType::ETHERNET,
                },
            ])
        }
    }

    fn selected(selector: Option<&str>) -> Vec<String> {
        let selector = InterfaceSelector::parse_optional(selector).expect("fixture selector");
        select_interfaces(&FixtureProvider, selector.as_ref())
            .expect("fixture enumeration succeeds")
            .into_iter()
            .map(|interface| interface.id.name)
            .collect()
    }

    #[test]
    fn an_absent_selector_lists_every_interface() {
        assert_eq!(selected(None), ["fixture0", "fixture1"]);
    }

    #[test]
    fn a_name_or_index_selector_keeps_only_its_interface() {
        assert_eq!(selected(Some("fixture1")), ["fixture1"]);
        assert_eq!(selected(Some("9")), ["fixture0"]);
    }

    #[test]
    fn an_unknown_selector_fails_before_rendering() {
        let selector =
            InterfaceSelector::parse_optional(Some("fixture9")).expect("fixture selector");
        let error = select_interfaces(&FixtureProvider, selector.as_ref())
            .expect_err("unknown names must fail");
        assert_eq!(error.exit_code(), 5);
        assert!(error.message.contains("no interface matches"));
    }

    #[test]
    fn the_text_row_spells_every_json_field() {
        let interfaces = select_interfaces(&FixtureProvider, None).expect("fixture enumeration");
        let result = output::interfaces::Report::new(interfaces);
        let mut lines = result.interfaces.iter().map(interface_line);
        let line = lines.next().expect("two fixture interfaces");
        assert!(line.starts_with("fixture0 (index 9): "), "{line}");
        for expected in [
            "mtu=1500",
            "capability=layer2_and3",
            "link_type=1",
            "mac=none",
            "flags=up,loopback",
            "description=first fixture",
        ] {
            assert!(line.contains(expected), "missing {expected:?} in {line:?}");
        }
        let bare = lines.next().expect("two fixture interfaces");
        assert!(bare.contains("mac=none"), "{bare}");
        assert!(bare.contains("flags=none"), "{bare}");
        assert!(bare.contains("description=none"), "{bare}");
    }
}
