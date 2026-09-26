// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::output::contract::AggregateFormat;

use packetcraftr_netio as net;

use crate::output;

use packetcraftr_netio::capture::Provider as _;

use crate::errors::CliError;
use crate::rendering::optional_display;
use crate::system::{InterfaceSelector, select_interfaces};

pub(super) const AFTER_LONG_HELP: &str = r"Examples:
  packetcraftr interfaces
  packetcraftr interfaces --interface lo
  packetcraftr --output json interfaces";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Only list the interface with this name or numeric index.
    #[arg(long, value_name = "NAME_OR_INDEX")]
    pub(crate) interface: Option<String>,
    /// List the packet timestamp types the capture backend advertises for each
    /// interface; types without a source are not selectable for capture.
    #[arg(long)]
    pub(crate) timestamp_types: bool,
}

impl super::Spec for Args {
    type Format = crate::output::contract::AggregateFormat;
    const CANCELLATION: bool = false;

    fn run(
        self,
        format: Self::Format,
        _stream: &crate::rendering::StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        run(self, format).map(|()| super::CommandExit::SUCCESS)
    }
}

pub(super) fn run(arguments: Args, format: AggregateFormat) -> Result<(), CliError> {
    let selector = InterfaceSelector::parse_optional(arguments.interface.as_deref())?;
    let interfaces = select_interfaces(&net::interface::SystemProvider, selector.as_ref())?;
    let mut result = output::interfaces::Report::new(interfaces);
    if arguments.timestamp_types {
        let provider = net::capture::SystemProvider;
        for interface in &mut result.interfaces {
            let id = net::interface::Id {
                name: interface.name.clone(),
                index: interface.index,
            };
            interface.timestamp_types = Some(
                provider
                    .timestamp_types(&id)
                    .map_err(CliError::classified)?,
            );
        }
    }
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
fn interface_flags(flags: &packetcraftr_netio::interface::Flags) -> String {
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
                    link_type: packetcraftr_core::frame::LinkType::ETHERNET,
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
                    link_type: packetcraftr_core::frame::LinkType::ETHERNET,
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
}
