// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use self::arguments::Args;
use crate::output::contract::AggregateFormat;

use packetcraftr_netio as net;

use crate::output;

use packetcraftr_netio::capture::Provider as _;

use crate::errors::CliError;
use crate::system::{InterfaceSelector, select_interfaces};

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
        rendering::interface_line,
    )
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
