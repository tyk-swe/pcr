// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::error::Kind;
use packetcraftr_netio as net;
use packetcraftr_netio::capture::Provider as _;
use packetcraftr_netio::route::Provider as _;

use crate::command_options::InterfaceSelector;
use crate::errors::CliError;

pub(crate) fn interfaces(
    selector: Option<&InterfaceSelector>,
) -> Result<Vec<net::interface::Info>, CliError> {
    select_interfaces(&net::interface::SystemProvider, selector)
}

pub(crate) fn resolve(selector: InterfaceSelector) -> Result<net::interface::Id, CliError> {
    select_interfaces(&net::interface::SystemProvider, Some(&selector))?
        .into_iter()
        .next()
        .map(|interface| interface.id)
        .ok_or_else(|| CliError::new(Kind::Internal, "interface selection returned no match"))
}

pub(crate) fn timestamp_types(
    interface: &net::interface::Id,
) -> Result<Vec<net::capture::TimestampType>, CliError> {
    net::capture::SystemProvider
        .timestamp_types(interface, &crate::invocation::passive_lookup())
        .map_err(CliError::classified)
}

pub(crate) fn interface_route(
    interface: &net::interface::Id,
) -> Result<Option<net::route::Decision>, CliError> {
    net::route::SystemProvider
        .lookup_interface(interface, &crate::invocation::passive_lookup())
        .map_err(CliError::classified)
}

fn select_interfaces<I: net::interface::Provider>(
    provider: &I,
    selector: Option<&InterfaceSelector>,
) -> Result<Vec<net::interface::Info>, CliError> {
    let interfaces = provider
        .interfaces(&crate::invocation::passive_lookup())
        .map_err(CliError::classified)?;
    let Some(selector) = selector else {
        return Ok(interfaces);
    };
    let wanted = packetcraftr::route::Interface::from(selector.clone());
    let selected = interfaces
        .into_iter()
        .filter(|interface| wanted.matches(&interface.id))
        .collect::<Vec<_>>();
    if selected.is_empty() {
        return Err(CliError::classified(net::Error::Device {
            interface: selector.to_string(),
            message: "no interface matches the requested name or index".to_owned(),
            source: None,
        }));
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use packetcraftr_netio as net;

    use super::{InterfaceSelector, select_interfaces};

    struct FixtureProvider;

    impl net::interface::Provider for FixtureProvider {
        fn interfaces(
            &self,
            _deadline: &packetcraftr_core::budget::Deadline,
        ) -> Result<Vec<net::interface::Info>, net::interface::Error> {
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
        let selector =
            selector.map(|selector| InterfaceSelector::parse(selector).expect("fixture selector"));
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
        let selector = InterfaceSelector::parse("fixture9").expect("fixture selector");
        let error = select_interfaces(&FixtureProvider, Some(&selector))
            .expect_err("unknown names must fail");
        assert_eq!(error.exit_code(), 5);
        assert!(error.message.contains("no interface matches"));
    }
}
