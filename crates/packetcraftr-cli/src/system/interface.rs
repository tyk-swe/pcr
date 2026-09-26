// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::num::NonZeroU32;

use packetcraftr_core::error::Kind;
use packetcraftr_netio as net;
use packetcraftr_netio::capture::Provider as _;
use packetcraftr_netio::route::Provider as _;

use crate::errors::CliError;

/// A validated `--interface` value. Decimal selectors are always indexes:
/// zero and values outside the public `u32` index domain never fall back to
/// interface-name lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InterfaceSelector {
    Name(String),
    Index(NonZeroU32),
}

impl InterfaceSelector {
    /// Validates a selector without consulting a platform provider.
    pub(crate) fn parse(selector: &str) -> Result<Self, CliError> {
        if selector.is_empty() {
            return Err(CliError::new(Kind::Usage, "--interface cannot be empty"));
        }
        if !selector.bytes().all(|byte| byte.is_ascii_digit()) {
            return Ok(Self::Name(selector.to_owned()));
        }
        let index = selector.parse::<u32>().map_err(|_| {
            CliError::new(
                Kind::Usage,
                format!("--interface index must be within 1..={}", u32::MAX),
            )
        })?;
        NonZeroU32::new(index)
            .map(Self::Index)
            .ok_or_else(|| CliError::new(Kind::Usage, "--interface index must be non-zero"))
    }

    /// The identity this selector describes before any provider confirms it:
    /// only the selected half is filled in.
    pub(crate) fn into_id(self) -> net::interface::Id {
        match self {
            Self::Name(name) => net::interface::Id { name, index: 0 },
            Self::Index(index) => net::interface::Id {
                name: String::new(),
                index: index.get(),
            },
        }
    }
}

/// The library selector the client resolves after admission.
impl From<InterfaceSelector> for packetcraftr::route::Interface {
    fn from(selector: InterfaceSelector) -> Self {
        match selector {
            InterfaceSelector::Name(name) => Self::Name(name),
            InterfaceSelector::Index(index) => Self::Index(index),
        }
    }
}

impl fmt::Display for InterfaceSelector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(name) => formatter.write_str(name),
            Self::Index(index) => write!(formatter, "{index}"),
        }
    }
}

/// The system's interfaces, keeping only the ones `selector` names.
pub(crate) fn interfaces(
    selector: Option<&InterfaceSelector>,
) -> Result<Vec<net::interface::Info>, CliError> {
    select_interfaces(&net::interface::SystemProvider, selector)
}

/// The one interface `selector` names on this system.
pub(crate) fn resolve(selector: InterfaceSelector) -> Result<net::interface::Id, CliError> {
    select_interfaces(&net::interface::SystemProvider, Some(&selector))?
        .into_iter()
        .next()
        .map(|interface| interface.id)
        .ok_or_else(|| CliError::new(Kind::Internal, "interface selection returned no match"))
}

/// The packet timestamp types the system capture backend advertises for
/// `interface`.
pub(crate) fn timestamp_types(
    interface: &net::interface::Id,
) -> Result<Vec<net::capture::TimestampType>, CliError> {
    net::capture::SystemProvider
        .timestamp_types(interface, &crate::invocation::passive_lookup())
        .map_err(CliError::classified)
}

/// The system route that leaves through `interface`, if it has one.
pub(crate) fn interface_route(
    interface: &net::interface::Id,
) -> Result<Option<net::route::Decision>, CliError> {
    net::route::SystemProvider
        .lookup_interface(interface, &crate::invocation::passive_lookup())
        .map_err(CliError::classified)
}

/// Enumerates interfaces, keeping only the ones `selector` names. A selector
/// nothing matches fails with the one "no interface matches" error every
/// command reports.
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
    use std::num::NonZeroU32;

    use packetcraftr_netio as net;

    use super::{InterfaceSelector, select_interfaces};

    #[test]
    fn interface_selectors_distinguish_names_and_numeric_indexes() {
        assert_eq!(
            InterfaceSelector::parse("ethernet0").unwrap(),
            InterfaceSelector::Name("ethernet0".to_owned())
        );
        assert_eq!(
            InterfaceSelector::parse("7").unwrap(),
            InterfaceSelector::Index(NonZeroU32::new(7).unwrap())
        );

        for (selector, expected) in [
            ("", "--interface cannot be empty"),
            ("0", "--interface index must be non-zero"),
            (
                "4294967296",
                "--interface index must be within 1..=4294967295",
            ),
        ] {
            let error = InterfaceSelector::parse(selector)
                .expect_err("invalid selectors must fail before provider access");
            assert_eq!(error.exit_code(), 2, "selector={selector:?}");
            assert_eq!(error.message, expected, "selector={selector:?}");
        }
    }

    #[test]
    fn selectors_display_verbatim() {
        let by_index = InterfaceSelector::parse("7").unwrap();
        let by_name = InterfaceSelector::parse("eth0").unwrap();
        assert_eq!(by_index.to_string(), "7");
        assert_eq!(by_name.to_string(), "eth0");
        assert_eq!(
            by_index.into_id(),
            net::interface::Id {
                name: String::new(),
                index: 7
            }
        );
        assert_eq!(
            by_name.into_id(),
            net::interface::Id {
                name: "eth0".to_owned(),
                index: 0
            }
        );
    }

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
