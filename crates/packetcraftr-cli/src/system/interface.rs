// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::num::NonZeroU32;

use packetcraftr::{core::error::Kind, netio as net};

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
            return Err(CliError::new(Kind::Cli, "--interface cannot be empty"));
        }
        if !selector.bytes().all(|byte| byte.is_ascii_digit()) {
            return Ok(Self::Name(selector.to_owned()));
        }
        let index = selector.parse::<u32>().map_err(|_| {
            CliError::new(
                Kind::Cli,
                format!("--interface index must be within 1..={}", u32::MAX),
            )
        })?;
        NonZeroU32::new(index)
            .map(Self::Index)
            .ok_or_else(|| CliError::new(Kind::Cli, "--interface index must be non-zero"))
    }

    pub(crate) fn parse_optional(selector: Option<&str>) -> Result<Option<Self>, CliError> {
        selector.map(Self::parse).transpose()
    }

    /// Whether a discovered interface is the one this selector names: an
    /// index selector ignores the name, and a name selector ignores the index.
    pub(crate) fn matches(&self, id: &net::interface::Id) -> bool {
        match self {
            Self::Name(name) => id.name == *name,
            Self::Index(index) => id.index == index.get(),
        }
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

impl fmt::Display for InterfaceSelector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(name) => formatter.write_str(name),
            Self::Index(index) => write!(formatter, "{index}"),
        }
    }
}

/// Enumerates interfaces, keeping only the ones `selector` names. A selector
/// nothing matches fails with the one "no interface matches" error every
/// command reports.
pub(crate) fn select_interfaces<I: net::interface::Provider>(
    provider: &I,
    selector: Option<&InterfaceSelector>,
) -> Result<Vec<net::interface::Info>, CliError> {
    let interfaces = provider.interfaces().map_err(CliError::classified)?;
    let Some(selector) = selector else {
        return Ok(interfaces);
    };
    let selected = interfaces
        .into_iter()
        .filter(|interface| selector.matches(&interface.id))
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

pub(crate) fn resolve<I: net::interface::Provider>(
    selector: InterfaceSelector,
    provider: &I,
) -> Result<net::interface::Id, CliError> {
    select_interfaces(provider, Some(&selector))?
        .into_iter()
        .next()
        .map(|interface| interface.id)
        .ok_or_else(|| CliError::new(Kind::Internal, "interface selection returned no match"))
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use packetcraftr::netio as net;

    use super::InterfaceSelector;

    #[test]
    fn interface_selectors_distinguish_names_and_numeric_indexes() {
        assert_eq!(InterfaceSelector::parse_optional(None).unwrap(), None);
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
    fn selectors_match_only_the_half_they_name_and_display_verbatim() {
        let id = net::interface::Id {
            name: "eth0".to_owned(),
            index: 7,
        };
        let by_index = InterfaceSelector::parse("7").unwrap();
        let by_name = InterfaceSelector::parse("eth0").unwrap();
        assert!(by_index.matches(&id));
        assert!(by_name.matches(&id));
        assert!(!InterfaceSelector::parse("8").unwrap().matches(&id));
        assert!(!InterfaceSelector::parse("eth1").unwrap().matches(&id));
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
}
