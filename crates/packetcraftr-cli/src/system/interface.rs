// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::error::Kind;
use packetcraftr_netio as net;
use packetcraftr_netio::capture::Provider as _;
use packetcraftr_netio::route::Provider as _;

use crate::command_options::InterfaceSelector;
use crate::errors::CliError;

pub(crate) fn interfaces(
    invocation: &crate::invocation::Invocation,
    selector: Option<&InterfaceSelector>,
) -> Result<Vec<net::interface::Info>, CliError> {
    select_interfaces(invocation, &net::interface::SystemProvider, selector)
}

pub(crate) fn resolve_unique(
    invocation: &crate::invocation::Invocation,
    selectors: &[crate::command_options::Selector<InterfaceSelector>],
    max_selectors: usize,
) -> Result<Vec<net::interface::Id>, CliError> {
    resolve_unique_with(
        invocation,
        &net::interface::SystemProvider,
        selectors,
        max_selectors,
    )
}

fn resolve_unique_with<I: net::interface::Provider>(
    invocation: &crate::invocation::Invocation,
    provider: &I,
    selectors: &[crate::command_options::Selector<InterfaceSelector>],
    max_selectors: usize,
) -> Result<Vec<net::interface::Id>, CliError> {
    if selectors.len() > max_selectors {
        return Err(CliError::new(
            Kind::Usage,
            format!(
                "capture accepts at most {max_selectors} interface selectors before deduplication"
            ),
        ));
    }
    if selectors.is_empty() {
        return Ok(Vec::new());
    }
    let selectors = selectors
        .iter()
        .map(crate::command_options::Selector::get)
        .collect::<Result<Vec<_>, _>>()?;
    let snapshot = provider
        .interfaces(&invocation.passive_lookup())
        .map_err(CliError::classified)?;
    let mut seen = std::collections::HashSet::with_capacity(selectors.len());
    selectors
        .into_iter()
        .filter_map(|selector| {
            let wanted = packetcraftr::route::Interface::from(selector.clone());
            match snapshot
                .iter()
                .find(|interface| wanted.matches(&interface.id))
            {
                Some(interface) => seen
                    .insert(interface.id.index)
                    .then(|| Ok(interface.id.clone())),
                None => Some(Err(no_match(&selector))),
            }
        })
        .collect()
}

pub(crate) fn timestamp_types(
    invocation: &crate::invocation::Invocation,
    interface: &net::interface::Id,
) -> Result<Vec<net::capture::TimestampType>, CliError> {
    net::capture::SystemProvider
        .timestamp_types(interface, &invocation.passive_lookup())
        .map_err(CliError::classified)
}

pub(crate) fn interface_routes(
    invocation: &crate::invocation::Invocation,
    interfaces: Vec<net::interface::Info>,
) -> Result<Vec<net::route::Decision>, CliError> {
    net::route::SystemProvider
        .lookup_interfaces(interfaces, &invocation.passive_lookup())
        .map_err(CliError::classified)
}

fn select_interfaces<I: net::interface::Provider>(
    invocation: &crate::invocation::Invocation,
    provider: &I,
    selector: Option<&InterfaceSelector>,
) -> Result<Vec<net::interface::Info>, CliError> {
    let interfaces = provider
        .interfaces(&invocation.passive_lookup())
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
        return Err(no_match(selector));
    }
    Ok(selected)
}

fn no_match(selector: &InterfaceSelector) -> CliError {
    CliError::classified(net::Error::Device {
        interface: selector.to_string(),
        message: "no interface matches the requested name or index".to_owned(),
        source: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetcraftr_core::{
        budget::{Cancellation, Deadline},
        frame::LinkType,
    };
    use std::sync::atomic::{AtomicBool, Ordering};

    struct ChangingSnapshot(AtomicBool);

    impl net::interface::Provider for ChangingSnapshot {
        fn interfaces(
            &self,
            _: &Deadline,
        ) -> Result<Vec<net::interface::Info>, net::interface::Error> {
            let index = if self.0.swap(true, Ordering::Relaxed) {
                2
            } else {
                1
            };
            Ok(vec![net::interface::Info {
                id: net::interface::Id {
                    index,
                    name: "controlled".into(),
                },
                description: None,
                addresses: Vec::new(),
                mac_address: None,
                flags: Default::default(),
                mtu: None,
                capability: net::link::Capability::Layer2,
                link_type: LinkType::ETHERNET,
            }])
        }
    }

    #[test]
    fn repeated_selectors_resolve_to_one_identity_when_interfaces_change() {
        use crate::invocation::StreamEncoder;
        use crate::output::contract::{Command, Format};

        let invocation = crate::invocation::Invocation::new(
            Format::Text,
            StreamEncoder::new(Command::Capture, std::io::sink()),
            None,
            Cancellation::default(),
            None,
        );
        let provider = ChangingSnapshot(AtomicBool::new(false));
        let by_name = crate::command_options::interface_selector("controlled").unwrap();
        let by_index = crate::command_options::interface_selector("1").unwrap();
        let selected =
            resolve_unique_with(&invocation, &provider, &[by_name, by_index], 2).unwrap();
        assert_eq!(
            selected,
            vec![net::interface::Id {
                index: 1,
                name: "controlled".into()
            }]
        );
    }
}
