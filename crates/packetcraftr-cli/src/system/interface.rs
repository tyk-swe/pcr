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

pub(crate) fn resolve(
    invocation: &crate::invocation::Invocation,
    selector: InterfaceSelector,
) -> Result<net::interface::Id, CliError> {
    select_interfaces(invocation, &net::interface::SystemProvider, Some(&selector))?
        .into_iter()
        .next()
        .map(|interface| interface.id)
        .ok_or_else(|| CliError::new(Kind::Internal, "interface selection returned no match"))
}

pub(crate) fn resolve_unique(
    invocation: &crate::invocation::Invocation,
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
    let mut seen = std::collections::HashSet::with_capacity(selectors.len());
    let mut interfaces = Vec::with_capacity(selectors.len());
    for selector in selectors {
        let interface = resolve(invocation, selector.get()?)?;
        if seen.insert(interface.index) {
            interfaces.push(interface);
        }
    }
    Ok(interfaces)
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
        return Err(CliError::classified(net::Error::Device {
            interface: selector.to_string(),
            message: "no interface matches the requested name or index".to_owned(),
            source: None,
        }));
    }
    Ok(selected)
}
