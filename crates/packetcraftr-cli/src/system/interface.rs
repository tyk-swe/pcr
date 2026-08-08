// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::network as net;

use super::super::errors::CliError;

#[derive(Debug)]
pub(crate) enum DeferredInterface {
    Pending(String),
    Resolved,
}

impl DeferredInterface {
    pub(crate) fn new(selector: Option<String>) -> Self {
        match selector {
            Some(selector) => Self::Pending(selector),
            None => Self::Resolved,
        }
    }

    pub(crate) fn resolve_into(
        &mut self,
        options: &mut net::route::Options,
    ) -> Result<(), CliError> {
        let Self::Pending(selector) = self else {
            return Ok(());
        };
        options.interface =
            resolve_interface(Some(selector.clone()), &net::interface::SystemProvider)?;
        *self = Self::Resolved;
        Ok(())
    }
}

pub(crate) fn resolve_interface<I: net::interface::Provider>(
    selector: Option<String>,
    provider: &I,
) -> Result<Option<net::interface::Id>, CliError> {
    let Some(selector) = selector else {
        return Ok(None);
    };
    let requested_index = validate_interface_selector("route", Some(&selector))?;
    let interfaces = provider.interfaces().map_err(CliError::classified)?;
    interfaces
        .into_iter()
        .find(|interface| {
            requested_index.map_or_else(
                || interface.id.name == selector,
                |index| interface.id.index == index,
            )
        })
        .map(|interface| Some(interface.id))
        .ok_or_else(|| {
            CliError::classified(net::Error::Device {
                interface: selector,
                message: "no interface matches the requested name or index".to_owned(),
            })
        })
}

/// Validates an optional interface selector without consulting a platform
/// provider. Decimal selectors are always indexes: zero and values outside
/// the public `u32` index domain must not fall back to interface-name lookup.
pub(crate) fn validate_interface_selector(
    command: &str,
    selector: Option<&str>,
) -> Result<Option<u32>, CliError> {
    let Some(selector) = selector else {
        return Ok(None);
    };
    if selector.is_empty() {
        return Err(CliError::new(
            2,
            format!("{command} interface cannot be empty"),
        ));
    }
    if !selector.bytes().all(|byte| byte.is_ascii_digit()) {
        return Ok(None);
    }
    let index = selector.parse::<u32>().map_err(|_| {
        CliError::new(
            2,
            format!("{command} interface index must be within 1..={}", u32::MAX),
        )
    })?;
    if index == 0 {
        return Err(CliError::new(
            2,
            format!("{command} interface index must be non-zero"),
        ));
    }
    Ok(Some(index))
}
