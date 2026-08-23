// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::{BoundaryError, netio as net};

use crate::error::{INTERFACE_SELECTOR, failure};

pub(crate) fn resolve<I: net::interface::Provider>(
    selector: Option<String>,
    provider: &I,
) -> Result<Option<net::interface::Id>, BoundaryError> {
    let Some(selector) = selector else {
        return Ok(None);
    };
    let requested_index = validate_selector(Some(&selector))?;
    let interfaces = provider.interfaces().map_err(BoundaryError::from_error)?;
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
            BoundaryError::from_error(net::Error::Device {
                interface: selector,
                message: "no interface matches the requested name or index".to_owned(),
            })
        })
}

/// Validates an optional interface selector without consulting a platform
/// provider. Decimal selectors are always indexes: zero and values outside
/// the public `u32` index domain must not fall back to interface-name lookup.
pub(crate) fn validate_selector(selector: Option<&str>) -> Result<Option<u32>, BoundaryError> {
    let Some(selector) = selector else {
        return Ok(None);
    };
    if selector.is_empty() {
        return Err(failure(INTERFACE_SELECTOR, "--interface cannot be empty"));
    }
    if !selector.bytes().all(|byte| byte.is_ascii_digit()) {
        return Ok(None);
    }
    let index = selector.parse::<u32>().map_err(|_| {
        failure(
            INTERFACE_SELECTOR,
            format!("--interface index must be within 1..={}", u32::MAX),
        )
    })?;
    if index == 0 {
        return Err(failure(
            INTERFACE_SELECTOR,
            "--interface index must be non-zero",
        ));
    }
    Ok(Some(index))
}

#[cfg(test)]
mod tests {
    use super::validate_selector;
    use crate::error::exit_code;

    #[test]
    fn interface_selectors_distinguish_names_and_numeric_indexes() {
        assert_eq!(validate_selector(None).unwrap(), None);
        assert_eq!(validate_selector(Some("ethernet0")).unwrap(), None);
        assert_eq!(validate_selector(Some("7")).unwrap(), Some(7));

        for (selector, expected) in [
            ("", "--interface cannot be empty"),
            ("0", "--interface index must be non-zero"),
            (
                "4294967296",
                "--interface index must be within 1..=4294967295",
            ),
        ] {
            let error = validate_selector(Some(selector))
                .expect_err("invalid selectors must fail before provider access");
            assert_eq!(exit_code(&error), 2, "selector={selector:?}");
            assert_eq!(error.to_string(), expected, "selector={selector:?}");
        }
    }
}
