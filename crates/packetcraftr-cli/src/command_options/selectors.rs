// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! A malformed value is reported where the command reads the selector, not while parsing.

use std::convert::Infallible;
use std::fmt;
use std::num::NonZeroU32;

use packetcraftr_core::analysis::{StreamRef, StreamTransport};
use packetcraftr_core::error::Kind;

use crate::errors::CliError;

/// Decimal selectors are always indexes and never fall back to interface-name lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InterfaceSelector {
    Name(String),
    Index(NonZeroU32),
}

impl InterfaceSelector {
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
}

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

#[derive(Clone, Debug)]
pub(crate) struct Selector<T> {
    text: String,
    parsed: Result<T, String>,
}

impl<T: Clone> Selector<T> {
    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    pub(crate) fn get(&self) -> Result<T, CliError> {
        self.parsed
            .clone()
            .map_err(|message| CliError::new(Kind::Usage, message))
    }
}

pub(crate) fn interface_selector(text: &str) -> Result<Selector<InterfaceSelector>, Infallible> {
    Ok(Selector {
        text: text.to_owned(),
        parsed: InterfaceSelector::parse(text).map_err(|error| error.message),
    })
}

/// Both transports parse, so each command states its own restriction.
pub(crate) fn stream_selector(text: &str) -> Result<Selector<StreamRef>, Infallible> {
    Ok(Selector {
        text: text.to_owned(),
        parsed: parse_stream(text)
            .ok_or_else(|| format!("invalid --stream '{text}': expected tcp:INDEX or udp:INDEX")),
    })
}

fn parse_stream(text: &str) -> Option<StreamRef> {
    let (transport, index) = text.split_once(':')?;
    let transport = match transport {
        "tcp" => StreamTransport::Tcp,
        "udp" => StreamTransport::Udp,
        _ => return None,
    };
    let index = index.parse::<u64>().ok()?;
    Some(StreamRef { transport, index })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_interfaces_fail_only_when_read() {
        let selector = interface_selector("0").unwrap();
        assert_eq!(selector.text(), "0");
        let error = selector.get().unwrap_err();
        assert_eq!(error.message, "--interface index must be non-zero");
        assert_eq!(error.exit_code(), 2);
        assert!(interface_selector("eth0").unwrap().get().is_ok());
    }
}
