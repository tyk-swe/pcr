// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Selector arguments: `--interface NAME_OR_INDEX` and
//! `--stream TRANSPORT:INDEX`.
//!
//! Clap parses each value into its type once, while arguments are parsed, but
//! a malformed value is reported where the command reads the selector: after
//! the output-format check, and for route selection after policy admission.
//! That keeps the error a malformed selector publishes, and which error wins
//! when several inputs are wrong, as they were for the untyped arguments.

use std::convert::Infallible;

use packetcraftr_core::analysis::{StreamRef, StreamTransport};
use packetcraftr_core::error::Kind;

use crate::errors::CliError;
use crate::system::InterfaceSelector;

/// A parsed selector argument and the text it was parsed from.
#[derive(Clone, Debug)]
pub(crate) struct Selector<T> {
    text: String,
    parsed: Result<T, String>,
}

impl<T: Clone> Selector<T> {
    /// The value as written on the command line.
    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    /// The selected value.
    ///
    /// # Errors
    ///
    /// A usage error naming the argument when the value was malformed.
    pub(crate) fn get(&self) -> Result<T, CliError> {
        self.parsed
            .clone()
            .map_err(|message| CliError::new(Kind::Usage, message))
    }
}

/// The `--interface` value parser.
pub(crate) fn interface_selector(text: &str) -> Result<Selector<InterfaceSelector>, Infallible> {
    Ok(Selector {
        text: text.to_owned(),
        parsed: InterfaceSelector::parse(text).map_err(|error| error.message),
    })
}

/// The `--stream` value parser: `tcp:INDEX` or `udp:INDEX`.
///
/// Both transports parse, so each command states its own restriction:
/// `follow` follows either, while a TCP-only command rejects a `udp:`
/// selector with a message that says why.
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

    fn stream(text: &str) -> Result<StreamRef, CliError> {
        stream_selector(text).unwrap().get()
    }

    #[test]
    fn stream_selectors_name_a_transport_and_an_unsigned_index() {
        assert_eq!(
            stream("tcp:7").unwrap(),
            StreamRef {
                transport: StreamTransport::Tcp,
                index: 7
            }
        );
        assert_eq!(
            stream("udp:0").unwrap(),
            StreamRef {
                transport: StreamTransport::Udp,
                index: 0
            }
        );
        for invalid in ["", "tcp", "tcp:", "sctp:0", "udp:nope", "tcp:-1", "TCP:1"] {
            let error = stream(invalid).unwrap_err();
            assert_eq!(error.classification.code, "cli.error", "{invalid:?}");
            assert_eq!(
                error.message,
                format!("invalid --stream '{invalid}': expected tcp:INDEX or udp:INDEX")
            );
        }
    }

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
