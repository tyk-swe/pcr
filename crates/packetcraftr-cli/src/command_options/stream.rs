// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The `--stream TRANSPORT:INDEX` conversation selector.

use packetcraftr_core::analysis::{StreamRef, StreamTransport};

/// Parses a `tcp:INDEX` or `udp:INDEX` conversation while arguments are
/// parsed.
///
/// Both transports parse, so each command states its own restriction:
/// `follow` follows either, while a TCP-only command rejects a `udp:`
/// selector with a message that says why.
pub(crate) fn stream_selector(spec: &str) -> Result<StreamRef, String> {
    let invalid = || "expected tcp:INDEX or udp:INDEX".to_owned();
    let (transport, index) = spec.split_once(':').ok_or_else(invalid)?;
    let transport = match transport {
        "tcp" => StreamTransport::Tcp,
        "udp" => StreamTransport::Udp,
        _ => return Err(invalid()),
    };
    let index = index.parse::<u64>().map_err(|_| invalid())?;
    Ok(StreamRef { transport, index })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_name_a_transport_and_an_unsigned_index() {
        assert_eq!(
            stream_selector("tcp:7"),
            Ok(StreamRef {
                transport: StreamTransport::Tcp,
                index: 7
            })
        );
        assert_eq!(
            stream_selector("udp:0"),
            Ok(StreamRef {
                transport: StreamTransport::Udp,
                index: 0
            })
        );
        for invalid in ["", "tcp", "tcp:", "sctp:0", "udp:nope", "tcp:-1", "TCP:1"] {
            assert!(stream_selector(invalid).is_err(), "{invalid:?}");
        }
    }
}
