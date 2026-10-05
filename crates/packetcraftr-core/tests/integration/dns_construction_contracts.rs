// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::protocol::application::dns::{self, Dns};

#[test]
fn borrowed_dns_wire_enforces_msg_byte_limit() {
    let mut wire = vec![0; 12];
    wire[7] = 1;
    wire.extend_from_slice(&[0, 0xfd, 0xe8, 0, 1, 0, 0, 0, 0]);
    wire.extend_from_slice(&65_512u16.to_be_bytes());
    wire.resize(65_535, 0);
    assert_eq!(
        Dns::try_from(wire.as_slice()).unwrap().wire().as_ref(),
        wire
    );

    wire.push(0);
    let error = Dns::try_from(wire.as_slice()).unwrap_err();
    assert!(matches!(
        error,
        dns::Error::MessageTooLarge {
            actual: 65_536,
            maximum: 65_535
        }
    ));
    assert_eq!(
        error.to_string(),
        "DNS message is 65536 bytes; maximum is 65535"
    );
    assert_eq!(
        error.to_string(),
        Dns::try_from(wire).unwrap_err().to_string()
    );
}
