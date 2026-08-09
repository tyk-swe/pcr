// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;
use packetcraftr_packet::Packet;
use packetcraftr_packet::build::Result as BuiltPacket;
use packetcraftr_packet::protocol::builtin;
use std::time::Instant;

use super::boundary::{FuzzCaseExecution, FuzzExecutionCase};
use crate::Stats;
use crate::exchange::ExchangeResult;
use crate::send::SentPacket;

#[test]
fn fuzz_case_identity_is_owned_by_the_prepared_case() {
    let packet = Packet::new();
    let case = FuzzExecutionCase::new(7, 0x5eed, packet.clone());
    assert_eq!(case.index(), 7);
    assert_eq!(case.seed(), 0x5eed);
    assert!(case.packet().structurally_eq(&packet));
}

#[test]
fn fuzz_case_rejects_a_substituted_authorized_build() {
    let authorized = BuiltPacket {
        bytes: Bytes::from_static(&[1]),
        packet: Packet::new(),
        layout: Default::default(),
        diagnostics: Vec::new(),
        requires_live_opt_in: false,
    };
    let registry = std::sync::Arc::new(builtin::registry().expect("built-in registry"));
    let case =
        FuzzExecutionCase::from_prepared(7, 0x5eed, authorized, registry, Default::default());
    let substituted = SentPacket::for_test(Bytes::from_static(&[2]), Instant::now());
    assert!(case.validate_receipt_for_test(&substituted).is_err());
}

#[test]
fn fuzz_case_rejects_an_exchange_with_multiple_sent_receipts() {
    let authorized = BuiltPacket {
        bytes: Bytes::from_static(&[1]),
        packet: Packet::new(),
        layout: Default::default(),
        diagnostics: Vec::new(),
        requires_live_opt_in: false,
    };
    let registry = std::sync::Arc::new(builtin::registry().expect("built-in registry"));
    let case =
        FuzzExecutionCase::from_prepared(7, 0x5eed, authorized, registry, Default::default());
    let first = SentPacket::for_test(Bytes::from_static(&[1]), Instant::now());
    let second = SentPacket::for_test(Bytes::from_static(&[1]), Instant::now());
    let exchange = ExchangeResult {
        sent: vec![first, second],
        responses: Vec::new(),
        unanswered: Vec::new(),
        unsolicited: Vec::new(),
        undecoded: Vec::new(),
        diagnostics: Vec::new(),
        stats: Stats::default(),
    };
    assert!(FuzzCaseExecution::from_exchange(&case, &exchange).is_err());
}
