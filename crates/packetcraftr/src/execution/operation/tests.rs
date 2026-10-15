// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#[path = "../../../tests/common/mod.rs"]
mod common;
#[path = "discovery_tests.rs"]
mod discovery;
#[path = "traceroute_tests.rs"]
mod traceroute;

#[test]
fn remaining_allowance_is_operation_local_and_saturates() {
    let (client, _) = crate::test_support::fake_client();
    let mut operation = super::Operation::new(&client, std::time::Duration::from_secs(1));
    operation.spent = crate::Stats {
        packets_attempted: u64::MAX,
        bytes: u64::MAX,
        ..Default::default()
    };
    let remaining = operation.policy(client.policy());
    assert_eq!(remaining.max_packets_per_operation, 0);
    assert_eq!(remaining.max_bytes_per_operation, 0);
    assert!(client.policy().max_packets_per_operation > 0);
    let fresh = super::Operation::new(&client, std::time::Duration::from_secs(1));
    assert_eq!(
        fresh.policy(client.policy()).max_packets_per_operation,
        client.policy().max_packets_per_operation
    );
}
