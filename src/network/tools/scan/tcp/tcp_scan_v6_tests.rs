// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

#[test]
fn test_scan_tcp_v6_rejects_ipv4() {
    let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80);
    let ports = vec![80];
    let timeout = Duration::from_millis(100);
    let strategy = GenericTcpScan::syn();

    let result = scan_tcp_v6(destination, &ports, timeout, None, &strategy);

    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "scan_tcp_v6 called with IPv4 address"
    );
}

#[test]
fn test_perform_tcp_scan_ipv6_mismatch() {
    let config = TcpScanConfig {
        address: SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 80),
        ports: vec![80],
        timeout: Duration::from_millis(100),
        source_override: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)), // Mismatch
        scan_strategy: GenericTcpScan::syn(),
    };

    let result = perform_tcp_scan(config);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("IPv4 interface override cannot be used for IPv6 target"));
}

#[cfg(feature = "net_integration")]
#[ignore = "opens raw IPv6 sockets to exercise OS error propagation"]
#[test]
fn test_scan_tcp_v6_propagates_socket_errors() {
    let destination = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 80);
    let ports = vec![80];
    let timeout = Duration::from_millis(100);
    let strategy = GenericTcpScan::syn();

    // Use a dummy override to bypass source discovery
    let source_override = Some(Ipv6Addr::LOCALHOST);

    let result = scan_tcp_v6(destination, &ports, timeout, source_override, &strategy);

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    // The error message should indicate failure during resource acquisition.
    // It could be "open TCPv6 transport channel" or similar, or "Operation not permitted"
    assert!(
        err_msg.contains("open TCPv6 transport channel")
            || err_msg.contains("create raw IPv6 TCP socket")
            || err_msg.contains("send TCP probe failed")
            || err_msg.contains("Operation not permitted")
            || err_msg.contains("Permission denied"),
        "Unexpected error message: {}",
        err_msg
    );
}
