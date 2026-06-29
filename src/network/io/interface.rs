// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use log::warn;
use pnet::datalink::{self, NetworkInterface};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};
use std::string::FromUtf8Error;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};
#[cfg(target_os = "linux")]
use std::{io::Read, thread};
use thiserror::Error;

type Result<T> = std::result::Result<T, InterfaceError>;

pub trait InterfaceProvider {
    fn interfaces(&self) -> Vec<NetworkInterface>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceSelectionReason {
    ExplicitInterface,
    RouteTable,
    Heuristic,
}

#[derive(Debug, Clone)]
pub struct InterfaceSelection {
    pub interface: NetworkInterface,
    pub reason: InterfaceSelectionReason,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemInterfaceProvider;

impl InterfaceProvider for SystemInterfaceProvider {
    fn interfaces(&self) -> Vec<NetworkInterface> {
        datalink::interfaces()
    }
}

#[derive(Debug, Error)]
pub enum InterfaceError {
    #[error("interface '{name}' not found")]
    NotFound { name: String },
    #[error(
        "routing table selected interface '{interface}' for {destination}, but it was not found"
    )]
    RouteInterfaceMissing {
        destination: IpAddr,
        interface: String,
    },
    #[error("routing table query for {destination} failed to execute")]
    RouteCommandIo {
        destination: IpAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("routing table query for {destination} exited with an error: {stderr}")]
    RouteCommandFailed { destination: IpAddr, stderr: String },
    #[error("routing table output for {destination} was not valid UTF-8")]
    RouteOutputUtf8 {
        destination: IpAddr,
        #[source]
        source: FromUtf8Error,
    },
    #[error("routing table JSON output for {destination} could not be parsed")]
    RouteOutputJson {
        destination: IpAddr,
        #[source]
        source: serde_json::Error,
    },
    #[error("no route found for {destination}")]
    RouteNotFound { destination: IpAddr },
    #[error(
        "no suitable interface found using heuristics; specify --interface explicitly or provide a destination address"
    )]
    HeuristicUnavailable,
    #[cfg(not(target_os = "linux"))]
    #[error(
        "routing table queries are not yet implemented for this platform; use --interface to specify the interface for destination {destination}"
    )]
    UnsupportedPlatform { destination: IpAddr },
    #[error("the 'ip' command could not be found in standard locations")]
    IpCommandNotFound,
}

pub fn find_interface(name: Option<&str>) -> Result<NetworkInterface> {
    Ok(find_interface_selection_with_provider_impl(name, &SystemInterfaceProvider)?.interface)
}

pub fn find_interface_selection(name: Option<&str>) -> Result<InterfaceSelection> {
    find_interface_selection_with_provider_impl(name, &SystemInterfaceProvider)
}

fn find_interface_selection_with_provider_impl<P>(
    name: Option<&str>,
    provider: &P,
) -> Result<InterfaceSelection>
where
    P: InterfaceProvider + ?Sized,
{
    if let Some(name) = name {
        return Ok(InterfaceSelection {
            interface: resolve_interface_by_name_with_provider(name, provider)?,
            reason: InterfaceSelectionReason::ExplicitInterface,
        });
    }
    Ok(InterfaceSelection {
        interface: heuristic_default_interface_with_provider(provider)?,
        reason: InterfaceSelectionReason::Heuristic,
    })
}

/// Find the interface for a specific destination using the routing table
pub fn find_interface_for_destination(destination: IpAddr) -> Result<NetworkInterface> {
    Ok(find_interface_for_destination_selection_with_provider_impl(
        destination,
        &SystemInterfaceProvider,
        query_routing_table,
    )?
    .interface)
}

pub fn find_interface_for_destination_selection(destination: IpAddr) -> Result<InterfaceSelection> {
    find_interface_for_destination_selection_with_provider_impl(
        destination,
        &SystemInterfaceProvider,
        query_routing_table,
    )
}

fn find_interface_for_destination_selection_with_provider_impl<P, Q>(
    destination: IpAddr,
    provider: &P,
    route_query: Q,
) -> Result<InterfaceSelection>
where
    P: InterfaceProvider + ?Sized,
    Q: FnOnce(IpAddr) -> Result<String>,
{
    match route_query(destination) {
        Ok(iface_name) => {
            let interface = resolve_interface_by_name_with_provider(&iface_name, provider)
                .map_err(|err| match err {
                    InterfaceError::NotFound { .. } => InterfaceError::RouteInterfaceMissing {
                        destination,
                        interface: iface_name,
                    },
                    other => other,
                })?;
            Ok(InterfaceSelection {
                interface,
                reason: InterfaceSelectionReason::RouteTable,
            })
        }
        Err(err) if should_fallback_to_heuristic(&err) => {
            warn!(
                "Failed to query routing table for {}: {}; falling back to heuristic selection. \
                Consider using --interface to specify the interface explicitly.",
                destination, err
            );
            Ok(InterfaceSelection {
                interface: heuristic_default_interface_with_provider(provider)?,
                reason: InterfaceSelectionReason::Heuristic,
            })
        }
        Err(err) => Err(err),
    }
}

#[cfg(target_os = "linux")]
fn should_fallback_to_heuristic(error: &InterfaceError) -> bool {
    matches!(error, InterfaceError::IpCommandNotFound)
}

#[cfg(not(target_os = "linux"))]
fn should_fallback_to_heuristic(error: &InterfaceError) -> bool {
    matches!(
        error,
        InterfaceError::IpCommandNotFound | InterfaceError::UnsupportedPlatform { .. }
    )
}

pub fn resolve_interface_by_name(name: &str) -> Result<NetworkInterface> {
    resolve_interface_by_name_with_provider(name, &SystemInterfaceProvider)
}

fn resolve_interface_by_name_with_provider<P>(name: &str, provider: &P) -> Result<NetworkInterface>
where
    P: InterfaceProvider + ?Sized,
{
    provider
        .interfaces()
        .into_iter()
        .find(|iface| iface.name == name)
        .ok_or_else(|| InterfaceError::NotFound {
            name: name.to_string(),
        })
}

#[cfg(target_os = "linux")]
fn get_ip_path() -> Result<String> {
    const CANDIDATES: &[&str] = &["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"];
    for &path in CANDIDATES {
        if std::path::Path::new(path).exists() {
            return Ok(path.to_string());
        }
    }
    Err(InterfaceError::IpCommandNotFound)
}

/// Helper to run a command with a timeout
#[cfg(target_os = "linux")]
fn run_with_timeout(command: &mut Command) -> std::io::Result<std::process::Output> {
    const COMMAND_TIMEOUT_SECS: u64 = 5;

    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    let mut child = command.spawn()?;
    let start = Instant::now();
    let timeout = Duration::from_secs(COMMAND_TIMEOUT_SECS);

    loop {
        if let Some(status) = child.try_wait()? {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();

            if let Some(mut handle) = child.stdout.take() {
                handle.read_to_end(&mut stdout)?;
            }
            if let Some(mut handle) = child.stderr.take() {
                handle.read_to_end(&mut stderr)?;
            }

            return Ok(std::process::Output {
                status,
                stdout,
                stderr,
            });
        }

        if start.elapsed() >= timeout {
            let _ = child.kill();
            // We must wait for the process to be reaped to prevent a zombie process.
            let _ = child.wait();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "command timed out",
            ));
        }

        thread::sleep(Duration::from_millis(50));
    }
}

/// Query the OS routing table to determine the interface for a destination
#[cfg(target_os = "linux")]
fn query_routing_table(destination: IpAddr) -> Result<String> {
    let destination_arg = destination.to_string();
    let family_flag = match destination {
        IpAddr::V4(_) => "-4",
        IpAddr::V6(_) => "-6",
    };

    let ip_path = get_ip_path()?;

    // Try `ip -j` first for robust JSON parsing
    let mut command_json = Command::new(&ip_path);
    command_json.env_clear();
    command_json.arg(family_flag);
    command_json.args(["-j", "route", "get", destination_arg.as_str()]);

    match run_with_timeout(&mut command_json) {
        Ok(output) => {
            if output.status.success() {
                let stdout = String::from_utf8(output.stdout).map_err(|source| {
                    InterfaceError::RouteOutputUtf8 {
                        destination,
                        source,
                    }
                })?;
                // If JSON parsing fails due to malformed output, keep diagnostics and fall back to
                // text mode for compatibility with older `ip` output variants.
                match parse_interface_from_json(destination, &stdout) {
                    Ok(iface) => return Ok(iface),
                    Err(InterfaceError::RouteNotFound { .. }) => {}
                    Err(err) => {
                        warn!(
                            "Routing table JSON parse for {} failed: {}. Falling back to text output.",
                            destination, err
                        );
                    }
                }
            }
        }
        Err(err) => {
            warn!(
                "Routing table JSON query for {} failed: {}. Falling back to text output.",
                destination, err
            );
        }
    }

    // Fallback to text output parsing
    let mut command = Command::new(&ip_path);
    command.env_clear();
    command.arg(family_flag);
    command.args(["route", "get", destination_arg.as_str()]);

    let output =
        run_with_timeout(&mut command).map_err(|source| InterfaceError::RouteCommandIo {
            destination,
            source,
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(InterfaceError::RouteCommandFailed {
            destination,
            stderr,
        });
    }

    let stdout_bytes = output.stdout;
    let stdout =
        String::from_utf8(stdout_bytes).map_err(|source| InterfaceError::RouteOutputUtf8 {
            destination,
            source,
        })?;

    parse_interface_from_route_output(destination, &stdout)
}

#[cfg(not(target_os = "linux"))]
fn query_routing_table(destination: IpAddr) -> Result<String> {
    Err(InterfaceError::UnsupportedPlatform { destination })
}

fn heuristic_default_interface_with_provider<P>(provider: &P) -> Result<NetworkInterface>
where
    P: InterfaceProvider + ?Sized,
{
    provider
        .interfaces()
        .into_iter()
        .filter(|iface| iface.is_up() && !iface.is_loopback())
        .filter(|iface| iface.mac.is_some())
        .find(iface_has_ip)
        .ok_or(InterfaceError::HeuristicUnavailable)
}

fn iface_has_ip(iface: &NetworkInterface) -> bool {
    iface.ips.iter().any(|ip| {
        matches!(ip.ip(), IpAddr::V4(v4) if v4 != Ipv4Addr::UNSPECIFIED)
            || matches!(ip.ip(), IpAddr::V6(v6) if v6 != Ipv6Addr::UNSPECIFIED)
    })
}

fn parse_interface_from_json(destination: IpAddr, stdout: &str) -> Result<String> {
    let value: serde_json::Value =
        serde_json::from_str(stdout).map_err(|source| InterfaceError::RouteOutputJson {
            destination,
            source,
        })?;

    if let Some(arr) = value.as_array() {
        for route in arr {
            if let Some(dev) = route.get("dev").and_then(|v| v.as_str()) {
                let dev = dev.trim();
                if !dev.is_empty() {
                    return Ok(dev.to_string());
                }
            }
        }
    }
    Err(InterfaceError::RouteNotFound { destination })
}

fn parse_interface_from_route_output(destination: IpAddr, stdout: &str) -> Result<String> {
    // Parse output like:
    //   IPv4: "192.0.2.1 via 10.0.0.1 dev eth0 src 10.0.0.2"
    //   IPv6: "2001:db8::1 dev eth0 src 2001:db8::2 metric 1024"
    for line in stdout.lines() {
        if let Some(dev_idx) = line.find(" dev ") {
            let after_dev = &line[dev_idx + 5..];
            if let Some(iface_name) = after_dev.split_whitespace().next() {
                return Ok(iface_name.to_string());
            }
        }
    }

    Err(InterfaceError::RouteNotFound { destination })
}

#[cfg(any(test, feature = "test_utils"))]
pub fn find_interface_with_provider<P>(name: Option<&str>, provider: &P) -> Result<NetworkInterface>
where
    P: InterfaceProvider + ?Sized,
{
    Ok(find_interface_selection_with_provider_impl(name, provider)?.interface)
}

#[cfg(any(test, feature = "test_utils"))]
pub fn find_interface_for_destination_with_provider<P, Q>(
    destination: IpAddr,
    provider: &P,
    route_query: Q,
) -> Result<NetworkInterface>
where
    P: InterfaceProvider + ?Sized,
    Q: FnOnce(IpAddr) -> Result<String>,
{
    Ok(find_interface_for_destination_selection_with_provider_impl(
        destination,
        provider,
        route_query,
    )?
    .interface)
}

#[cfg(any(test, feature = "test_utils"))]
pub fn find_interface_selection_with_provider<P>(
    name: Option<&str>,
    provider: &P,
) -> Result<InterfaceSelection>
where
    P: InterfaceProvider + ?Sized,
{
    find_interface_selection_with_provider_impl(name, provider)
}

#[cfg(any(test, feature = "test_utils"))]
pub fn find_interface_for_destination_selection_with_provider<P, Q>(
    destination: IpAddr,
    provider: &P,
    route_query: Q,
) -> Result<InterfaceSelection>
where
    P: InterfaceProvider + ?Sized,
    Q: FnOnce(IpAddr) -> Result<String>,
{
    find_interface_for_destination_selection_with_provider_impl(destination, provider, route_query)
}

#[cfg(any(test, feature = "test_utils"))]
pub mod test_utils {
    use super::*;
    use pnet::datalink::MacAddr;
    use pnet::ipnetwork::IpNetwork;

    #[derive(Debug, Clone, Default)]
    pub struct StaticInterfaceProvider {
        interfaces: Vec<NetworkInterface>,
    }

    impl StaticInterfaceProvider {
        pub fn new(interfaces: Vec<NetworkInterface>) -> Self {
            Self { interfaces }
        }
    }

    impl InterfaceProvider for StaticInterfaceProvider {
        fn interfaces(&self) -> Vec<NetworkInterface> {
            self.interfaces.clone()
        }
    }

    pub fn interface(
        name: impl Into<String>,
        flags: u32,
        ips: Vec<IpNetwork>,
        mac: Option<MacAddr>,
    ) -> NetworkInterface {
        NetworkInterface {
            name: name.into(),
            description: "test interface".to_string(),
            index: 1,
            mac,
            ips,
            flags,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::datalink::MacAddr;
    use pnet::ipnetwork::IpNetwork;
    use proptest::prelude::*;

    fn up_flag() -> u32 {
        libc::IFF_UP as u32
    }

    fn loopback_flag() -> u32 {
        libc::IFF_LOOPBACK as u32
    }

    fn fake_provider() -> test_utils::StaticInterfaceProvider {
        test_utils::StaticInterfaceProvider::new(vec![
            test_utils::interface(
                "lo",
                up_flag() | loopback_flag(),
                vec![IpNetwork::V4("127.0.0.1/8".parse().unwrap())],
                None,
            ),
            test_utils::interface(
                "eth-test",
                up_flag(),
                vec![IpNetwork::V4("192.0.2.2/24".parse().unwrap())],
                Some(MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)),
            ),
        ])
    }

    /// Returns the interface name the heuristic selector would pick on this host, if any.
    ///
    /// Tests that rely on system interfaces call this helper so they can assert against the
    /// exact choice or gracefully handle the "no suitable interface" error in environments
    /// where the heuristic has nothing to return (such as minimal CI containers).
    #[cfg(feature = "net_integration")]
    fn heuristic_interface_name() -> Option<String> {
        SystemInterfaceProvider
            .interfaces()
            .into_iter()
            .filter(|iface| iface.is_up() && !iface.is_loopback())
            .filter(|iface| iface.mac.is_some())
            .find(super::iface_has_ip)
            .map(|iface| iface.name)
    }

    /// Asserts that the provided error matches the canonical heuristic failure message.
    ///
    /// The heuristic is intentionally conservative, so tests should treat this error as the
    /// expected outcome when no usable interface exists rather than as a failure of the logic
    /// under test.
    #[cfg(feature = "net_integration")]
    fn assert_heuristic_error(err: InterfaceError) {
        match err {
            InterfaceError::HeuristicUnavailable => {}
            other => panic!("unexpected error: {other}"),
        }
    }

    #[cfg(feature = "net_integration")]
    fn assert_heuristic_selection_result(
        expected: Option<String>,
        result: Result<NetworkInterface>,
    ) {
        match (expected, result) {
            (Some(expected_name), Ok(iface)) => {
                assert_eq!(iface.name, expected_name);
                assert!(iface.is_up());
                assert!(iface_has_ip(&iface));
            }
            (None, Err(err)) => assert_heuristic_error(err),
            (Some(expected_name), Err(err)) => {
                panic!("heuristic predicted interface {expected_name}, but call failed: {err}");
            }
            (None, Ok(iface)) => panic!(
                "heuristic predicted error, but call succeeded with {:?}",
                iface.name
            ),
        }
    }

    #[cfg(feature = "net_integration")]
    fn assert_routing_error(err: InterfaceError) {
        assert!(matches!(
            err,
            InterfaceError::RouteInterfaceMissing { .. }
                | InterfaceError::RouteCommandIo { .. }
                | InterfaceError::RouteCommandFailed { .. }
                | InterfaceError::RouteOutputUtf8 { .. }
                | InterfaceError::RouteOutputJson { .. }
                | InterfaceError::RouteNotFound { .. }
        ));
    }

    #[test]
    fn iface_has_ip_returns_true_for_ipv4() {
        let iface = NetworkInterface {
            name: "test0".to_string(),
            description: "test interface".to_string(),
            index: 1,
            mac: Some(MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)),
            ips: vec![IpNetwork::V4("192.168.1.1/24".parse().unwrap())],
            flags: 0,
        };
        assert!(iface_has_ip(&iface));
    }

    #[test]
    fn iface_has_ip_returns_true_for_ipv6() {
        let iface = NetworkInterface {
            name: "test0".to_string(),
            description: "test interface".to_string(),
            index: 1,
            mac: Some(MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)),
            ips: vec![IpNetwork::V6("2001:db8::1/64".parse().unwrap())],
            flags: 0,
        };
        assert!(iface_has_ip(&iface));
    }

    #[test]
    fn iface_has_ip_returns_false_for_unspecified_ipv4() {
        let iface = NetworkInterface {
            name: "test0".to_string(),
            description: "test interface".to_string(),
            index: 1,
            mac: Some(MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)),
            ips: vec![IpNetwork::V4("0.0.0.0/0".parse().unwrap())],
            flags: 0,
        };
        assert!(!iface_has_ip(&iface));
    }

    #[test]
    fn iface_has_ip_returns_false_for_unspecified_ipv6() {
        let iface = NetworkInterface {
            name: "test0".to_string(),
            description: "test interface".to_string(),
            index: 1,
            mac: Some(MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)),
            ips: vec![IpNetwork::V6("::/128".parse().unwrap())],
            flags: 0,
        };
        assert!(!iface_has_ip(&iface));
    }

    #[test]
    fn iface_has_ip_returns_false_for_empty() {
        let iface = NetworkInterface {
            name: "test0".to_string(),
            description: "test interface".to_string(),
            index: 1,
            mac: Some(MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)),
            ips: vec![],
            flags: 0,
        };
        assert!(!iface_has_ip(&iface));
    }

    #[test]
    fn resolve_interface_by_name_with_provider_fails_for_nonexistent() {
        let provider = test_utils::StaticInterfaceProvider::default();
        let result =
            resolve_interface_by_name_with_provider("nonexistent_interface_12345", &provider);
        match result {
            Err(InterfaceError::NotFound { name }) => {
                assert_eq!(name, "nonexistent_interface_12345");
            }
            Err(other) => panic!("unexpected error: {other}"),
            Ok(iface) => panic!("expected error but got {}", iface.name),
        }
    }

    #[test]
    fn resolve_interface_by_name_with_provider_resolves_fake_interface() {
        let provider = fake_provider();
        let iface =
            resolve_interface_by_name_with_provider("eth-test", &provider).expect("fake interface");
        assert_eq!(iface.name, "eth-test");
        assert!(iface.is_up());
        assert!(iface.mac.is_some());
    }

    /// When no explicit interface is provided, the heuristic selector should either return
    /// a usable interface discovered via `datalink::interfaces` or emit the standard
    /// "no suitable interface" error when nothing qualifies.
    #[test]
    fn find_interface_with_none_uses_heuristic() {
        let provider = fake_provider();
        let iface = find_interface_with_provider(None, &provider).expect("heuristic interface");
        assert_eq!(iface.name, "eth-test");
        assert!(iface.is_up());
        assert!(!iface.is_loopback());
        assert!(iface.mac.is_some());
        assert!(iface_has_ip(&iface));
    }

    #[test]
    fn find_interface_with_name_resolves() {
        let provider = fake_provider();
        let iface = find_interface_with_provider(Some("eth-test"), &provider)
            .expect("named fake interface");
        assert_eq!(iface.name, "eth-test");

        let result = find_interface_with_provider(Some("nonexistent_test_interface"), &provider);
        assert!(matches!(result, Err(InterfaceError::NotFound { .. })));
    }

    #[test]
    fn find_interface_for_destination_uses_fake_route_and_provider() {
        let provider = fake_provider();
        let destination: IpAddr = "198.51.100.7".parse().unwrap();
        let iface = find_interface_for_destination_with_provider(destination, &provider, |_| {
            Ok("eth-test".to_string())
        })
        .expect("fake routed interface");

        assert_eq!(iface.name, "eth-test");
    }

    #[test]
    fn interface_selection_reports_explicit_reason() {
        let provider = fake_provider();
        let selection = find_interface_selection_with_provider(Some("eth-test"), &provider)
            .expect("named fake interface");

        assert_eq!(selection.interface.name, "eth-test");
        assert_eq!(
            selection.reason,
            InterfaceSelectionReason::ExplicitInterface
        );
    }

    #[test]
    fn interface_selection_reports_route_table_reason() {
        let provider = fake_provider();
        let destination: IpAddr = "198.51.100.7".parse().unwrap();
        let selection =
            find_interface_for_destination_selection_with_provider(destination, &provider, |_| {
                Ok("eth-test".to_string())
            })
            .expect("fake routed interface");

        assert_eq!(selection.interface.name, "eth-test");
        assert_eq!(selection.reason, InterfaceSelectionReason::RouteTable);
    }

    #[test]
    fn interface_selection_reports_heuristic_fallback_reason() {
        let provider = fake_provider();
        let destination: IpAddr = "198.51.100.7".parse().unwrap();
        let selection =
            find_interface_for_destination_selection_with_provider(destination, &provider, |_| {
                Err(InterfaceError::IpCommandNotFound)
            })
            .expect("fake heuristic fallback");

        assert_eq!(selection.interface.name, "eth-test");
        assert_eq!(selection.reason, InterfaceSelectionReason::Heuristic);
    }

    #[test]
    fn find_interface_for_destination_reports_missing_fake_route_interface() {
        let provider = fake_provider();
        let destination: IpAddr = "198.51.100.7".parse().unwrap();
        let err = find_interface_for_destination_with_provider(destination, &provider, |_| {
            Ok("missing0".to_string())
        })
        .expect_err("missing fake route interface should fail");

        assert!(matches!(
            err,
            InterfaceError::RouteInterfaceMissing {
                destination: err_destination,
                interface
            } if err_destination == destination && interface == "missing0"
        ));
    }

    #[test]
    fn find_interface_for_destination_falls_back_to_fake_heuristic_when_route_unavailable() {
        let provider = fake_provider();
        let destination: IpAddr = "198.51.100.7".parse().unwrap();
        let iface = find_interface_for_destination_with_provider(destination, &provider, |_| {
            Err(InterfaceError::IpCommandNotFound)
        })
        .expect("fake heuristic fallback");

        assert_eq!(iface.name, "eth-test");
    }

    /// Verifies that querying for a loopback destination returns the routing-table interface
    /// when available, otherwise falling back to the heuristic selection.
    #[cfg(feature = "net_integration")]
    #[ignore = "requires host routing table and interface inventory"]
    #[test]
    fn find_interface_for_destination_handles_localhost() {
        use std::net::IpAddr;
        let localhost: IpAddr = "127.0.0.1".parse().unwrap();
        let result = find_interface_for_destination(localhost);
        #[cfg(target_os = "linux")]
        {
            match super::query_routing_table(localhost) {
                Ok(route_iface) => {
                    let iface = result.expect("routing table lookup should succeed");
                    assert_eq!(iface.name, route_iface);
                    assert!(iface.is_up());
                    assert!(iface_has_ip(&iface));
                }
                Err(InterfaceError::IpCommandNotFound) => {
                    let expected = heuristic_interface_name();
                    assert_heuristic_selection_result(expected, result);
                }
                Err(_) => {
                    let err = result.expect_err(
                        "routing query errors should be returned without heuristic fallback",
                    );
                    assert_routing_error(err);
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        let expected = heuristic_interface_name();
        #[cfg(not(target_os = "linux"))]
        assert_heuristic_selection_result(expected, result);
    }

    /// Verifies that querying for a remote destination yields either the resolved interface or
    /// the expected heuristic error message when no route can be determined.
    #[cfg(feature = "net_integration")]
    #[ignore = "requires host routing table and interface inventory"]
    #[test]
    fn find_interface_for_destination_handles_remote() {
        use std::net::IpAddr;
        let remote: IpAddr = "8.8.8.8".parse().unwrap();
        let result = find_interface_for_destination(remote);

        #[cfg(target_os = "linux")]
        {
            match super::query_routing_table(remote) {
                Ok(route_iface) => {
                    let iface =
                        result.expect("routing table lookup should succeed for remote host");
                    assert_eq!(iface.name, route_iface);
                    assert!(iface.is_up());
                    assert!(iface_has_ip(&iface));
                }
                Err(InterfaceError::IpCommandNotFound) => {
                    let expected = heuristic_interface_name();
                    assert_heuristic_selection_result(expected, result);
                }
                Err(_) => {
                    let err = result.expect_err(
                        "routing query errors should be returned without heuristic fallback",
                    );
                    assert_routing_error(err);
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        let expected = heuristic_interface_name();
        #[cfg(not(target_os = "linux"))]
        assert_heuristic_selection_result(expected, result);
    }

    #[test]
    fn iface_has_ip_handles_mixed_addresses() {
        // Test with both specified and unspecified addresses
        let iface = NetworkInterface {
            name: "test0".to_string(),
            description: "test interface".to_string(),
            index: 1,
            mac: Some(MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)),
            ips: vec![
                IpNetwork::V4("0.0.0.0/0".parse().unwrap()),
                IpNetwork::V4("192.168.1.1/24".parse().unwrap()),
            ],
            flags: 0,
        };
        // Should return true because at least one IP is valid
        assert!(iface_has_ip(&iface));
    }

    #[test]
    fn parse_route_output_extracts_ipv6_interface() {
        use std::net::IpAddr;

        let destination = IpAddr::V6("2001:db8::1".parse().unwrap());
        let output = "2001:db8::1 dev eth0 src 2001:db8::2 metric 1024";

        let iface = super::parse_interface_from_route_output(destination, output)
            .expect("IPv6 route parser should locate interface");

        assert_eq!(iface, "eth0");
    }

    #[test]
    fn parse_route_output_extracts_ipv4_interface() {
        use std::net::IpAddr;

        let destination = IpAddr::V4("192.0.2.1".parse().unwrap());
        let output = "192.0.2.1 via 10.0.0.1 dev eth1 src 10.0.0.2";

        let iface = super::parse_interface_from_route_output(destination, output)
            .expect("IPv4 route parser should locate interface");

        assert_eq!(iface, "eth1");
    }

    #[test]
    fn parse_route_output_extracts_interface_from_multiline_output() {
        use std::net::IpAddr;

        let destination = IpAddr::V4("203.0.113.9".parse().unwrap());
        let output = "203.0.113.9 from 198.51.100.99 iif eth0\n    cache\n    dev enp0s31f6 src 198.51.100.42 metric 100";

        let iface = super::parse_interface_from_route_output(destination, output)
            .expect("parser should scan multiple lines");

        assert_eq!(iface, "enp0s31f6");
    }

    fn interface_name_strategy() -> impl Strategy<Value = String> {
        const ALLOWED: &[char] = &[
            '-', '_', '.', ':', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
            'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D',
            'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
            'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
        ];

        prop::collection::vec(prop::sample::select(ALLOWED), 1..=16)
            .prop_map(|chars| chars.into_iter().collect())
    }

    proptest! {
        #[test]
        fn parse_route_output_handles_varied_interface_names(name in interface_name_strategy(), use_ipv6 in any::<bool>()) {
            use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

            let (destination, output) = if use_ipv6 {
                let dest = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1));
                let route = format!(
                    "2001:db8::1 dev {name} src 2001:db8::2 metric 1024 pref medium"
                );
                (dest, route)
            } else {
                let dest = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
                let route = format!(
                    "192.0.2.1 via 198.51.100.1 dev {name} src 198.51.100.2 proto kernel scope link"
                );
                (dest, route)
            };

            let parsed = super::parse_interface_from_route_output(destination, &output)
                .expect("parser should succeed for well-formed output");
            prop_assert_eq!(parsed, name);
        }
    }

    #[test]
    fn parse_route_output_errors_without_device() {
        use std::net::IpAddr;

        let destination = IpAddr::V4("192.0.2.1".parse().unwrap());
        let output = "192.0.2.1 src 10.0.0.2 metric 100";

        let err = super::parse_interface_from_route_output(destination, output)
            .expect_err("missing device should cause an error");

        match err {
            InterfaceError::RouteNotFound { destination: dest } => {
                assert_eq!(dest, destination);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn parse_interface_from_json_extracts_dev() {
        use std::net::IpAddr;
        let destination = IpAddr::V4("8.8.8.8".parse().unwrap());
        let json = r#"[{"dst":"8.8.8.8","gateway":"192.168.0.1","dev":"eth0","prefsrc":"192.168.0.2","flags":[],"uid":1001,"cache":[]}]"#;

        let result = super::parse_interface_from_json(destination, json).expect("parse json");
        assert_eq!(result, "eth0");
    }

    #[test]
    fn parse_interface_from_json_ignores_empty_or_whitespace_dev() {
        use std::net::IpAddr;

        let destination = IpAddr::V4("1.1.1.1".parse().unwrap());
        let json = r#"[{"dst":"1.1.1.1","dev":"   "}]"#;

        let result = super::parse_interface_from_json(destination, json);
        assert!(matches!(result, Err(InterfaceError::RouteNotFound { .. })));
    }

    #[test]
    fn parse_interface_from_json_handles_invalid_json() {
        use std::net::IpAddr;
        let destination = IpAddr::V4("1.1.1.1".parse().unwrap());
        let json = "{ invalid json }";
        let result = super::parse_interface_from_json(destination, json);
        assert!(matches!(
            result,
            Err(InterfaceError::RouteOutputJson { .. })
        ));
    }

    #[test]
    fn parse_interface_from_json_handles_empty_array() {
        use std::net::IpAddr;
        let destination = IpAddr::V4("1.1.1.1".parse().unwrap());
        let json = "[]";
        let result = super::parse_interface_from_json(destination, json);
        assert!(matches!(result, Err(InterfaceError::RouteNotFound { .. })));
    }

    #[test]
    fn parse_interface_from_json_handles_non_array_root() {
        use std::net::IpAddr;
        let destination = IpAddr::V4("1.1.1.1".parse().unwrap());
        let json = "{}";
        let result = super::parse_interface_from_json(destination, json);
        assert!(matches!(result, Err(InterfaceError::RouteNotFound { .. })));
    }

    #[test]
    fn parse_interface_from_json_handles_missing_dev_key() {
        use std::net::IpAddr;
        let destination = IpAddr::V4("1.1.1.1".parse().unwrap());
        let json = r#"[{"dst":"1.1.1.1"}]"#;
        let result = super::parse_interface_from_json(destination, json);
        assert!(matches!(result, Err(InterfaceError::RouteNotFound { .. })));
    }

    #[test]
    fn parse_interface_from_json_handles_null_dev_value() {
        use std::net::IpAddr;
        let destination = IpAddr::V4("1.1.1.1".parse().unwrap());
        let json = r#"[{"dst":"1.1.1.1", "dev": null}]"#;
        let result = super::parse_interface_from_json(destination, json);
        assert!(matches!(result, Err(InterfaceError::RouteNotFound { .. })));
    }

    #[test]
    fn parse_route_output_handles_empty_output() {
        use std::net::IpAddr;
        let destination = IpAddr::V4("192.0.2.1".parse().unwrap());
        let output = "";
        let result = super::parse_interface_from_route_output(destination, output);
        assert!(matches!(result, Err(InterfaceError::RouteNotFound { .. })));
    }

    #[test]
    fn parse_route_output_handles_dev_at_end_of_line() {
        use std::net::IpAddr;
        let destination = IpAddr::V4("192.0.2.1".parse().unwrap());
        // "dev eth0" at the very end
        let output = "192.0.2.1 via 10.0.0.1 dev eth0";
        let result =
            super::parse_interface_from_route_output(destination, output).expect("should parse");
        assert_eq!(result, "eth0");
    }
}
