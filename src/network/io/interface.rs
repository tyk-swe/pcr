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

pub(crate) trait InterfaceProvider {
    fn interfaces(&self) -> Vec<NetworkInterface>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InterfaceSelectionReason {
    ExplicitInterface,
    RouteTable,
    Heuristic,
}

#[derive(Debug, Clone)]
pub(crate) struct InterfaceSelection {
    pub interface: NetworkInterface,
    pub reason: InterfaceSelectionReason,
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct SystemInterfaceProvider;

impl InterfaceProvider for SystemInterfaceProvider {
    fn interfaces(&self) -> Vec<NetworkInterface> {
        datalink::interfaces()
    }
}

#[derive(Debug, Error)]
pub(crate) enum InterfaceError {
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

#[cfg(any(feature = "pcap", feature = "scan"))]
pub(crate) fn find_interface(name: Option<&str>) -> Result<NetworkInterface> {
    Ok(find_interface_selection_with_provider_impl(name, &SystemInterfaceProvider)?.interface)
}

pub(crate) fn find_interface_selection(name: Option<&str>) -> Result<InterfaceSelection> {
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

pub(crate) fn find_interface_for_destination_selection(
    destination: IpAddr,
) -> Result<InterfaceSelection> {
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
