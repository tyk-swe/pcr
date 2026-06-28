use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{anyhow, Context, Result};
use pnet::datalink;
use pnet::ipnetwork::IpNetwork;

use crate::util::error::operation_failed;

/// Attempts to determine the source IP address that the OS would use to reach the given destination.
///
/// This is done by creating a UDP socket and connecting it to the destination. No packets are sent.
/// The `port` argument is used for the connection but does not need to be open on the remote host.
pub fn discover_source_ip(destination: IpAddr, port: u16) -> Result<IpAddr> {
    discover_impl(destination, port)
}

pub fn discover_source_ipv4(destination: Ipv4Addr, port: u16) -> Result<Ipv4Addr> {
    match discover_impl(IpAddr::V4(destination), port)? {
        IpAddr::V4(addr) => Ok(addr),
        other => Err(anyhow!(
            "source IP discovery returned {} for IPv4 destination {}",
            other,
            destination
        )),
    }
}

pub fn discover_source_ipv6(destination: Ipv6Addr, port: u16) -> Result<Ipv6Addr> {
    match discover_impl(IpAddr::V6(destination), port)? {
        IpAddr::V6(addr) => Ok(addr),
        other => Err(anyhow!(
            "source IP discovery returned {} for IPv6 destination {}",
            other,
            destination
        )),
    }
}

pub fn resolve_interface_or_ip_override(
    interface: Option<&str>,
    target: IpAddr,
) -> Result<Option<IpAddr>> {
    let Some(spec) = interface.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };

    if let Ok(addr) = spec.parse::<IpAddr>() {
        if is_matching_ip_family(addr, target) {
            return Ok(Some(addr));
        }
        return Err(anyhow!(
            "interface override {} does not match target address family",
            addr
        ));
    }

    let iface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == spec)
        .ok_or_else(|| anyhow!("interface {spec} not found"))?;

    let family = if target.is_ipv4() { "IPv4" } else { "IPv6" };
    let candidate = match target {
        IpAddr::V4(_) => iface.ips.iter().find_map(|network| match network {
            IpNetwork::V4(v4) => Some(IpAddr::V4(v4.ip())),
            _ => None,
        }),
        IpAddr::V6(_) => iface.ips.iter().find_map(|network| match network {
            IpNetwork::V6(v6) => Some(IpAddr::V6(v6.ip())),
            _ => None,
        }),
    };

    candidate
        .map(Some)
        .ok_or_else(|| anyhow!("interface {spec} does not have a {family} address"))
}

pub fn source_override_ipv4(source_override: Option<IpAddr>) -> Result<Option<Ipv4Addr>> {
    source_override
        .map(|ip| match ip {
            IpAddr::V4(v4) => Ok(v4),
            IpAddr::V6(_) => Err(anyhow!(
                "IPv6 interface override cannot be used for IPv4 target"
            )),
        })
        .transpose()
}

pub fn source_override_ipv6(source_override: Option<IpAddr>) -> Result<Option<Ipv6Addr>> {
    source_override
        .map(|ip| match ip {
            IpAddr::V6(v6) => Ok(v6),
            IpAddr::V4(_) => Err(anyhow!(
                "IPv4 interface override cannot be used for IPv6 target"
            )),
        })
        .transpose()
}

fn is_matching_ip_family(candidate: IpAddr, target: IpAddr) -> bool {
    (candidate.is_ipv4() && target.is_ipv4()) || (candidate.is_ipv6() && target.is_ipv6())
}

fn discover_impl(destination: IpAddr, port: u16) -> Result<IpAddr> {
    let (bind_ip, family) = match destination {
        IpAddr::V4(_) => (IpAddr::V4(Ipv4Addr::UNSPECIFIED), "IPv4"),
        IpAddr::V6(_) => (IpAddr::V6(Ipv6Addr::UNSPECIFIED), "IPv6"),
    };

    let bind_addr = (bind_ip, 0);
    let socket = std::net::UdpSocket::bind(bind_addr).with_context(|| {
        operation_failed(
            &format!("bind socket for {} source discovery", family),
            format!("addr={bind_addr:?}"),
        )
    })?;

    socket.connect((destination, port)).with_context(|| {
        operation_failed(
            &format!("determine {} source address", family),
            format!("destination={} port={}", destination, port),
        )
    })?;

    let local_addr = socket.local_addr()?;
    match (destination, local_addr) {
        (IpAddr::V4(_), SocketAddr::V4(addr)) => Ok(IpAddr::V4(*addr.ip())),
        (IpAddr::V6(_), SocketAddr::V6(addr)) => Ok(IpAddr::V6(*addr.ip())),
        (IpAddr::V4(_), _) => Err(anyhow!(
            "unexpected local address family for IPv4 source discovery"
        )),
        (IpAddr::V6(_), _) => Err(anyhow!(
            "unexpected local address family for IPv6 source discovery"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "net_integration")]
    fn is_permission_error(err: &anyhow::Error) -> bool {
        err.chain().any(|cause| {
            if let Some(io_err) = cause.downcast_ref::<std::io::Error>() {
                return io_err.kind() == std::io::ErrorKind::PermissionDenied;
            }
            let message = cause.to_string();
            message.contains("Operation not permitted") || message.contains("permission denied")
        })
    }

    #[cfg(feature = "net_integration")]
    #[ignore = "requires local UDP sockets and OS route/source selection"]
    #[test]
    fn discover_source_ipv4_localhost() {
        match discover_source_ipv4(Ipv4Addr::LOCALHOST, 80) {
            Ok(addr) => assert_eq!(addr, Ipv4Addr::LOCALHOST),
            Err(err) if is_permission_error(&err) => {}
            Err(err) => panic!("unexpected source discovery error: {err}"),
        }
    }

    #[cfg(feature = "net_integration")]
    #[ignore = "requires local IPv6 UDP sockets and OS route/source selection"]
    #[test]
    fn discover_source_ipv6_localhost() {
        // CI environments might not support IPv6, so we only assert if we can bind v6
        if let Ok(socket) = std::net::UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)) {
            drop(socket);
            match discover_source_ipv6(Ipv6Addr::LOCALHOST, 80) {
                Ok(addr) => assert_eq!(addr, Ipv6Addr::LOCALHOST),
                Err(err) if is_permission_error(&err) => {}
                Err(err) => panic!("unexpected source discovery error: {err}"),
            }
        }
    }

    #[test]
    fn resolve_interface_override_none_returns_none() {
        let result =
            resolve_interface_or_ip_override(None, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
                .expect("none should succeed");
        assert!(result.is_none());
    }

    #[test]
    fn resolve_interface_override_accepts_matching_ip_literal() {
        let override_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let result = resolve_interface_or_ip_override(Some("192.0.2.10"), override_ip)
            .expect("matching IP literal should work");
        assert_eq!(result, Some(override_ip));
    }

    #[test]
    fn resolve_interface_override_rejects_mismatched_family() {
        let err =
            resolve_interface_or_ip_override(Some("::1"), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
                .expect_err("family mismatch should fail");
        assert!(
            err.to_string()
                .contains("does not match target address family"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn source_override_helpers_validate_family() {
        let v4 = source_override_ipv4(Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))))
            .expect("v4 override should succeed");
        assert_eq!(v4, Some(Ipv4Addr::new(203, 0, 113, 7)));

        let v6 = source_override_ipv6(Some(IpAddr::V6(Ipv6Addr::LOCALHOST)))
            .expect("v6 override should succeed");
        assert_eq!(v6, Some(Ipv6Addr::LOCALHOST));

        let v4_err = source_override_ipv4(Some(IpAddr::V6(Ipv6Addr::LOCALHOST)))
            .expect_err("mismatch should fail");
        assert!(v4_err
            .to_string()
            .contains("cannot be used for IPv4 target"));

        let v6_err = source_override_ipv6(Some(IpAddr::V4(Ipv4Addr::LOCALHOST)))
            .expect_err("mismatch should fail");
        assert!(v6_err
            .to_string()
            .contains("cannot be used for IPv6 target"));
    }
}
