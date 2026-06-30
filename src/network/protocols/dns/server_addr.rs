// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use anyhow::{anyhow, Result};

pub(crate) fn resolve_dns_server_address(server: &str) -> Result<String> {
    let server = server.trim();

    if server.is_empty() {
        return Err(anyhow!("DNS server address cannot be empty"));
    }

    // Check if it parses as SocketAddr (e.g., "1.2.3.4:53") or IpAddr (e.g., "1.2.3.4")
    if SocketAddr::from_str(server).is_ok() {
        return Ok(server.to_string());
    }

    if let Ok(ip) = IpAddr::from_str(server) {
        return match ip {
            IpAddr::V4(_) => Ok(format!("{}:53", server)),
            IpAddr::V6(_) => Ok(format!("[{}]:53", server)),
        };
    }

    // Handle [ipv6] without port case
    if server.starts_with('[') && server.ends_with(']') {
        return Ok(format!("{}:53", server));
    }

    // Handle cases with multiple colons (IPv6-like)
    if server.matches(':').count() > 1 {
        // Try to split the last part as port
        if let Some((ip_part, port_part)) = server.rsplit_once(':') {
            // Check if the left part is a valid IPv6 and right part is a valid port
            if IpAddr::from_str(ip_part).is_ok() && port_part.parse::<u16>().is_ok() {
                return Ok(format!("[{}]:{}", ip_part, port_part));
            }
        }
        return Err(anyhow!("Invalid DNS server address format: {}", server));
    }

    // Fallback for hostnames or other formats
    if server.contains(':') {
        // Validate port if present
        if let Some((_, port_str)) = server.rsplit_once(':') {
            if port_str.parse::<u16>().is_err() {
                return Err(anyhow!("Invalid port number in address: {}", server));
            }
        }
        // Assume it has a port if it contains a colon
        // e.g., "dns.google:53"
        Ok(server.to_string())
    } else {
        // e.g., "dns.google"
        Ok(format!("{}:53", server))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_dns_server_address_adds_default_ports() {
        assert_eq!(resolve_dns_server_address("1.1.1.1").unwrap(), "1.1.1.1:53");
        assert_eq!(
            resolve_dns_server_address("2001:4860:4860::8888").unwrap(),
            "[2001:4860:4860::8888]:53"
        );
        assert_eq!(
            resolve_dns_server_address("dns.example").unwrap(),
            "dns.example:53"
        );
    }

    #[test]
    fn resolve_dns_server_address_preserves_socket_addresses() {
        assert_eq!(
            resolve_dns_server_address("1.1.1.1:5353").unwrap(),
            "1.1.1.1:5353"
        );
        assert_eq!(
            resolve_dns_server_address("[2001:4860:4860::8888]:5353").unwrap(),
            "[2001:4860:4860::8888]:5353"
        );
    }

    #[test]
    fn resolve_dns_server_address_treats_unbracketed_ipv6_like_value_as_ip() {
        assert_eq!(
            resolve_dns_server_address("2001:4860:4860::8888:5353").unwrap(),
            "[2001:4860:4860::8888:5353]:53"
        );
    }

    #[test]
    fn resolve_dns_server_address_rejects_empty_and_invalid_ports() {
        assert!(resolve_dns_server_address(" ").is_err());
        assert!(resolve_dns_server_address("dns.example:notaport").is_err());
    }

    #[test]
    fn resolve_dns_server_address_rejects_malformed_ipv6_like_input() {
        assert!(resolve_dns_server_address("2001:db8::1:99999").is_err());
    }
}
