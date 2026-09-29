// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::errors::CliError;
use packetcraftr_core::{
    error::Kind,
    packet::MacAddress,
    transform::{HeaderRewrite, VlanRewrite},
};
use std::net::IpAddr;

#[derive(Clone, Debug, Default, clap::Args)]
pub(crate) struct HeaderRewriteArgs {
    /// Replace the outer Ethernet source MAC address.
    #[arg(long, value_parser = mac)]
    pub(crate) source_mac: Option<[u8; 6]>,
    /// Replace the outer Ethernet destination MAC address.
    #[arg(long, value_parser = mac)]
    pub(crate) destination_mac: Option<[u8; 6]>,
    /// Replace the IP source address.
    #[arg(long)]
    pub(crate) source_ip: Option<IpAddr>,
    /// Replace the IP destination address.
    #[arg(long)]
    pub(crate) destination_ip: Option<IpAddr>,
    /// Replace the TCP or UDP source port.
    #[arg(long)]
    pub(crate) source_port: Option<u16>,
    /// Replace the TCP or UDP destination port.
    #[arg(long)]
    pub(crate) destination_port: Option<u16>,
    /// Replace the outer VLAN stack; repeat VID or TPID:VID[:PRIORITY[:DEI]].
    #[arg(long = "vlan", value_parser = vlan, conflicts_with = "strip_vlans")]
    #[allow(rustdoc::broken_intra_doc_links)]
    pub(crate) vlans: Vec<VlanRewrite>,
    /// Remove the outer VLAN stack.
    #[arg(long)]
    pub(crate) strip_vlans: bool,
}

impl HeaderRewriteArgs {
    pub(crate) fn core(&self) -> HeaderRewrite {
        HeaderRewrite {
            source_mac: self.source_mac,
            destination_mac: self.destination_mac,
            source_ip: self.source_ip,
            destination_ip: self.destination_ip,
            source_port: self.source_port,
            destination_port: self.destination_port,
            vlans: if self.strip_vlans {
                Some(Vec::new())
            } else if !self.vlans.is_empty() {
                Some(self.vlans.clone())
            } else {
                None
            },
        }
    }
}

fn mac(value: &str) -> Result<[u8; 6], CliError> {
    value
        .parse::<MacAddress>()
        .map(|address| address.0)
        .map_err(|error| CliError::caused(Kind::Usage, &error))
}

fn vlan(value: &str) -> Result<VlanRewrite, CliError> {
    fn number(value: &str) -> Result<u16, CliError> {
        match value.strip_prefix("0x") {
            Some(digits) if digits.bytes().all(|digit| digit.is_ascii_hexdigit()) => {
                u16::from_str_radix(digits, 16).ok()
            }
            Some(_) => None,
            None => value.parse().ok(),
        }
        .ok_or_else(|| CliError::new(Kind::Usage, "invalid VLAN number"))
    }
    let parts: Vec<_> = value.split(':').collect();
    let tag = match parts.as_slice() {
        [id] => VlanRewrite {
            ether_type: 0x8100,
            identifier: number(id)?,
            priority: 0,
            drop_eligible: false,
        },
        [kind, id, rest @ ..] if rest.len() <= 2 => {
            let priority = rest.first().map(|s| number(s)).transpose()?.unwrap_or(0);
            let dei = rest.get(1).map(|s| number(s)).transpose()?.unwrap_or(0);
            if priority > 7 || dei > 1 {
                return Err(CliError::new(
                    Kind::Usage,
                    "VLAN priority must be 0..=7 and DEI 0 or 1",
                ));
            }
            VlanRewrite {
                ether_type: number(kind)?,
                identifier: number(id)?,
                priority: priority as u8,
                drop_eligible: dei == 1,
            }
        }
        _ => {
            return Err(CliError::new(
                Kind::Usage,
                "use VID or TPID:VID[:PRIORITY[:DEI]]",
            ));
        }
    };
    HeaderRewrite {
        vlans: Some(vec![tag]),
        ..Default::default()
    }
    .validate()
    .map_err(CliError::classified)?;
    Ok(tag)
}
