// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

mod common;
mod icmp;
mod tcp;
mod udp;
mod utils;

use std::net::IpAddr;

use anyhow::Result;
use log::info;

use crate::domain::command::{TracerouteProtocol, TracerouteRequest};
use crate::domain::policy::{
    classify_ip, TrafficMode, TrafficPlan, TrafficPolicy, TrafficPrivilege, TrafficSelection,
    TrafficSelectionValue,
};

use self::common::resolve_destination_with_reason;
use self::icmp::{run_icmp_traceroute_v4, run_icmp_traceroute_v6};
use self::tcp::{run_tcp_traceroute_v4, run_tcp_traceroute_v6};
use self::udp::{run_udp_traceroute_v4, run_udp_traceroute_v6};

#[derive(Debug, Clone)]
pub(crate) struct PreparedTraceroute {
    pub traffic_plan: TrafficPlan,
    pub destination: IpAddr,
    send_delay: Option<std::time::Duration>,
}

pub(crate) fn prepare(
    opts: &TracerouteRequest,
    policy: TrafficPolicy,
) -> Result<PreparedTraceroute> {
    let resolved_destination = resolve_destination_with_reason(&opts.destination)?;
    let destination = resolved_destination.address;
    let mut plan = TrafficPlan::new(TrafficMode::Traceroute, classify_ip(destination));
    plan.target_count = 1;
    plan.port_count = 1;
    plan.estimated_packets = Some(u64::from(opts.max_ttl) * u64::from(opts.probes));
    plan.batch_size = 1;
    plan.rate_per_sec = Some(policy.budget.max_rate_per_sec);
    plan.required_privileges = vec![TrafficPrivilege::RawSocket];
    plan.selection = Some(traceroute_selection(
        destination,
        resolved_destination.reason,
        opts.protocol,
    ));
    Ok(PreparedTraceroute {
        traffic_plan: plan,
        destination,
        send_delay: policy.rate_delay(),
    })
}

fn traceroute_selection(
    destination: IpAddr,
    destination_reason: &'static str,
    protocol: TracerouteProtocol,
) -> TrafficSelection {
    let (source_value, source_reason) = match (destination, protocol) {
        (IpAddr::V4(destination), TracerouteProtocol::Tcp) => (
            common::resolve_source_ipv4(destination)
                .ok()
                .map(|ip| ip.to_string()),
            "route_table",
        ),
        (IpAddr::V6(destination), TracerouteProtocol::Tcp | TracerouteProtocol::Icmp) => (
            common::resolve_source_ipv6(destination)
                .ok()
                .map(|ip| ip.to_string()),
            "route_table",
        ),
        _ => (None, "os_socket_selected"),
    };

    TrafficSelection {
        interface: None,
        source: Some(TrafficSelectionValue {
            value: source_value,
            reason: source_reason.to_string(),
        }),
        destination: Some(TrafficSelectionValue {
            value: Some(destination.to_string()),
            reason: destination_reason.to_string(),
        }),
    }
}

pub(crate) async fn run_prepared(
    opts: &TracerouteRequest,
    prepared: PreparedTraceroute,
) -> Result<()> {
    tokio::task::spawn_blocking({
        let opts = opts.clone();
        move || traceroute_blocking(&opts, prepared.destination, prepared.send_delay)
    })
    .await??;
    Ok(())
}

fn traceroute_blocking(
    opts: &TracerouteRequest,
    destination: IpAddr,
    send_delay: Option<std::time::Duration>,
) -> Result<()> {
    info!(
        "Traceroute destination {} using {:?}",
        destination, opts.protocol
    );

    match destination {
        IpAddr::V4(dest_v4) => match opts.protocol {
            TracerouteProtocol::Udp => run_udp_traceroute_v4(dest_v4, opts, send_delay),
            TracerouteProtocol::Icmp => run_icmp_traceroute_v4(dest_v4, opts, send_delay),
            TracerouteProtocol::Tcp => run_tcp_traceroute_v4(dest_v4, opts, send_delay),
        },
        IpAddr::V6(dest_v6) => match opts.protocol {
            TracerouteProtocol::Udp => run_udp_traceroute_v6(dest_v6, opts, send_delay),
            TracerouteProtocol::Icmp => run_icmp_traceroute_v6(dest_v6, opts, send_delay),
            TracerouteProtocol::Tcp => run_tcp_traceroute_v6(dest_v6, opts, send_delay),
        },
    }
}
