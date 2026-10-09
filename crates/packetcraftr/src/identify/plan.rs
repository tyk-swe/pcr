// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::SocketAddr;

use super::{Error, Request, Transport, engine};
use crate::policy::SocketLimits;

#[derive(Default)]
struct Traffic {
    attempts: u64,
    writing_connections: u64,
    connections: u64,
    messages: u64,
    write_bytes: u64,
    max_request_bytes: u64,
}

/// Conservative bounds for the selected plan, not the unused operation
/// allowance. Responses and deadlines can reduce traffic further at runtime.
pub(super) fn declaration(
    request: &Request,
) -> Result<(Vec<SocketAddr>, SocketLimits, u64), Error> {
    let mut endpoints = Vec::new();
    let mut hosts = BTreeMap::<_, Traffic>::new();
    let limits = request.limits;
    let attempts = limits
        .probe
        .attempts
        .min(limits.host.attempts)
        .min(limits.operation.attempts);
    for endpoint in &request.endpoints {
        if request
            .exclusions
            .excludes(endpoint.transport, endpoint.address.port())
        {
            continue;
        }
        let mut admitted = false;
        for probe in request.corpus.probes.iter().filter(|probe| {
            probe.transport == endpoint.transport && probe.intensity <= request.intensity
        }) {
            let bytes = engine::request_bytes(probe, 1)?.len() as u64;
            if [
                limits.operation,
                limits.host,
                limits.connection,
                limits.probe,
            ]
            .iter()
            .any(|limit| bytes > limit.write_bytes)
            {
                continue;
            }
            admitted = true;
            let host = hosts.entry(engine::host_key(endpoint.address)).or_default();
            host.attempts += attempts;
            if endpoint.transport == Transport::Tcp {
                host.connections += attempts;
            }
            if bytes != 0 {
                if endpoint.transport == Transport::Tcp {
                    host.writing_connections += attempts;
                }
                host.messages += attempts;
                host.write_bytes += (bytes * attempts).min(limits.probe.write_bytes);
                host.max_request_bytes = host.max_request_bytes.max(bytes);
            }
        }
        if admitted {
            endpoints.push(endpoint.address);
        }
    }
    let mut total = Traffic::default();
    for host in hosts.values() {
        total.attempts += host.attempts.min(limits.host.attempts);
        total.writing_connections += host.writing_connections.min(limits.host.attempts);
        total.connections += host.connections.min(limits.host.attempts);
        total.messages += host.messages.min(limits.host.attempts);
        total.write_bytes += host
            .write_bytes
            .min(limits.host.write_bytes)
            .min(host.max_request_bytes * limits.host.attempts);
        total.max_request_bytes = total.max_request_bytes.max(host.max_request_bytes);
    }
    // Every admitted attempt costs one unit; only a TCP attempt that writes a
    // request can cost a second. Connection/message maxima are independent,
    // but their sum must also respect the shared host and operation attempts.
    let admitted_attempts = total.attempts.min(limits.operation.attempts);
    let units = admitted_attempts + total.writing_connections.min(admitted_attempts);
    Ok((
        endpoints,
        SocketLimits::new(
            total.connections.min(limits.operation.attempts),
            total.messages.min(limits.operation.attempts),
            total
                .write_bytes
                .min(limits.operation.write_bytes)
                .min(total.max_request_bytes * limits.operation.attempts),
        ),
        units,
    ))
}
