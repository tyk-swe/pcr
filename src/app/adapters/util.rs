// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use crate::domain::spec::{PacketSpec, TransportSpec};
use crate::engine::error::EngineError;
use crate::engine::ports::{PortFuture, PrivilegeChecker, TargetResolver};

#[derive(Debug, Default)]
pub(crate) struct SystemTargetResolverAdapter;

impl TargetResolver for SystemTargetResolverAdapter {
    fn resolve_target_ip(
        &self,
        target: String,
        prefer_ipv6: Option<bool>,
    ) -> PortFuture<std::net::IpAddr> {
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                crate::util::net::resolve_target_ip(&target, prefer_ipv6).map_err(|source| {
                    anyhow::anyhow!("resolve hostname failed: host='{target}': {source}")
                })
            })
            .await
            .map_err(|source| anyhow::anyhow!("target resolution task failed: {source}"))?
        })
    }
}

#[derive(Debug, Default)]
pub(crate) struct RawSocketPrivilegeChecker;

impl PrivilegeChecker for RawSocketPrivilegeChecker {
    fn check_packet_send(&self, spec: Arc<PacketSpec>) -> PortFuture<()> {
        Box::pin(async move {
            tokio::task::spawn_blocking(move || check_privileges(spec.as_ref()))
                .await
                .map_err(|source| anyhow::anyhow!("privilege check task failed: {source}"))?
                .map_err(anyhow::Error::from)
        })
    }
}

fn check_privileges(spec: &PacketSpec) -> Result<(), EngineError> {
    let requires_raw = spec.layer2.source.is_some()
        || spec.layer2.destination.is_some()
        || matches!(
            &spec.transport,
            TransportSpec::Tcp(_)
                | TransportSpec::Udp(_)
                | TransportSpec::Icmp(_)
                | TransportSpec::Icmpv6(_)
        )
        || spec.transmit.is_layer3();

    if requires_raw {
        crate::util::privileges::assert_raw_socket_capability()
            .map_err(|e| EngineError::InsufficientPrivileges(e.into()))?;
    }
    Ok(())
}
