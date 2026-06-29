// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use thiserror::Error;

use crate::engine::request::PacketRequest;

pub type ResolveResult<T> = std::result::Result<T, ResolveError>;

pub trait TargetResolver {
    fn resolve_target_ip(&self, target: &str, prefer_ipv6: Option<bool>) -> ResolveResult<IpAddr>;
}

#[derive(Debug, Error)]
pub enum ResolveError {
    #[error("resolve hostname failed: host='{host}': {message}")]
    HostnameResolution { host: String, message: String },
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemTargetResolver;

impl TargetResolver for SystemTargetResolver {
    fn resolve_target_ip(&self, target: &str, prefer_ipv6: Option<bool>) -> ResolveResult<IpAddr> {
        crate::util::net::resolve_target_ip(target, prefer_ipv6).map_err(|err| {
            ResolveError::HostnameResolution {
                host: target.to_string(),
                message: err.to_string(),
            }
        })
    }
}

pub fn resolve_packet_request<R>(
    mut request: PacketRequest,
    resolver: &R,
) -> ResolveResult<PacketRequest>
where
    R: TargetResolver + ?Sized,
{
    if request.destination.destination_ip.is_none() {
        if let Some(target) = request.destination.destination.as_deref() {
            let trimmed = target.trim();
            if !trimmed.is_empty() && trimmed.parse::<IpAddr>().is_err() {
                let resolved = resolver.resolve_target_ip(trimmed, request.prefer_ipv6_hint())?;
                request.destination.resolved_destination = Some(resolved);
            }
        }
    }

    Ok(request)
}
