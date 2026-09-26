// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Admission and preparation of the complete exchange before capture starts.

use super::{Collection, Error, Request, Window};
use crate::preparation::{Admitted, PreparedPacket};
use crate::route::CachedProvider;
use crate::{Client, clock::Clock, providers::Providers};

impl<P: Providers, K: Clock> Client<P, K> {
    pub(super) fn prepare_exchange(&self, request: Request) -> Result<Prepared, Error> {
        self.check_cancelled()?;
        request.validate()?;
        let Request {
            template,
            send,
            timeout,
            max_template_packets,
            collection,
        } = request;
        let window =
            Window::open(&self.clock, timeout, self.cancellation.clone()).ok_or_else(|| {
                Error::InvalidRequest {
                    field: "timeout",
                    message: "cannot be represented by the platform monotonic clock".to_owned(),
                }
            })?;
        let expansion_len = template.expansion_len().map_err(crate::Error::from)?;
        let packet_count = u64::try_from(expansion_len).unwrap_or(u64::MAX);
        let mut admission = self.admitting(&send, packet_count, window.deadline())?;
        if expansion_len == 0 {
            return Err(crate::Error::Template {
                message: "template expanded to no packets".to_owned(),
                source: None,
            }
            .into());
        }
        let mut expanded_packets = template
            .expand(max_template_packets)
            .map_err(crate::Error::from)?;
        let routes = CachedProvider::new(self.providers.route());
        let mut admitted: Vec<Admitted> = Vec::with_capacity(expanded_packets.len());
        loop {
            // Expansion allocates, so the operation's stop conditions are
            // checked before each packet is pulled.
            admission.check()?;
            let Some(expanded_packet) = expanded_packets.next() else {
                break;
            };
            let packet = expanded_packet.map_err(crate::Error::from)?;
            let admitted_packet = admission.admit(packet, &routes)?;
            if let Some(first_packet) = admitted.first()
                && !first_packet.shares_route_with(&admitted_packet)
            {
                return Err(Error::HeterogeneousRoute);
            }
            admitted.push(admitted_packet);
        }
        let total_bytes = admission.wire_bytes();
        // Neighbor discovery is delayed until every packet has passed packet,
        // route, permissive-build, and aggregate byte-policy checks.
        let discovery = admission.discover();
        let packets = admitted
            .into_iter()
            .map(|packet| discovery.materialize(packet))
            .collect::<Result<Vec<_>, _>>()?;
        drop(discovery);

        Ok(Prepared {
            cancellation: self.cancellation.clone(),
            window,
            collection,
            packets,
            packet_count,
            total_bytes,
        })
    }
}

/// Every packet of one exchange, admitted and materialized, with the window
/// and collection bounds its capture runs under.
pub(crate) struct Prepared {
    pub(crate) cancellation: Option<packetcraftr_core::budget::Cancellation>,
    pub(crate) window: Window,
    pub(crate) collection: Collection,
    pub(crate) packets: Vec<PreparedPacket>,
    pub(crate) packet_count: u64,
    pub(crate) total_bytes: u64,
}
