// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Collection, Error, Request, Window};
use crate::engine::preparation::{Admitted, PreparedPacket};
use crate::route::CachedProvider;
use crate::{Client, clock::Clock, providers::PacketProviders};

impl<P: PacketProviders, K: Clock> Client<P, K> {
    pub(super) fn prepare_exchange(
        &self,
        request: Request,
        operation: &crate::engine::execution::Operation,
    ) -> Result<Prepared, Error> {
        self.check_cancelled()?;
        request.validate()?;
        let Request {
            template,
            send,
            timeout,
            max_template_packets,
            collection,
            stop: _,
        } = request;
        let count = template.expansion_len().map_err(crate::Error::from)?;
        self.prepare_packet_exchange(
            count,
            || {
                let packets = template
                    .expand(max_template_packets)
                    .map_err(crate::Error::from)?;
                Ok(packets.map(|packet| packet.map_err(crate::Error::from)))
            },
            &send,
            timeout,
            collection,
            operation,
            None,
        )
    }

    /// Internal ordered batches share the complete template admission path.
    pub(super) fn prepare_packet_exchange<I>(
        &self,
        expansion_len: usize,
        expand: impl FnOnce() -> Result<I, Error>,
        send: &crate::send::Options,
        timeout: std::time::Duration,
        collection: Collection,
        operation: &crate::engine::execution::Operation,
        mut pinned: Option<&mut Option<crate::route::Plan>>,
    ) -> Result<Prepared, Error>
    where
        I: ExactSizeIterator<Item = Result<packetcraftr_core::packet::Packet, crate::Error>>,
    {
        self.check_cancelled()?;
        collection.validate()?;
        let window = Window::open(&self.clock, timeout, self.cancellation.clone())
            .ok_or_else(|| Error::InvalidRequest {
                field: "timeout",
                message: "cannot be represented by the platform monotonic clock".to_owned(),
            })?
            .with_parent(operation.deadline.clone());
        let packet_count = u64::try_from(expansion_len).unwrap_or(u64::MAX);
        let mut admission = self.admitting_in(send, packet_count, window.deadline(), operation)?;
        if expansion_len == 0 {
            return Err(crate::Error::Template {
                message: "template expanded to no packets".to_owned(),
                source: None,
            }
            .into());
        }
        // Preserve count admission before template validation and expansion.
        let mut expanded_packets = expand()?;
        let routes = CachedProvider::new(self.providers.route());
        let mut admitted: Vec<Admitted> = Vec::with_capacity(expanded_packets.len());
        loop {
            // Expansion allocates, so stop conditions are checked before each packet is pulled.
            admission.check()?;
            let Some(expanded_packet) = expanded_packets.next() else {
                break;
            };
            let packet = expanded_packet?;
            let admitted_packet = admission.admit(packet, &routes)?;
            if let Some(slot) = pinned.as_deref_mut() {
                let expected = slot.get_or_insert_with(|| admitted_packet.plan().clone());
                let actual = admitted_packet.plan();
                if expected.packet_source != actual.packet_source
                    || expected.decision.interface != actual.decision.interface
                    || expected.mode != actual.mode
                {
                    return Err(Error::HeterogeneousRoute);
                }
            }
            if let Some(first_packet) = admitted.first()
                && !first_packet.shares_route_with(&admitted_packet)
            {
                return Err(Error::HeterogeneousRoute);
            }
            admitted.push(admitted_packet);
        }
        let total_bytes = admission.wire_bytes();
        // Neighbor discovery waits until every packet has passed every policy check.
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

pub(crate) struct Prepared {
    pub(crate) cancellation: Option<packetcraftr_core::budget::Cancellation>,
    pub(crate) window: Window,
    pub(crate) collection: Collection,
    pub(crate) packets: Vec<PreparedPacket>,
    pub(crate) packet_count: u64,
    pub(crate) total_bytes: u64,
}
