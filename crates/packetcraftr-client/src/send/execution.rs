// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::*;

impl<R, N, I> Client<R, N, I>
where
    R: RouteProvider,
    N: NeighborResolver,
    I: PacketIo,
{
    pub fn send(&self, packet: Packet, options: SendOptions) -> Result<SendReport, ClientError> {
        let started = Instant::now();
        self.policy.authorize_operation(1, 0)?;
        let plan = self.plan(&packet, options.destination, &options.plan)?;
        let mut packet_to_send = packet;
        materialize_network_fields(&mut packet_to_send, &plan)?;
        materialize_link_structure(&mut packet_to_send, &plan)?;
        let builder = Builder::new(Arc::clone(&self.registry));
        let context = build_context(&plan);
        // Validate all packet fields before neighbor discovery emits traffic.
        let mut preliminary = builder.build(
            packet_to_send.clone(),
            context.clone(),
            options.build.clone(),
        )?;
        validate_mtu(&preliminary, plan.route.mtu)?;
        self.authorize_built(&preliminary, options.allow_permissive_live)?;
        self.authorize_final_wire(&preliminary, &plan)?;
        self.policy
            .authorize_operation(1, preliminary.bytes.len() as u64)?;
        let preliminary_len = preliminary.bytes.len();
        let route = self.planner.materialize(plan, &self.neighbors)?;
        let link_changed = materialize_link_fields(&mut packet_to_send, &route)?;
        let built = if link_changed {
            let built = if patch_builtin_ethernet(&self.registry, &mut preliminary, &packet_to_send)
            {
                preliminary
            } else {
                builder.build(packet_to_send, context, options.build)?
            };
            require_fixed_width_link_materialization(preliminary_len, built.bytes.len())?;
            self.authorize_built(&built, options.allow_permissive_live)?;
            self.authorize_final_wire(&built, &route.plan)?;
            self.policy
                .authorize_operation(1, built.bytes.len() as u64)?;
            built
        } else {
            preliminary
        };
        // Link-layer synthesis is already included in the exact build. The
        // typed frame selects the matching native provider boundary.
        let io_report = self
            .io
            .send(TransmissionFrame::try_new(&built.bytes, &route)?)?;
        validate_send_report(&built.bytes, &io_report)?;
        let bytes_sent = io_report.bytes_sent;
        let wire_bytes = io_report.wire_bytes;
        Ok(SendReport {
            built,
            route,
            wire_bytes,
            stats: Stats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes: bytes_sent as u64,
                elapsed: started.elapsed(),
                capture: CaptureStatistics::default(),
            },
        })
    }

    pub(crate) fn authorize_built(
        &self,
        built: &BuiltPacket,
        allow_permissive_live: bool,
    ) -> Result<(), ClientError> {
        self.policy.authorize_packet_destinations(&built.packet)?;
        if built.requires_live_opt_in {
            if !allow_permissive_live {
                return Err(ClientError::PermissiveLiveOptInRequired);
            }
            if !self.policy.allow_permissive_packets {
                return Err(TrafficPolicyError::PermissivePacket.into());
            }
        }
        Ok(())
    }

    pub(crate) fn authorize_final_wire(
        &self,
        built: &BuiltPacket,
        route: &PlannedRoute,
    ) -> Result<(), ClientError> {
        let link_type = match route.mode {
            LinkMode::Layer2 => route.route.link_type,
            LinkMode::Layer3 => LinkType::RAW,
            LinkMode::Auto => return Err(LiveIoError::UnresolvedLinkMode.into()),
        };
        let frame = Frame::new(
            std::time::SystemTime::UNIX_EPOCH,
            link_type,
            built.bytes.clone(),
        )
        .map_err(|error| TrafficPolicyError::InvalidPacketSemantics {
            reason: error.to_string(),
        })?;
        static REGISTRY: OnceLock<Result<Arc<ProtocolRegistry>, String>> = OnceLock::new();
        let registry = REGISTRY
            .get_or_init(|| {
                packetcraftr_protocol::builtin::registry()
                    .map(Arc::new)
                    .map_err(|error| error.to_string())
            })
            .as_ref()
            .map_err(|reason| TrafficPolicyError::InvalidPacketSemantics {
                reason: reason.clone(),
            })?;
        let decoded = Dissector::new(Arc::clone(registry))
            .decode(frame, DecodeOptions::default())
            .map_err(|error| TrafficPolicyError::InvalidPacketSemantics {
                reason: error.to_string(),
            })?;
        self.policy.authorize_packet_destinations(&decoded.packet)?;
        Ok(())
    }
}

pub(crate) fn ensure_preparation_deadline(deadline: Instant) -> Result<(), ClientError> {
    if deadline.checked_duration_since(Instant::now()).is_none() {
        return Err(LiveIoError::DeadlineExceeded {
            operation: "preparing the exchange",
        }
        .into());
    }
    Ok(())
}
