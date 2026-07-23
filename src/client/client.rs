use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::net::{
    Error as LiveIoError,
    capture::CaptureStatistics,
    exchange::ExchangeIo,
    route::{
        InterfaceId, NeighborResolver, PlanOptions, PlannedRoute, RouteDecision, RoutePlanner,
        RouteProvider,
    },
    transmit::{PacketIo, TransmissionFrame},
};
use crate::packet::{
    Packet,
    build::{Builder, BuiltPacket},
    registry::ProtocolRegistry,
    semantics::BuiltinProtocol,
    template::PacketTemplate,
};

use super::exchange::{
    ExchangeOptions, ExchangeResult, ExchangeTransaction, PlannedExchangePacket, PreparedExchange,
    PreparedExchangePacket, WorkflowResponseMatcher,
};
use super::helpers::{
    build_context, materialize_link_fields, materialize_link_structure, materialize_network_fields,
    patch_builtin_ethernet, require_fixed_width_link_materialization, validate_mtu,
    validate_send_report,
};
use super::policy::{TrafficPolicy, TrafficPolicyError};
use super::send::{ClientError, SendOptions, SendReport};
use super::stats::OperationStats;
use super::target::{
    HostnameResolver, IpVersion, LiveTarget, ResolvedTarget, TargetResolutionError,
};

/// High-level composition of packet construction, passive route planning,
/// explicit neighbor materialization, policy, and packet I/O.
#[derive(Debug)]
pub struct Client<R, N, I> {
    registry: Arc<ProtocolRegistry>,
    routes: R,
    neighbors: N,
    io: I,
    policy: TrafficPolicy,
    planner: RoutePlanner,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum ExchangeRouteLookupKey {
    Lookup {
        destination: IpAddr,
        interface_hint: Option<InterfaceId>,
    },
    LookupWithPreferences {
        destination: IpAddr,
        interface_hint: Option<InterfaceId>,
        preferred_source: Option<IpAddr>,
    },
    Interface {
        interface: InterfaceId,
    },
}

/// Memoizes passive route decisions for one exchange without retaining an
/// operating-system route snapshot beyond that operation.
struct ExchangeRouteProvider<'a, R> {
    inner: &'a R,
    decisions: Mutex<HashMap<ExchangeRouteLookupKey, Option<RouteDecision>>>,
}

impl<'a, R: RouteProvider> ExchangeRouteProvider<'a, R> {
    fn new(inner: &'a R) -> Self {
        Self {
            inner,
            decisions: Mutex::new(HashMap::new()),
        }
    }

    fn get_or_lookup(
        &self,
        key: ExchangeRouteLookupKey,
        lookup: impl FnOnce() -> Result<Option<RouteDecision>, R::Error>,
    ) -> Result<Option<RouteDecision>, R::Error> {
        let cached = self
            .decisions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&key)
            .cloned();
        if let Some(decision) = cached {
            return Ok(decision);
        }

        let decision = lookup()?;
        self.decisions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(key, decision.clone());
        Ok(decision)
    }
}

impl<R: RouteProvider> RouteProvider for ExchangeRouteProvider<'_, R> {
    type Error = R::Error;

    fn lookup(
        &self,
        destination: IpAddr,
        interface_hint: Option<&InterfaceId>,
    ) -> Result<RouteDecision, Self::Error> {
        let key = ExchangeRouteLookupKey::Lookup {
            destination,
            interface_hint: interface_hint.cloned(),
        };
        Ok(self
            .get_or_lookup(key, || {
                self.inner.lookup(destination, interface_hint).map(Some)
            })?
            .expect("route provider lookup always returns a decision"))
    }

    fn lookup_with_preferences(
        &self,
        destination: IpAddr,
        interface_hint: Option<&InterfaceId>,
        preferred_source: Option<IpAddr>,
    ) -> Result<RouteDecision, Self::Error> {
        let key = ExchangeRouteLookupKey::LookupWithPreferences {
            destination,
            interface_hint: interface_hint.cloned(),
            preferred_source,
        };
        Ok(self
            .get_or_lookup(key, || {
                self.inner
                    .lookup_with_preferences(destination, interface_hint, preferred_source)
                    .map(Some)
            })?
            .expect("route provider lookup always returns a decision"))
    }

    fn lookup_interface(
        &self,
        interface: &InterfaceId,
    ) -> Result<Option<RouteDecision>, Self::Error> {
        let key = ExchangeRouteLookupKey::Interface {
            interface: interface.clone(),
        };
        self.get_or_lookup(key, || self.inner.lookup_interface(interface))
    }

    fn classify_error(&self, error: &Self::Error) -> crate::error::Classification {
        self.inner.classify_error(error)
    }
}

impl<R, N, I> Client<R, N, I>
where
    R: RouteProvider,
    N: NeighborResolver,
    I: PacketIo,
{
    pub fn new(
        registry: Arc<ProtocolRegistry>,
        routes: R,
        neighbors: N,
        io: I,
        policy: TrafficPolicy,
    ) -> Self {
        Self {
            registry,
            routes,
            neighbors,
            io,
            policy,
            planner: RoutePlanner,
        }
    }

    pub fn registry(&self) -> &Arc<ProtocolRegistry> {
        &self.registry
    }

    /// Resolve and authorize a declared destination before passive route
    /// planning. A denied hostname never reaches `resolver`; if any resolved
    /// address is denied, no route-provider method is called.
    pub fn plan_target<H: HostnameResolver>(
        &self,
        packet: &Packet,
        target: &LiveTarget,
        resolver: &H,
        options: &PlanOptions,
    ) -> Result<(ResolvedTarget, PlannedRoute), ClientError> {
        let resolved = self.policy.resolve_target(target, resolver)?;
        let packet_ip_version = packet
            .iter()
            .find_map(|layer| match BuiltinProtocol::of(layer) {
                Some(BuiltinProtocol::Ipv4) => Some(IpVersion::V4),
                Some(BuiltinProtocol::Ipv6) => Some(IpVersion::V6),
                _ => None,
            });
        let selected = match packet_ip_version {
            Some(version) => resolved.address_for_version(version).ok_or(
                TargetResolutionError::AddressFamilyUnavailable {
                    family: version.label(),
                },
            )?,
            None => resolved.selected_address(),
        };
        let plan = self.plan(packet, Some(selected), options)?;
        Ok((resolved, plan))
    }

    /// Passive dry planning: route/source/interface lookup only.
    pub fn plan(
        &self,
        packet: &Packet,
        destination: Option<IpAddr>,
        options: &PlanOptions,
    ) -> Result<PlannedRoute, ClientError> {
        self.plan_with_provider(packet, destination, options, &self.routes, None)
    }

    fn plan_with_provider<P: RouteProvider>(
        &self,
        packet: &Packet,
        destination: Option<IpAddr>,
        options: &PlanOptions,
        provider: &P,
        deadline: Option<Instant>,
    ) -> Result<PlannedRoute, ClientError> {
        if let Some(destination) = destination {
            self.policy.authorize_destination(destination)?;
        }
        // Authorize every declared outer and SRH destination before the route
        // provider can observe one. The completed plan is checked again below
        // so provider-derived selections cannot bypass policy either.
        self.policy.authorize_packet_destinations(packet)?;
        if let Some(deadline) = deadline {
            ensure_preparation_deadline(deadline)?;
        }
        let plan = self.planner.plan(packet, destination, options, provider)?;
        for destination in &plan.visited_destinations {
            self.policy.authorize_destination(*destination)?;
        }
        Ok(plan)
    }

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
        let wire_bytes = io_report
            .wire_bytes
            .or_else(|| route.plan.synthesized_ethernet.then(|| built.bytes.clone()));
        Ok(SendReport {
            built,
            route,
            wire_bytes,
            stats: OperationStats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes: bytes_sent as u64,
                elapsed: started.elapsed(),
                capture: CaptureStatistics::default(),
            },
        })
    }

    fn authorize_built(
        &self,
        built: &BuiltPacket,
        allow_permissive_live: bool,
    ) -> Result<(), ClientError> {
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
}

fn ensure_preparation_deadline(deadline: Instant) -> Result<(), ClientError> {
    if deadline.checked_duration_since(Instant::now()).is_none() {
        return Err(LiveIoError::DeadlineExceeded {
            operation: "preparing the exchange",
        }
        .into());
    }
    Ok(())
}

impl<R, N, I> Client<R, N, I>
where
    R: RouteProvider,
    N: NeighborResolver,
    I: ExchangeIo,
{
    pub fn exchange(
        &self,
        template: &PacketTemplate,
        options: ExchangeOptions,
    ) -> Result<ExchangeResult, ClientError> {
        self.exchange_internal(template, options, None)
    }

    pub(crate) fn exchange_for_workflow(
        &self,
        template: &PacketTemplate,
        options: ExchangeOptions,
        mut matches_request: impl FnMut(usize, &Packet, &crate::packet::decode::DecodedPacket) -> bool,
    ) -> Result<ExchangeResult, ClientError> {
        self.exchange_internal(template, options, Some(&mut matches_request))
    }

    fn exchange_internal(
        &self,
        template: &PacketTemplate,
        options: ExchangeOptions,
        workflow_matcher: Option<&mut WorkflowResponseMatcher<'_>>,
    ) -> Result<ExchangeResult, ClientError> {
        let prepared = self.prepare_exchange(template, options)?;
        let transaction = self.arm_capture(prepared)?;
        transaction.execute(&self.io, workflow_matcher)
    }

    fn prepare_exchange(
        &self,
        template: &PacketTemplate,
        options: ExchangeOptions,
    ) -> Result<PreparedExchange, ClientError> {
        let started = Instant::now();
        let capture_limits = options.validate()?;
        let deadline = started
            .checked_add(options.timeout)
            .expect("validated bounded exchange timeout must fit Instant");
        let expansion_len = template
            .expansion_len()
            .map_err(|source| ClientError::Template {
                message: source.to_string(),
            })?;
        self.policy.authorize_operation(expansion_len as u64, 0)?;
        if expansion_len == 0 {
            return Err(ClientError::Template {
                message: "template expanded to no packets".to_owned(),
            });
        }
        let mut expanded_packets =
            template
                .expand(options.max_template_packets)
                .map_err(|source| ClientError::Template {
                    message: source.to_string(),
                })?;
        let packet_count = expansion_len as u64;
        let builder = Builder::new(Arc::clone(&self.registry));
        let routes = ExchangeRouteProvider::new(&self.routes);
        let mut planned_packets: Vec<PlannedExchangePacket> = Vec::with_capacity(expansion_len);
        let mut total_bytes = 0u64;
        loop {
            ensure_preparation_deadline(deadline)?;
            let Some(expanded_packet) = expanded_packets.next() else {
                break;
            };
            ensure_preparation_deadline(deadline)?;
            let mut packet_to_send = expanded_packet.map_err(|source| ClientError::Template {
                message: source.to_string(),
            })?;
            ensure_preparation_deadline(deadline)?;
            let plan = self.plan_with_provider(
                &packet_to_send,
                options.send.destination,
                &options.send.plan,
                &routes,
                Some(deadline),
            )?;
            ensure_preparation_deadline(deadline)?;
            materialize_network_fields(&mut packet_to_send, &plan)?;
            materialize_link_structure(&mut packet_to_send, &plan)?;
            ensure_preparation_deadline(deadline)?;
            let context = build_context(&plan);
            let preliminary = builder.build(
                packet_to_send.clone(),
                context.clone(),
                options.send.build.clone(),
            )?;
            ensure_preparation_deadline(deadline)?;
            validate_mtu(&preliminary, plan.route.mtu)?;
            self.authorize_built(&preliminary, options.send.allow_permissive_live)?;
            total_bytes = total_bytes
                .checked_add(preliminary.bytes.len() as u64)
                .ok_or(TrafficPolicyError::ByteLimit {
                    actual: u64::MAX,
                    limit: self.policy.max_bytes_per_operation,
                })?;
            self.policy.authorize_operation(packet_count, total_bytes)?;
            if let Some(first_packet) = planned_packets.first()
                && (first_packet.plan.route.interface != plan.route.interface
                    || first_packet.plan.mode != plan.mode)
            {
                return Err(ClientError::HeterogeneousExchangeRoute);
            }
            planned_packets.push(PlannedExchangePacket {
                packet: packet_to_send,
                plan,
                build_context: context,
                preliminary_build: preliminary,
            });
        }

        // Neighbor discovery is delayed until every packet has passed packet,
        // route, permissive-build, and aggregate byte-policy checks.
        let mut prepared_packets = Vec::with_capacity(planned_packets.len());
        for planned_packet in planned_packets {
            ensure_preparation_deadline(deadline)?;
            let PlannedExchangePacket {
                mut packet,
                plan,
                build_context,
                mut preliminary_build,
            } = planned_packet;
            let preliminary_len = preliminary_build.bytes.len();
            let route = self.planner.materialize(plan, &self.neighbors)?;
            ensure_preparation_deadline(deadline)?;
            let link_changed = materialize_link_fields(&mut packet, &route)?;
            let built = if link_changed {
                if patch_builtin_ethernet(&self.registry, &mut preliminary_build, &packet) {
                    preliminary_build
                } else {
                    ensure_preparation_deadline(deadline)?;
                    builder.build(packet, build_context, options.send.build.clone())?
                }
            } else {
                preliminary_build
            };
            ensure_preparation_deadline(deadline)?;
            self.authorize_built(&built, options.send.allow_permissive_live)?;
            require_fixed_width_link_materialization(preliminary_len, built.bytes.len())?;
            prepared_packets.push(PreparedExchangePacket { built, route });
        }

        Ok(PreparedExchange {
            started,
            deadline,
            capture_limits,
            options,
            packets: prepared_packets,
            packet_count,
            total_bytes,
        })
    }

    fn arm_capture(
        &self,
        prepared: PreparedExchange,
    ) -> Result<
        ExchangeTransaction<<I as crate::net::capture::CaptureProvider>::Capture>,
        ClientError,
    > {
        let first_route = &prepared
            .packets
            .first()
            .expect("non-empty prepared exchange")
            .route
            .plan;
        ensure_preparation_deadline(prepared.deadline)?;
        let capture = self.io.arm_capture(first_route, prepared.capture_limits)?;
        Ok(ExchangeTransaction::new(
            Arc::clone(&self.registry),
            capture,
            prepared,
        ))
    }
}
