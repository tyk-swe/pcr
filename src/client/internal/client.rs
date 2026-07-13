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
        let packet_ip_version =
            packet
                .iter()
                .find_map(|layer| match layer.protocol_id().as_str() {
                    "ipv4" => Some(IpVersion::V4),
                    "ipv6" => Some(IpVersion::V6),
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
        if let Some(destination) = destination {
            self.policy.authorize_destination(destination)?;
        }
        // Authorize every declared outer and SRH destination before the route
        // provider can observe one. The completed plan is checked again below
        // so provider-derived selections cannot bypass policy either.
        self.policy.authorize_packet_destinations(packet)?;
        let plan = self
            .planner
            .plan(packet, destination, options, &self.routes)?;
        for destination in &plan.visited_destinations {
            self.policy.authorize_destination(*destination)?;
        }
        Ok(plan)
    }

    pub fn send(&self, packet: Packet, options: SendOptions) -> Result<SendReport, ClientError> {
        let started = Instant::now();
        if self.policy.max_packets_per_operation < 1 {
            return Err(TrafficPolicyError::PacketLimit {
                actual: 1,
                limit: self.policy.max_packets_per_operation,
            }
            .into());
        }
        let plan = self.plan(&packet, options.destination, &options.plan)?;
        let mut packet_to_send = packet;
        materialize_network_fields(&mut packet_to_send, &plan)?;
        materialize_link_structure(&mut packet_to_send, &plan)?;
        let builder = Builder::new(Arc::clone(&self.registry));
        let context = build_context(&plan);
        // Validate all packet fields before neighbor discovery emits traffic.
        let preliminary = builder.build(
            packet_to_send.clone(),
            context.clone(),
            options.build.clone(),
        )?;
        validate_mtu(&preliminary, plan.route.mtu)?;
        self.authorize_built(&preliminary, options.allow_permissive_live)?;
        self.authorize_byte_count(preliminary.bytes.len() as u64)?;
        let preliminary_len = preliminary.bytes.len();
        let route = self.planner.materialize(plan, &self.neighbors)?;
        let link_changed = materialize_link_fields(&mut packet_to_send, &route)?;
        let built = if link_changed {
            let built = builder.build(packet_to_send, context, options.build)?;
            require_fixed_width_link_materialization(preliminary_len, built.bytes.len())?;
            self.authorize_built(&built, options.allow_permissive_live)?;
            self.authorize_byte_count(built.bytes.len() as u64)?;
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

    fn authorize_byte_count(&self, bytes: u64) -> Result<(), ClientError> {
        if bytes > self.policy.max_bytes_per_operation {
            return Err(TrafficPolicyError::ByteLimit {
                actual: bytes,
                limit: self.policy.max_bytes_per_operation,
            }
            .into());
        }
        Ok(())
    }
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
        self.exchange_with_capture_options(template, options, CaptureOptions::default())
    }

    /// Runs an exchange with capture mode and filter installation completed
    /// before the readiness barrier and first transmission.
    pub fn exchange_with_capture_options(
        &self,
        template: &PacketTemplate,
        options: ExchangeOptions,
        capture_options: CaptureOptions,
    ) -> Result<ExchangeResult, ClientError> {
        let operation = crate::operation::Context::generate()?;
        self.exchange_streaming(
            template,
            options,
            capture_options,
            &operation,
            &mut |_| Ok(()),
        )
    }

    /// Incremental, cancellable exchange entry point. Successful sends are
    /// emitted immediately; classified capture evidence follows after the
    /// owned capture session has shut down cleanly.
    pub fn exchange_streaming<S>(
        &self,
        template: &PacketTemplate,
        options: ExchangeOptions,
        capture_options: CaptureOptions,
        operation: &crate::operation::Context,
        sink: &mut S,
    ) -> Result<ExchangeResult, ClientError>
    where
        S: crate::operation::EventSink<ExchangeEvent>,
    {
        operation.cancellation().check()?;
        let started = Instant::now();
        let capture_options = capture_options.validate()?;
        let discard_unmatched = capture_options.discard_unmatched;
        let capture_limits = options.validate()?;
        let deadline = started
            .checked_add(options.timeout)
            .expect("validated bounded exchange timeout must fit Instant");
        let expansion_len = template
            .expansion_len()
            .map_err(|source| ClientError::Template {
                message: source.to_string(),
            })?;
        let policy_packet_limit =
            usize::try_from(self.policy.max_packets_per_operation).unwrap_or(usize::MAX);
        if expansion_len > policy_packet_limit {
            return Err(TrafficPolicyError::PacketLimit {
                actual: expansion_len as u64,
                limit: self.policy.max_packets_per_operation,
            }
            .into());
        }
        if expansion_len == 0 {
            return Err(ClientError::Template {
                message: "template expanded to no packets".to_owned(),
            });
        }
        let expanded_packets = template
            .expand(options.max_template_packets)
            .map_err(|source| ClientError::Template {
                message: source.to_string(),
            })?;
        let packet_count = expansion_len as u64;
        let builder = Builder::new(Arc::clone(&self.registry));
        let mut planned_packets: Vec<PlannedExchangePacket> = Vec::with_capacity(expansion_len);
        let mut total_bytes = 0u64;
        for expanded_packet in expanded_packets {
            let mut packet_to_send = expanded_packet.map_err(|source| ClientError::Template {
                message: source.to_string(),
            })?;
            let plan = self.plan(
                &packet_to_send,
                options.send.destination,
                &options.send.plan,
            )?;
            materialize_network_fields(&mut packet_to_send, &plan)?;
            materialize_link_structure(&mut packet_to_send, &plan)?;
            let context = build_context(&plan);
            let preliminary = builder.build(
                packet_to_send.clone(),
                context.clone(),
                options.send.build.clone(),
            )?;
            validate_mtu(&preliminary, plan.route.mtu)?;
            self.authorize_built(&preliminary, options.send.allow_permissive_live)?;
            total_bytes = total_bytes
                .checked_add(preliminary.bytes.len() as u64)
                .ok_or(TrafficPolicyError::ByteLimit {
                    actual: u64::MAX,
                    limit: self.policy.max_bytes_per_operation,
                })?;
            if total_bytes > self.policy.max_bytes_per_operation {
                return Err(TrafficPolicyError::ByteLimit {
                    actual: total_bytes,
                    limit: self.policy.max_bytes_per_operation,
                }
                .into());
            }
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
        operation.cancellation().check()?;
        let mut prepared_packets = Vec::with_capacity(planned_packets.len());
        for planned_packet in planned_packets {
            let PlannedExchangePacket {
                mut packet,
                plan,
                build_context,
                preliminary_build,
            } = planned_packet;
            let preliminary_len = preliminary_build.bytes.len();
            let route = self.planner.materialize(plan, &self.neighbors)?;
            let link_changed = materialize_link_fields(&mut packet, &route)?;
            let built = if link_changed {
                builder.build(packet, build_context, options.send.build.clone())?
            } else {
                preliminary_build
            };
            self.authorize_built(&built, options.send.allow_permissive_live)?;
            require_fixed_width_link_materialization(preliminary_len, built.bytes.len())?;
            prepared_packets.push(PreparedExchangePacket { built, route });
        }

        let first_route = &prepared_packets
            .first()
            .expect("non-empty prepared exchange")
            .route
            .plan;
        if deadline.checked_duration_since(Instant::now()).is_none() {
            return Err(LiveIoError::DeadlineExceeded {
                operation: "preparing the exchange",
            }
            .into());
        }
        operation.cancellation().check()?;
        let mut capture = CaptureGuard::new(self.io.arm_capture_with_options(
            first_route,
            capture_limits,
            capture_options,
        )?);
        let readiness_timeout = match deadline.checked_duration_since(Instant::now()) {
            Some(remaining) => remaining.min(Duration::from_secs(1)),
            None => {
                return Err(error_after_shutdown(
                    &mut capture,
                    LiveIoError::DeadlineExceeded {
                        operation: "waiting for capture readiness",
                    },
                ))
            }
        };
        if let Err(error) = capture.wait_ready(readiness_timeout) {
            return Err(error_after_shutdown(&mut capture, error));
        }
        if let Err(error) = operation.cancellation().check() {
            return Err(operation_error_after_shutdown(&mut capture, error));
        }

        let mut sent_at = Vec::with_capacity(prepared_packets.len());
        let mut sent_evidence = Vec::with_capacity(prepared_packets.len());
        let mut completed_sends = 0u64;
        let dissector = Dissector::new(Arc::clone(&self.registry));
        let mut captured = ExchangeAccumulator::new(prepared_packets.len(), discard_unmatched);
        for (send_index, prepared_packet) in prepared_packets.iter().enumerate() {
            if let Err(error) = operation.cancellation().check() {
                return Err(operation_error_after_shutdown(&mut capture, error));
            }
            let built = &prepared_packet.built;
            let route = &prepared_packet.route;
            if let Err(error) = drain_available(
                &mut capture,
                Some(deadline),
                capture_limits.max_frames,
                &mut captured,
                ExchangeProcessContext {
                    registry: &self.registry,
                    dissector: &dissector,
                    prepared: &prepared_packets,
                    sent_at: &sent_at,
                    deadline,
                    options: &options,
                },
                operation.cancellation(),
            ) {
                return Err(drain_error_after_shutdown(&mut capture, error));
            }
            if deadline.checked_duration_since(Instant::now()).is_none() {
                return Err(error_after_shutdown(
                    &mut capture,
                    LiveIoError::DeadlineExceeded {
                        operation: "sending exchange requests",
                    },
                ));
            }
            let send_started = Instant::now();
            let send_wall_time = std::time::SystemTime::now();
            let frame = match TransmissionFrame::try_new(&built.bytes, route) {
                Ok(frame) => frame,
                Err(error) => return Err(error_after_shutdown(&mut capture, error)),
            };
            let sent = match self.io.send(frame) {
                Ok(report) => report,
                Err(error) => return Err(error_after_shutdown(&mut capture, error)),
            };
            if let Err(error) = validate_send_report(&built.bytes, &sent) {
                return Err(error_after_shutdown(&mut capture, error));
            }
            let link_type = match route.plan.mode {
                crate::net::LinkMode::Layer2 => route.plan.route.link_type,
                crate::net::LinkMode::Layer3 => crate::capture::LinkType::RAW,
                crate::net::LinkMode::Auto => {
                    return Err(error_after_shutdown(
                        &mut capture,
                        LiveIoError::UnresolvedLinkMode,
                    ))
                }
            };
            let evidence = match Frame::new(send_wall_time, link_type, built.bytes.clone()) {
                Ok(evidence) => evidence,
                Err(source) => {
                    return Err(error_after_shutdown(
                        &mut capture,
                        LiveIoError::InvalidSendEvidence {
                            message: source.to_string(),
                        },
                    ))
                }
            };
            sent_at.push(send_started);
            sent_evidence.push(evidence);
            completed_sends += 1;
            if let Err(error) = sink.emit(ExchangeEvent::Sent {
                request_index: send_index,
                frame: sent_evidence
                    .last()
                    .expect("successful send evidence was just retained")
                    .clone(),
            }) {
                return Err(event_error_after_shutdown(&mut capture, error));
            }
            if deadline.checked_duration_since(Instant::now()).is_none() {
                return Err(error_after_shutdown(
                    &mut capture,
                    LiveIoError::DeadlineExceeded {
                        operation: "sending exchange requests",
                    },
                ));
            }
            if let Err(error) = drain_available(
                &mut capture,
                (send_index + 1 < prepared_packets.len()).then_some(deadline),
                capture_limits.max_frames,
                &mut captured,
                ExchangeProcessContext {
                    registry: &self.registry,
                    dissector: &dissector,
                    prepared: &prepared_packets,
                    sent_at: &sent_at,
                    deadline,
                    options: &options,
                },
                operation.cancellation(),
            ) {
                return Err(drain_error_after_shutdown(&mut capture, error));
            }
        }

        loop {
            if let Err(error) = operation.cancellation().check() {
                return Err(operation_error_after_shutdown(&mut capture, error));
            }
            let now = Instant::now();
            let Some(remaining) = deadline.checked_duration_since(now) else {
                break;
            };
            let wait = remaining.min(Duration::from_millis(100));
            let frame = match capture.next_captured_frame(wait) {
                Ok(Some(frame)) => frame,
                Ok(None) if wait < remaining => continue,
                Ok(None) => break,
                Err(error) => {
                    return Err(error_after_shutdown(&mut capture, error));
                }
            };
            captured.process(
                frame,
                ExchangeProcessContext {
                    registry: &self.registry,
                    dissector: &dissector,
                    prepared: &prepared_packets,
                    sent_at: &sent_at,
                    deadline,
                    options: &options,
                },
            );
        }
        if let Err(error) = drain_available(
            &mut capture,
            None,
            capture_limits.max_frames,
            &mut captured,
            ExchangeProcessContext {
                registry: &self.registry,
                dissector: &dissector,
                prepared: &prepared_packets,
                sent_at: &sent_at,
                deadline,
                options: &options,
            },
            operation.cancellation(),
        ) {
            return Err(drain_error_after_shutdown(&mut capture, error));
        }
        if let Err(error) = operation.cancellation().check() {
            return Err(operation_error_after_shutdown(&mut capture, error));
        }
        capture.shutdown()?;
        let capture_statistics = capture.statistics().validate()?;
        if capture_statistics.has_loss() {
            if capture_limits.overflow_policy == CaptureOverflowPolicy::Fail {
                return Err(capture_statistics
                    .evidence_loss_error()
                    .expect("lossy capture statistics must produce a typed error")
                    .into());
            }
            push_diagnostic_once(
                &mut captured.diagnostics,
                crate::packet::internal::Diagnostic::warning(
                    "capture.evidence_incomplete",
                    format!(
                        "capture backend reported {} overflow event(s), {} receiver drop(s), {} total dropped frame(s), and {} dropped byte(s) under {:?}",
                        capture_statistics.overflow_events,
                        capture_statistics.receiver_dropped_frames,
                        capture_statistics.dropped_frames,
                        capture_statistics.dropped_bytes,
                        capture_limits.overflow_policy,
                    ),
                ),
            );
        }

        let unanswered = captured
            .response_counts
            .iter()
            .enumerate()
            .filter_map(|(index, response_count)| (*response_count == 0).then_some(index))
            .collect();
        let sent = prepared_packets
            .into_iter()
            .map(|prepared_packet| prepared_packet.built)
            .collect();
        if captured.discarded_unmatched != 0 {
            push_diagnostic_once(
                &mut captured.diagnostics,
                crate::packet::internal::Diagnostic::warning(
                    "capture.unmatched_discarded",
                    format!(
                        "discarded {} unmatched or undecodable captured frame(s)",
                        captured.discarded_unmatched
                    ),
                ),
            );
        }
        for response in captured.responses.iter().cloned() {
            sink.emit(ExchangeEvent::Response(response))?;
        }
        for response in captured.unsolicited.iter().cloned() {
            sink.emit(ExchangeEvent::Unsolicited(response))?;
        }
        for frame in captured.undecoded.iter().cloned() {
            sink.emit(ExchangeEvent::Undecoded(frame))?;
        }
        Ok(ExchangeResult {
            sent,
            sent_evidence,
            responses: captured.responses,
            unanswered,
            unsolicited: captured.unsolicited,
            undecoded: captured.undecoded,
            diagnostics: captured.diagnostics,
            stats: OperationStats {
                packets_attempted: packet_count,
                packets_completed: completed_sends,
                bytes: total_bytes,
                elapsed: started.elapsed(),
                capture: capture_statistics,
            },
        })
    }
}
