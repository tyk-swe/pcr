// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Constant names preserve the former enum variants, keeping the crate-local
// ownership split from adding a second source-level renaming migration.
#![allow(non_upper_case_globals)]
pub(crate) const CapabilityDnsScope: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("capability.dns_scope");
pub(crate) const CapabilityDnsTcp: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("capability.dns_tcp");
pub(crate) const CapabilityDnsTcpScope: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("capability.dns_tcp_scope");
pub(crate) const CapabilityLinkMode: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("capability.link_mode");
pub(crate) const CapabilityReplayLinkType: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("capability.replay_link_type");
pub(crate) const CapabilityScanTcpRoute: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("capability.scan_tcp_route");
pub(crate) const CapabilityTracerouteScope: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("capability.traceroute_scope");
pub(crate) const CapabilityZoneResolution: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("capability.zone_resolution");
pub(crate) const CaptureDifferentialIncomplete: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("capture.differential_incomplete");
pub(crate) const CaptureEvidenceIncomplete: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("capture.evidence_incomplete");
pub(crate) const CaptureIngressTimeUnavailable: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("capture.ingress_time_unavailable");
pub(crate) const CliAuditRequest: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.audit_request");
pub(crate) const CliCaptureOptions: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.capture_options");
pub(crate) const CliDifferentialLimit: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.differential_limit");
pub(crate) const CliDnsExecutor: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.dns_executor");
pub(crate) const CliDnsLimit: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.dns_limit");
pub(crate) const CliExchangeLimit: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.exchange_limit");
pub(crate) const CliHeterogeneousExchangeRoute: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.heterogeneous_exchange_route");
pub(crate) const CliIdentifyOsExecutor: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.identify_os_executor");
pub(crate) const CliIdentifyOsLimit: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.identify_os_limit");
pub(crate) const CliIdentifyRequest: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.identify_request");
pub(crate) const CliInterfaceRequired: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.interface_required");
pub(crate) const CliLiveTarget: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.live_target");
pub(crate) const CliNeighborLimit: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.neighbor_limit");
pub(crate) const CliReplayLimit: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.replay_limit");
pub(crate) const CliScanDiscovery: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.scan_discovery");
pub(crate) const CliScanExecutor: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.scan_executor");
pub(crate) const CliScanLimit: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.scan_limit");
pub(crate) const CliScanMethod: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.scan_method");
pub(crate) const CliSendLimit: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.send_limit");
pub(crate) const CliTargetSelection: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.target_selection");
pub(crate) const CliTracerouteExecutor: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.traceroute_executor");
pub(crate) const CliTracerouteLimit: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.traceroute_limit");
pub(crate) const CliUdpProfile: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.udp_profile");
pub(crate) const CliWorkerCapacity: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.worker_capacity");
pub(crate) const InternalCaptureStatistics: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.capture_statistics");
pub(crate) const InternalDifferentialEvidence: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.differential_evidence");
pub(crate) const InternalDnsEvidence: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.dns_evidence");
pub(crate) const InternalDnsExecutor: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.dns_executor");
pub(crate) const InternalDnsTcpRequest: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.dns_tcp_request");
pub(crate) const InternalExchangeEventCoherence: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.exchange_event_coherence");
pub(crate) const InternalFuzzEvidence: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.fuzz_evidence");
pub(crate) const InternalFuzzExecutor: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.fuzz_executor");
pub(crate) const InternalIdentifyOsEvidence: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.identify_os_evidence");
pub(crate) const InternalIdentifyProvider: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.identify_provider");
pub(crate) const InternalNeighborInvariant: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.neighbor_invariant");
pub(crate) const InternalProgressiveOutput: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.progressive_output");
pub(crate) const InternalProgressiveOutputWorkerExhausted: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.progressive_output_worker_exhausted");
pub(crate) const InternalReplayEventCoherence: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.replay_event_coherence");
pub(crate) const InternalReplayEvidence: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.replay_evidence");
pub(crate) const InternalReplayRebuild: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.replay_rebuild");
pub(crate) const InternalRouteContract: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.route_contract");
pub(crate) const InternalScanCandidateIndex: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.scan_candidate_index");
pub(crate) const InternalScanEventCoherence: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.scan_event_coherence");
pub(crate) const InternalScanEvidence: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.scan_evidence");
pub(crate) const InternalScanPipelineEvent: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.scan_pipeline_event");
pub(crate) const InternalScanProbeMismatch: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.scan_probe_mismatch");
pub(crate) const InternalSendEventCoherence: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.send_event_coherence");
pub(crate) const InternalTargetPlan: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.target_plan");
pub(crate) const InternalTracerouteEventCoherence: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.traceroute_event_coherence");
pub(crate) const InternalTracerouteEvidence: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.traceroute_evidence");
pub(crate) const InternalUnresolvedInterface: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.unresolved_interface");
pub(crate) const IoAmbiguousInterface: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.ambiguous_interface");
pub(crate) const IoAudit: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.audit");
pub(crate) const IoDifferential: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.differential");
pub(crate) const IoDnsClock: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.dns_clock");
pub(crate) const IoDnsEntropy: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.dns_entropy");
pub(crate) const IoDnsTcp: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.dns_tcp");
pub(crate) const IoDnsTcpTimeout: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.dns_tcp_timeout");
pub(crate) const IoFuzzClock: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.fuzz_clock");
pub(crate) const IoIdentifyOs: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.identify_os");
pub(crate) const IoIdentifyOsClock: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.identify_os_clock");
pub(crate) const IoInterface: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.interface");
pub(crate) const IoNeighbor: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.neighbor");
pub(crate) const IoNeighborClock: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.neighbor_clock");
pub(crate) const IoNeighborTimeout: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.neighbor_timeout");
pub(crate) const IoReplay: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.replay");
pub(crate) const IoRouteChanged: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.route_changed");
pub(crate) const IoScanClock: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.scan_clock");
pub(crate) const IoSendClock: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.send_clock");
#[cfg(test)]
pub(crate) const IoTest: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.test");
pub(crate) const IoTracerouteClock: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.traceroute_clock");
pub(crate) const IoTracerouteEntropy: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.traceroute_entropy");
pub(crate) const PacketCaptureSize: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("packet.capture_size");
pub(crate) const PacketDnsQuery: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("packet.dns_query");
pub(crate) const PacketDnsTcpFrame: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("packet.dns_tcp_frame");
pub(crate) const PacketMaterialization: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("packet.materialization");
pub(crate) const PacketMtu: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("packet.mtu");
pub(crate) const PacketOfflineLinkHeader: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("packet.offline_link_header");
pub(crate) const PacketPlan: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("packet.plan");
pub(crate) const PacketReplayNetwork: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("packet.replay_network");
pub(crate) const PacketReplayRebuild: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("packet.replay_rebuild");
pub(crate) const PacketReplayTiming: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("packet.replay_timing");
pub(crate) const PacketReplayTruncated: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("packet.replay_truncated");
pub(crate) const PacketTargetAddressFamily: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("packet.target_address_family");
pub(crate) const PacketTemplate: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("packet.template");
pub(crate) const PolicyBudgetOverflow: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("policy.budget_overflow");
pub(crate) const PolicyByteLimit: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("policy.byte_limit");
pub(crate) const PolicyDestinationNotAllowed: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("policy.destination_not_allowed");
pub(crate) const PolicyDifferentialPlan: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("policy.differential_plan");
pub(crate) const PolicyDifferentialResourceLimit: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("policy.differential_resource_limit");
pub(crate) const PolicyDnsDurationLimit: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("policy.dns_duration_limit");
pub(crate) const PolicyExchangeDurationLimit: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("policy.exchange_duration_limit");
pub(crate) const PolicyHostnameResolution: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("policy.hostname_resolution");
pub(crate) const PolicyInvalidPacketSemantics: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("policy.invalid_packet_semantics");
pub(crate) const PolicyPacketLimit: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("policy.packet_limit");
pub(crate) const PolicyPermissiveLiveOptIn: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("policy.permissive_live_opt_in");
pub(crate) const PolicyPermissivePacket: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("policy.permissive_packet");
pub(crate) const PolicyPublicDestination: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("policy.public_destination");
pub(crate) const PolicyReplayLimit: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("policy.replay_limit");
pub(crate) const PolicyScanDurationLimit: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("policy.scan_duration_limit");
pub(crate) const PolicyScanPipelineLimit: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("policy.scan_pipeline_limit");
pub(crate) const PolicySourceOwnership: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("policy.source_ownership");
pub(crate) const PolicyTracerouteDurationLimit: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("policy.traceroute_duration_limit");
pub(crate) const PolicyTrafficByteLimit: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("policy.traffic_byte_limit");
pub(crate) const PolicyTrafficUnitLimit: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("policy.traffic_unit_limit");
