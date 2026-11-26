// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Constant names preserve the former enum variants, keeping the crate-local
// ownership split from adding a second source-level renaming migration.
#![allow(non_upper_case_globals)]
pub(crate) const CapabilityCaptureSetting: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("capability.capture_setting");
pub(crate) const CapabilityMissingDependency: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("capability.missing_dependency");
pub(crate) const CapabilityPrivilege: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("capability.privilege");
pub(crate) const CapabilityRoute: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("capability.route");
pub(crate) const CapabilityUnsupported: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("capability.unsupported");
pub(crate) const CliCaptureFilter: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.capture_filter");
pub(crate) const CliCaptureGroup: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.capture_group");
pub(crate) const CliCaptureSetting: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.capture_setting");
pub(crate) const CliCaptureTimeout: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.capture_timeout");
pub(crate) const CliTcpConnectTimeout: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.tcp_connect_timeout");
pub(crate) const CliTcpExchangeLimit: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.tcp_exchange_limit");
pub(crate) const CliTlsLimits: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.tls_limits");
pub(crate) const CliTlsServerName: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.tls_server_name");
pub(crate) const CliUdpExchangeLimit: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("cli.udp_exchange_limit");
pub(crate) const InternalCaptureGroup: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.capture_group");
pub(crate) const InternalLiveIoInvariant: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.live_io_invariant");
pub(crate) const InternalRouteResponse: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.route_response");
pub(crate) const InternalTcpConnectState: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("internal.tcp_connect_state");
pub(crate) const IoCapture: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.capture");
pub(crate) const IoCaptureEvidenceLoss: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.capture_evidence_loss");
pub(crate) const IoCaptureFilter: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.capture_filter");
pub(crate) const IoCaptureOverflow: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.capture_overflow");
pub(crate) const IoCaptureReadiness: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.capture_readiness");
pub(crate) const IoDeadlineExceeded: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.deadline_exceeded");
pub(crate) const IoDevice: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.device");
pub(crate) const IoHostnameAddressLimit: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.hostname_address_limit");
pub(crate) const IoHostnameResolution: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.hostname_resolution");
pub(crate) const IoInterfaceDiscovery: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.interface_discovery");
pub(crate) const IoInterfaceNotFound: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.interface_not_found");
pub(crate) const IoPartialSend: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.partial_send");
pub(crate) const IoRoute: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.route");
pub(crate) const IoRouteNotFound: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.route_not_found");
pub(crate) const IoRouteSelection: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.route_selection");
pub(crate) const IoSend: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.send");
pub(crate) const IoTcpConnect: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.tcp_connect");
pub(crate) const IoTcpConnectCapacity: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.tcp_connect_capacity");
pub(crate) const IoTcpConnectEvidence: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.tcp_connect_evidence");
pub(crate) const IoTcpConnectWorker: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.tcp_connect_worker");
pub(crate) const IoTlsProtocol: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.tls_protocol");
pub(crate) const IoTlsTransport: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.tls_transport");
pub(crate) const IoUdpExchange: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.udp_exchange");
pub(crate) const IoUdpPeer: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("io.udp_peer");
pub(crate) const PacketTransmissionFrame: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("packet.transmission_frame");
pub(crate) const PolicyTlsLimit: packetcraftr_core::error::Code =
    packetcraftr_core::error::Code::new("policy.tls_limit");

pub(crate) fn deadline_exceeded() -> packetcraftr_core::error::Classification {
    packetcraftr_core::error::Classification::new(
        IoDeadlineExceeded,
        packetcraftr_core::error::Kind::Io,
        Some("increase the finite operation timeout or reduce readiness, send, and capture work"),
    )
}

pub(crate) fn interface_discovery() -> packetcraftr_core::error::Classification {
    packetcraftr_core::error::Classification::new(
        IoInterfaceDiscovery,
        packetcraftr_core::error::Kind::Io,
        Some("inspect the operating-system interface state and retry with an available interface"),
    )
}

pub(crate) fn live_io_invariant() -> packetcraftr_core::error::Classification {
    packetcraftr_core::error::Classification::new(
        InternalLiveIoInvariant,
        packetcraftr_core::error::Kind::Internal,
        Some(
            "report the inconsistent provider result; do not reinterpret it as a successful operation",
        ),
    )
}
