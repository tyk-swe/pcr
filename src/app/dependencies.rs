// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use crate::cli::enums::OutputFormat as CliOutputFormat;
use crate::engine::ports::EngineDependencies;

use super::adapters;

pub(crate) fn system(output_format: Option<CliOutputFormat>) -> EngineDependencies {
    EngineDependencies {
        target_resolver: Arc::new(adapters::util::SystemTargetResolverAdapter),
        privilege_checker: Arc::new(adapters::util::RawSocketPrivilegeChecker),
        packet_planner: Arc::new(adapters::network::NetworkPacketPlanner),
        packet_transmitter: Arc::new(adapters::network::NetworkPacketTransmitter),
        listener_runner: Arc::new(adapters::network::NetworkListenerRunner),
        #[cfg(feature = "daemon")]
        daemon_listener_runtime: Arc::new(adapters::network::NetworkListenerRunner),
        dns_client: Arc::new(adapters::tools::ToolsDnsClient),
        #[cfg(feature = "traceroute")]
        traceroute_runner: Arc::new(adapters::tools::ToolsTracerouteRunner),
        #[cfg(feature = "scan")]
        scan_runner: Arc::new(adapters::tools::ToolsScanRunner),
        #[cfg(feature = "fuzz")]
        fuzz_runner: Arc::new(adapters::tools::ToolsFuzzRunner),
        output: Arc::new(adapters::output::OutputEventSink::new(
            output_format.map(crate::output::OutputFormat::from),
        )),
        rule_action_telemetry: Arc::new(adapters::telemetry::UtilRuleActionTelemetry),
    }
}
