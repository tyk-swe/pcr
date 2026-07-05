// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use anyhow::Result;

use crate::domain::command::EngineCommand;
use crate::engine::core::Engine;

pub(crate) async fn run(engine: &mut Engine, command: EngineCommand) -> Result<()> {
    match command {
        EngineCommand::Send(request) | EngineCommand::DryRun(request) => {
            engine.run_one_shot(request).await?;
        }
        #[cfg(feature = "repl")]
        EngineCommand::Interactive(opts) => {
            crate::cli::repl::start_session(&opts, engine).await?;
        }
        #[cfg(feature = "daemon")]
        EngineCommand::Daemon(opts) => {
            engine.run_daemon(&opts).await?;
        }
        #[cfg(feature = "pcap")]
        EngineCommand::Listen(opts) => {
            engine.run_listener(&opts).await?;
        }
        #[cfg(feature = "traceroute")]
        EngineCommand::Traceroute(opts) => {
            engine.run_traceroute(&opts).await?;
        }
        #[cfg(feature = "scan")]
        EngineCommand::Scan(opts) => {
            engine.run_scan(&opts).await?;
        }
        EngineCommand::DnsQuery(opts) => {
            let result = engine.run_dns_query(&opts).await?;
            engine.dependencies.output.emit_text_output(&result)?;
        }
        #[cfg(feature = "fuzz")]
        EngineCommand::Fuzz(opts) => {
            engine.run_fuzz(&opts).await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tokio::runtime::Handle;

    use super::*;
    use crate::domain::command::{DnsQueryResult, DnsRequest, DnsTransport, DnsTransportMode};
    use crate::domain::event::ListenerEvent;
    use crate::domain::policy::{TargetScope, TrafficMode, TrafficPlan, TrafficPolicy};
    use crate::domain::spec::PacketSpec;
    use crate::domain::transmission::TransmissionPlan;
    use crate::engine::ports::{
        DnsClient, EngineDependencies, EngineOutput, PortFuture, PreparedDnsQuery,
    };
    #[cfg(feature = "daemon")]
    use crate::engine::test_support::RejectDaemonListenerRuntime;
    #[cfg(feature = "fuzz")]
    use crate::engine::test_support::RejectFuzzRunner;
    #[cfg(feature = "scan")]
    use crate::engine::test_support::RejectScanRunner;
    #[cfg(feature = "traceroute")]
    use crate::engine::test_support::RejectTracerouteRunner;
    use crate::engine::test_support::{
        NoOpRuleActionTelemetry, RejectListenerRunner, RejectPacketPlanner,
        RejectPacketTransmitter, RejectPrivilegeChecker, RejectTargetResolver,
    };

    #[derive(Default)]
    struct DnsOutputState {
        rendered: Mutex<Vec<String>>,
    }

    struct FakeDnsClient;

    impl DnsClient for FakeDnsClient {
        fn prepare(
            &self,
            _request: DnsRequest,
            _policy: TrafficPolicy,
        ) -> PortFuture<PreparedDnsQuery> {
            Box::pin(async {
                Ok(PreparedDnsQuery::new(
                    TrafficPlan::with_shape(
                        TrafficMode::Send,
                        TargetScope::Private,
                        1,
                        1,
                        Some(1),
                        1,
                        Some(100),
                    ),
                    Box::new(|| Box::pin(async { Ok(dns_result()) })),
                ))
            })
        }
    }

    struct FakeOutput {
        state: Arc<DnsOutputState>,
    }

    impl EngineOutput for FakeOutput {
        fn emit_preflight_summary(
            &self,
            _spec: &PacketSpec,
            _plan: &TransmissionPlan,
        ) -> crate::engine::ports::PortResult<()> {
            Ok(())
        }

        #[cfg(any(feature = "scan", feature = "traceroute", feature = "fuzz"))]
        fn emit_traffic_plan_summary(
            &self,
            _plan: &TrafficPlan,
        ) -> crate::engine::ports::PortResult<()> {
            Ok(())
        }

        fn emit_listener_event(&self, _event: &ListenerEvent) {}

        fn emit_text_output(&self, rendered: &str) -> crate::engine::ports::PortResult<()> {
            self.state
                .rendered
                .lock()
                .unwrap()
                .push(rendered.to_string());
            Ok(())
        }

        fn format_dns_dry_run(
            &self,
            _request: &DnsRequest,
        ) -> crate::engine::ports::PortResult<String> {
            Ok("dry-run dns".to_string())
        }

        fn format_dns_response(
            &self,
            _result: &DnsQueryResult,
        ) -> crate::engine::ports::PortResult<String> {
            Ok("formatted dns response".to_string())
        }
    }

    fn dns_result() -> DnsQueryResult {
        DnsQueryResult {
            id: 7,
            opcode: "Query".to_string(),
            response_code: "No Error".to_string(),
            flags: vec![],
            questions: vec![],
            answers: vec![],
            authority: vec![],
            additional: vec![],
            transport_used: DnsTransport::Udp,
            attempts: 1,
            server: "192.0.2.53:53".to_string(),
            response_bytes: 64,
            udp_truncated: false,
            tcp_fallback_used: false,
        }
    }

    fn dns_request() -> DnsRequest {
        DnsRequest {
            domain: "example.test".to_string(),
            record_type: "A".to_string(),
            server: "192.0.2.53".to_string(),
            timeout: 250,
            transaction_id: Some(7),
            transport: DnsTransportMode::Udp,
            retries: 0,
        }
    }

    fn engine(state: Arc<DnsOutputState>) -> Engine {
        let dependencies = EngineDependencies {
            target_resolver: Arc::new(RejectTargetResolver),
            privilege_checker: Arc::new(RejectPrivilegeChecker),
            packet_planner: Arc::new(RejectPacketPlanner),
            packet_transmitter: Arc::new(RejectPacketTransmitter),
            listener_runner: Arc::new(RejectListenerRunner),
            #[cfg(feature = "daemon")]
            daemon_listener_runtime: Arc::new(RejectDaemonListenerRuntime),
            dns_client: Arc::new(FakeDnsClient),
            #[cfg(feature = "traceroute")]
            traceroute_runner: Arc::new(RejectTracerouteRunner),
            #[cfg(feature = "scan")]
            scan_runner: Arc::new(RejectScanRunner),
            #[cfg(feature = "fuzz")]
            fuzz_runner: Arc::new(RejectFuzzRunner),
            output: Arc::new(FakeOutput { state }),
            rule_action_telemetry: Arc::new(NoOpRuleActionTelemetry),
        };
        let config = crate::engine::config::EngineConfig {
            prometheus_bind: None,
            rule_workers: None,
            rule_queue: None,
            send_workers: None,
            send_queue: None,
            traffic_policy: TrafficPolicy::default(),
            dry_run: false,
        };

        Engine::new_with_runtime_handle(config, dependencies, Handle::current()).unwrap()
    }

    #[tokio::test]
    async fn dns_query_dispatch_routes_formatted_output_through_engine_output() {
        let state = Arc::new(DnsOutputState::default());
        let mut engine = engine(Arc::clone(&state));

        run(&mut engine, EngineCommand::DnsQuery(dns_request()))
            .await
            .unwrap();

        assert_eq!(*state.rendered.lock().unwrap(), ["formatted dns response"]);
    }
}
