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
    use std::net::IpAddr;
    use std::sync::{Arc, Mutex};

    use anyhow::anyhow;
    use tokio::runtime::Handle;

    use super::*;
    use crate::domain::command::{DnsQueryResult, DnsRequest, DnsTransport, DnsTransportMode};
    use crate::domain::event::ListenerEvent;
    use crate::domain::policy::{TargetScope, TrafficMode, TrafficPlan, TrafficPolicy};
    use crate::domain::spec::{ListenerSpec, PacketSpec};
    use crate::domain::transmission::{PlanningMode, TransmissionPlan};
    #[cfg(feature = "daemon")]
    use crate::engine::ports::DaemonListenerRuntime;
    use crate::engine::ports::{
        DnsClient, EngineDependencies, EngineOutput, ListenerEventHandler, ListenerRunner,
        PacketPlanner, PacketTransmitter, PortFuture, PreparedDnsQuery, PrivilegeChecker,
        RuleActionTelemetry, TargetResolver,
    };
    #[cfg(feature = "fuzz")]
    use crate::engine::ports::{FuzzRunner, GeneratedPacketSender, PreparedFuzzRun};
    #[cfg(feature = "scan")]
    use crate::engine::ports::{PreparedScanRun, ScanRunner};
    #[cfg(feature = "traceroute")]
    use crate::engine::ports::{PreparedTracerouteRun, TracerouteRunner};

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

    struct UnusedPorts;

    impl TargetResolver for UnusedPorts {
        fn resolve_target_ip(
            &self,
            _target: String,
            _prefer_ipv6: Option<bool>,
        ) -> PortFuture<IpAddr> {
            Box::pin(async { Err(anyhow!("target resolver should not be used")) })
        }
    }

    impl PrivilegeChecker for UnusedPorts {
        fn check_packet_send(&self, _spec: Arc<PacketSpec>) -> PortFuture<()> {
            Box::pin(async { Err(anyhow!("privilege checker should not be used")) })
        }
    }

    impl PacketPlanner for UnusedPorts {
        fn plan_packet(
            &self,
            _spec: Arc<PacketSpec>,
            _mode: PlanningMode,
            _policy: crate::domain::policy::TransmissionPolicy,
        ) -> PortFuture<TransmissionPlan> {
            Box::pin(async { Err(anyhow!("packet planner should not be used")) })
        }
    }

    impl PacketTransmitter for UnusedPorts {
        fn transmit(&self, _plan: TransmissionPlan) -> PortFuture<()> {
            Box::pin(async { Err(anyhow!("packet transmitter should not be used")) })
        }
    }

    impl ListenerRunner for UnusedPorts {
        #[cfg(not(feature = "pcap"))]
        fn run_for_packet(
            &self,
            _spec: ListenerSpec,
            _interface_hint: Option<String>,
            _handler: ListenerEventHandler,
        ) -> PortFuture<()> {
            Box::pin(async { Err(anyhow!("listener runner should not be used")) })
        }

        #[cfg(feature = "pcap")]
        fn run_for_packet_with_lifecycle(
            &self,
            _spec: ListenerSpec,
            _interface_hint: Option<String>,
            _handler: ListenerEventHandler,
            _shutdown: Arc<std::sync::atomic::AtomicBool>,
            _startup: Option<crate::engine::ports::ListenerStartupSignal>,
        ) -> PortFuture<()> {
            Box::pin(async { Err(anyhow!("listener lifecycle runner should not be used")) })
        }

        #[cfg(feature = "pcap")]
        fn run_command(
            &self,
            _request: crate::domain::command::ListenRequest,
            _handler: ListenerEventHandler,
        ) -> PortFuture<()> {
            Box::pin(async { Err(anyhow!("listener command should not be used")) })
        }
    }

    #[cfg(feature = "traceroute")]
    impl TracerouteRunner for UnusedPorts {
        fn prepare(
            &self,
            _request: crate::domain::command::TracerouteRequest,
            _policy: TrafficPolicy,
        ) -> PortFuture<PreparedTracerouteRun> {
            Box::pin(async { Err(anyhow!("traceroute runner should not be used")) })
        }
    }

    #[cfg(feature = "scan")]
    impl ScanRunner for UnusedPorts {
        fn prepare(
            &self,
            _request: crate::domain::command::ScanRequest,
            _policy: TrafficPolicy,
        ) -> PortFuture<PreparedScanRun> {
            Box::pin(async { Err(anyhow!("scan runner should not be used")) })
        }
    }

    #[cfg(feature = "fuzz")]
    impl FuzzRunner for UnusedPorts {
        fn prepare(
            &self,
            _request: crate::domain::command::FuzzRequest,
            _policy: TrafficPolicy,
            _sender: GeneratedPacketSender,
        ) -> PortFuture<PreparedFuzzRun> {
            Box::pin(async { Err(anyhow!("fuzz runner should not be used")) })
        }
    }

    #[cfg(feature = "daemon")]
    impl DaemonListenerRuntime for UnusedPorts {
        fn validate_options(
            &self,
            _options: &crate::domain::request::ListenerRequest,
        ) -> crate::engine::ports::PortResult<()> {
            Err(anyhow!("daemon listener runtime should not be used"))
        }

        fn spawn_background(
            &self,
            _options: crate::domain::request::ListenerRequest,
            _interface_hint: Option<String>,
            _handler: ListenerEventHandler,
            _shutdown: Arc<std::sync::atomic::AtomicBool>,
            _startup: Option<crate::engine::ports::ListenerStartupSignal>,
        ) -> crate::engine::ports::PortResult<
            tokio::task::JoinHandle<crate::engine::ports::PortResult<()>>,
        > {
            Err(anyhow!("daemon listener runtime should not be used"))
        }
    }

    impl RuleActionTelemetry for UnusedPorts {
        fn record_rule_action(&self, _action: &'static str, _status: &'static str) {}

        fn record_rule_executor_drop(&self, _action: &'static str, _reason: &'static str) {}
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
        let unused = Arc::new(UnusedPorts);
        let dependencies = EngineDependencies {
            target_resolver: unused.clone(),
            privilege_checker: unused.clone(),
            packet_planner: unused.clone(),
            packet_transmitter: unused.clone(),
            listener_runner: unused.clone(),
            #[cfg(feature = "daemon")]
            daemon_listener_runtime: unused.clone(),
            dns_client: Arc::new(FakeDnsClient),
            #[cfg(feature = "traceroute")]
            traceroute_runner: unused.clone(),
            #[cfg(feature = "scan")]
            scan_runner: unused.clone(),
            #[cfg(feature = "fuzz")]
            fuzz_runner: unused.clone(),
            output: Arc::new(FakeOutput { state }),
            rule_action_telemetry: unused,
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
