// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
#[cfg(feature = "metrics")]
use log::info;
use log::warn;
use tokio::runtime::{Builder, Runtime};

use crate::cli::PacketcraftArgs;
use crate::domain::command::EngineCommand;
use crate::{engine, util};

mod adapters;
mod cli_mapping;
#[cfg(feature = "repl")]
mod repl_engine;

pub fn run_cli() -> Result<()> {
    let args = PacketcraftArgs::parse();
    let app = PacketcraftApp::bootstrap(args)?;
    app.run()
}

/// Coordinates application bootstrapping and command dispatch.
struct PacketcraftApp {
    args: PacketcraftArgs,
    command: EngineCommand,
    runtime: Runtime,
    engine: engine::core::Engine,
    #[cfg(feature = "metrics")]
    prometheus_handle: Option<util::telemetry::PrometheusExporterHandle>,
}

impl PacketcraftApp {
    /// Build the application with its runtime, engine, and telemetry wiring in place.
    fn bootstrap(args: PacketcraftArgs) -> Result<Self> {
        Self::init_logging(&args)?;

        let config = args.engine_config();
        config
            .traffic_policy
            .validate_configuration()
            .map_err(anyhow::Error::from)?;
        let command = args.engine_command();

        #[cfg(feature = "daemon")]
        let daemon_preflight = Self::preflight_daemon_if_needed(&args, &command)?;

        Self::maybe_daemonize(&args)?;

        let runtime = Self::build_runtime()?;
        let dependencies = Self::build_engine_dependencies(args.output_format);
        let engine = engine::core::Engine::new_with_runtime_handle(
            config,
            dependencies,
            runtime.handle().clone(),
        )?;

        #[cfg(feature = "daemon")]
        let mut engine = engine;

        #[cfg(feature = "daemon")]
        if let Some(preflight) = daemon_preflight {
            engine.apply_daemon_preflight(preflight);
        }

        #[cfg(feature = "metrics")]
        let prometheus_handle =
            Self::maybe_start_prometheus_exporter(&args, engine.config(), &runtime)?;

        #[cfg(not(feature = "metrics"))]
        if let Some(oneshot) = args.one_shot_options() {
            if engine.config().prometheus_bind.is_some()
                || oneshot.logging.metrics_json.is_some()
                || oneshot.logging.allow_public_metrics.unwrap_or(false)
            {
                return Err(anyhow::anyhow!(
                    "metrics options require PacketcraftR to be built with the 'metrics' feature"
                ));
            }
        }

        Ok(Self {
            args,
            command,
            runtime,
            engine,
            #[cfg(feature = "metrics")]
            prometheus_handle,
        })
    }

    /// Execute the command requested by the CLI arguments.
    fn run(self) -> Result<()> {
        let _args = self.args;
        let command = self.command;
        let mut engine = self.engine;
        #[cfg(feature = "metrics")]
        let mut prometheus_handle = self.prometheus_handle; // Keep handle alive

        self.runtime.block_on(async {
            match command {
                EngineCommand::Send(request) | EngineCommand::DryRun(request) => {
                    engine.run_one_shot(request).await?;
                }
                #[cfg(feature = "repl")]
                EngineCommand::Interactive(opts) => {
                    crate::cli::repl::start_session(&opts, &mut engine).await?;
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
                    println!("{}", result);
                }
                #[cfg(feature = "fuzz")]
                EngineCommand::Fuzz(opts) => {
                    engine.run_fuzz(&opts).await?;
                }
            }

            #[cfg(feature = "metrics")]
            if let Some(handle) = prometheus_handle.take() {
                let _ = handle.shutdown_tx.send(());

                if let Err(err) = handle.join_handle.await {
                    warn!("prometheus exporter task terminated with error: {err}");
                }
            }

            Ok::<(), anyhow::Error>(())
        })?;

        Ok(())
    }

    #[cfg(feature = "daemon")]
    fn preflight_daemon_if_needed(
        args: &PacketcraftArgs,
        command: &EngineCommand,
    ) -> Result<Option<crate::engine::daemon::DaemonStartupPreflight>> {
        if args.effective_dry_run() {
            return Ok(None);
        }

        if let EngineCommand::Daemon(opts) = command {
            return crate::engine::daemon::preflight(opts).map(Some);
        }

        Ok(None)
    }

    fn init_logging(args: &PacketcraftArgs) -> Result<()> {
        let logging = args.one_shot_options().map(|options| &options.logging);
        let level_override = logging
            .and_then(|options| options.log_level)
            .map(|level| level.to_level_filter());
        match util::logging::init(
            args.verbose,
            level_override,
            logging
                .and_then(|options| options.structured)
                .unwrap_or(false),
            logging
                .and_then(|options| options.log_file.as_deref())
                .map(Path::new),
        ) {
            Ok(()) => Ok(()),
            Err(util::logging::LoggingInitError::LoggerInit(_)) => {
                warn!("logging subsystem already initialized; ignoring new configuration");
                Ok(())
            }
            Err(e) => Err(anyhow::Error::new(e)).context("failed to initialize logging subsystem"),
        }
    }

    fn maybe_daemonize(args: &PacketcraftArgs) -> Result<()> {
        if args.effective_dry_run() {
            return Ok(());
        }
        #[cfg(feature = "daemon")]
        if let crate::cli::commands::PacketcraftCommand::Daemon(opts) = &args.command {
            util::daemon::ensure_daemonized(opts.foreground.unwrap_or(false))?;
        }
        Ok(())
    }

    #[cfg(feature = "metrics")]
    fn maybe_start_prometheus_exporter(
        args: &PacketcraftArgs,
        config: &engine::config::EngineConfig,
        runtime: &Runtime,
    ) -> Result<Option<util::telemetry::PrometheusExporterHandle>> {
        if let Some(bind) = config.prometheus_bind.as_deref() {
            let addr: std::net::SocketAddr = bind
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid prometheus bind address: {}", e))?;
            let allow_public_metrics = args
                .one_shot_options()
                .and_then(|options| options.logging.allow_public_metrics)
                .unwrap_or(false);
            if !addr.ip().is_loopback() && !allow_public_metrics {
                return Err(anyhow::anyhow!(
                    "prometheus bind address '{}' is not a loopback address. Use --allow-public-metrics to allow public binding.",
                    bind
                ));
            }
            let handle = util::telemetry::spawn_prometheus_exporter(runtime.handle(), bind)?;
            info!(
                "Prometheus exporter bound to http://{}/metrics",
                handle.addr
            );
            Ok(Some(handle))
        } else {
            Ok(None)
        }
    }

    fn build_runtime() -> Result<Runtime> {
        Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("initialise tokio runtime failed: builder construction error")
    }

    fn build_engine_dependencies(
        output_format: Option<crate::cli::enums::OutputFormat>,
    ) -> engine::ports::EngineDependencies {
        engine::ports::EngineDependencies {
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
}
