use std::path::Path;

use anyhow::{Context, Result};
use clap::Parser;
use log::warn;
use tokio::runtime::{Builder, Runtime};

use crate::cli::PacketcraftArgs;
use crate::engine::EngineCommand;
use crate::{engine, util};

pub fn run_cli() -> Result<()> {
    let args = PacketcraftArgs::parse();
    let app = PacketcraftApp::bootstrap(args)?;
    app.run()
}

/// Coordinates application bootstrapping and command dispatch.
pub struct PacketcraftApp {
    args: PacketcraftArgs,
    command: EngineCommand,
    runtime: Runtime,
    engine: engine::Engine,
    #[cfg(feature = "metrics")]
    prometheus_handle: Option<util::telemetry::PrometheusExporterHandle>,
}

impl PacketcraftApp {
    /// Build the application with its runtime, engine, and telemetry wiring in place.
    pub fn bootstrap(args: PacketcraftArgs) -> Result<Self> {
        Self::init_logging(&args)?;
        Self::maybe_daemonize(&args)?;

        let config = args.engine_config();
        let command = args.engine_command();
        let runtime = Self::build_runtime()?;

        #[cfg(feature = "metrics")]
        let prometheus_handle = Self::maybe_start_prometheus_exporter(&args, &config, &runtime)?;

        #[cfg(not(feature = "metrics"))]
        if let Some(oneshot) = args.one_shot_options() {
            if config.prometheus_bind.is_some()
                || oneshot.logging.metrics_json.is_some()
                || oneshot.logging.allow_public_metrics.unwrap_or(false)
            {
                return Err(anyhow::anyhow!(
                    "metrics options require PacketcraftR to be built with the 'metrics' feature"
                ));
            }
        }

        let engine = engine::Engine::new_with_runtime_handle(config, runtime.handle().clone())?;

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
    pub fn run(self) -> Result<()> {
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

    /// Access the derived engine configuration for testing or telemetry wiring.
    pub fn config(&self) -> &engine::EngineConfig {
        self.engine.config()
    }

    /// Whether the configured engine has any receive rules loaded.
    pub fn has_receive_rules(&self) -> bool {
        self.engine.has_receive_rules()
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
        if let crate::cli::PacketcraftCommand::Daemon(opts) = &args.command {
            util::daemon::ensure_daemonized(opts.foreground.unwrap_or(false))?;
        }
        Ok(())
    }

    #[cfg(feature = "metrics")]
    fn maybe_start_prometheus_exporter(
        args: &PacketcraftArgs,
        config: &engine::EngineConfig,
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
            Ok(Some(util::telemetry::spawn_prometheus_exporter(
                runtime.handle(),
                bind,
            )?))
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
}

#[cfg(test)]
mod tests {
    use serial_test::serial;

    use super::*;
    use crate::cli::{OutputFormat, PacketcraftCommand, SendOptions};

    fn minimal_args() -> PacketcraftArgs {
        PacketcraftArgs {
            verbose: 0,
            output_format: None,
            dry_run: false,
            command: PacketcraftCommand::Send(SendOptions::default()),
        }
    }

    #[test]
    #[serial]
    fn bootstrap_builds_engine_and_config() {
        let mut args = minimal_args();
        args.output_format = Some(OutputFormat::Json);

        let app = PacketcraftApp::bootstrap(args).expect("bootstrap should succeed");

        assert!(app.config().output_format.is_some());
        assert!(!app.has_receive_rules());
    }

    #[cfg(feature = "metrics")]
    #[test]
    #[serial]
    fn bootstrap_fails_non_loopback_prometheus_without_flag() {
        let mut args = minimal_args();
        if let PacketcraftCommand::Send(options) = &mut args.command {
            options.oneshot.logging.prometheus_bind = Some("0.0.0.0:9090".to_string());
        }

        let result = PacketcraftApp::bootstrap(args);
        match result {
            Ok(_) => panic!("expected error"),
            Err(e) => assert!(e.to_string().contains("not a loopback address")),
        }
    }
}
