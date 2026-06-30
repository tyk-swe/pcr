// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::Path;

use anyhow::{Context, Result};
use clap::Parser;
use log::warn;
use tokio::runtime::{Builder, Runtime};

use crate::cli::PacketcraftArgs;
use crate::domain::command::EngineCommand;
use crate::{engine, util};

mod adapters;
mod cli_mapping;
mod daemon_bootstrap;
mod dependencies;
mod dispatch;
#[cfg(feature = "repl")]
mod repl_engine;
mod telemetry;

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
    telemetry: telemetry::AppTelemetry,
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
        telemetry::AppTelemetry::validate_requested_options(&args, &config)?;
        let command = args.engine_command();

        let daemon_bootstrap = daemon_bootstrap::DaemonBootstrap::prepare(&args, &command)?;
        daemon_bootstrap::DaemonBootstrap::daemonize_if_needed(&args)?;

        let runtime = Self::build_runtime()?;
        let dependencies = dependencies::system(args.output_format);
        let mut engine = engine::core::Engine::new_with_runtime_handle(
            config,
            dependencies,
            runtime.handle().clone(),
        )?;
        daemon_bootstrap.apply_to(&mut engine);

        let telemetry =
            telemetry::AppTelemetry::start_if_configured(&args, engine.config(), runtime.handle())?;

        Ok(Self {
            args,
            command,
            runtime,
            engine,
            telemetry,
        })
    }

    /// Execute the command requested by the CLI arguments.
    fn run(self) -> Result<()> {
        let _args = self.args;
        let command = self.command;
        let mut engine = self.engine;
        let telemetry = self.telemetry;

        self.runtime.block_on(async {
            dispatch::run(&mut engine, command).await?;
            telemetry.shutdown().await;

            Ok::<(), anyhow::Error>(())
        })?;

        Ok(())
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

    fn build_runtime() -> Result<Runtime> {
        Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("initialise tokio runtime failed: builder construction error")
    }
}
