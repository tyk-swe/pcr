// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::future::Future;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;
use log::warn;
use serde::Serialize;
use tokio::runtime::{Builder, Runtime};

use crate::cli::PacketcraftArgs;
use crate::domain::command::EngineCommand;
use crate::domain::policy::PolicyRejection;
use crate::engine::error::EngineError;
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
    run_args(args)
}

pub fn run_cli_entrypoint() -> ExitCode {
    let args = match PacketcraftArgs::try_parse() {
        Ok(args) => args,
        Err(err) => err.exit(),
    };
    let output_format = args.output_format;

    match run_args(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            ErrorReport::from_error(&err).emit(output_format);
            ExitCode::FAILURE
        }
    }
}

fn run_args(args: PacketcraftArgs) -> Result<()> {
    let app = PacketcraftApp::bootstrap(args)?;
    app.run()
}

/// Coordinates application bootstrapping and command dispatch.
struct PacketcraftApp {
    args: PacketcraftArgs,
    command: EngineCommand,
    runtime: Runtime,
    engine: engine::core::Engine,
}

impl PacketcraftApp {
    /// Build the application with its runtime and engine wiring in place.
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

        Ok(Self {
            args,
            command,
            runtime,
            engine,
        })
    }

    /// Execute the command requested by the CLI arguments.
    fn run(self) -> Result<()> {
        let PacketcraftApp {
            args,
            command,
            runtime,
            mut engine,
        } = self;
        let runtime_handle = runtime.handle().clone();

        runtime.block_on(async move {
            let telemetry = telemetry::AppTelemetry::start_if_configured(
                &args,
                engine.config(),
                &runtime_handle,
            )?;
            await_with_shutdown(dispatch::run(&mut engine, command), telemetry.shutdown()).await
        })?;

        Ok(())
    }

    fn init_logging(args: &PacketcraftArgs) -> Result<()> {
        let observability = &args.observability;
        let level_override = observability.log_level.map(|level| level.to_level_filter());
        match util::logging::init(
            args.verbose,
            level_override,
            observability.structured.unwrap_or(false),
            observability.log_file.as_deref().map(Path::new),
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

async fn await_with_shutdown<T, E, Fut, Shutdown>(
    future: Fut,
    shutdown: Shutdown,
) -> std::result::Result<T, E>
where
    Fut: Future<Output = std::result::Result<T, E>>,
    Shutdown: Future<Output = ()>,
{
    let result = future.await;
    shutdown.await;
    result
}

#[derive(Debug, Serialize)]
struct ErrorEnvelope<'a> {
    status: &'static str,
    error: &'a ErrorReport,
}

#[derive(Debug, Serialize)]
struct ErrorReport {
    kind: &'static str,
    message: String,
    causes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_code: Option<String>,
}

impl ErrorReport {
    fn from_error(err: &anyhow::Error) -> Self {
        let message = err.to_string();
        let kind = err
            .chain()
            .find_map(|source| source.downcast_ref::<EngineError>())
            .map(EngineError::kind)
            .unwrap_or("runtime");
        let policy_code = err
            .chain()
            .find_map(|source| source.downcast_ref::<PolicyRejection>())
            .map(|source| source.code.to_string());

        let mut causes = Vec::new();
        for cause in err.chain().skip(1).map(ToString::to_string) {
            if cause != message && !causes.contains(&cause) {
                causes.push(cause);
            }
        }

        Self {
            kind,
            message,
            causes,
            policy_code,
        }
    }

    fn emit(&self, output_format: Option<crate::cli::enums::OutputFormat>) {
        if matches!(output_format, Some(crate::cli::enums::OutputFormat::Json)) {
            let envelope = ErrorEnvelope {
                status: "error",
                error: self,
            };
            match serde_json::to_string_pretty(&envelope) {
                Ok(json) => println!("{json}"),
                Err(err) => {
                    eprintln!("failed to serialize error report: {err}");
                    eprintln!("error: {}", self.message);
                }
            }
        } else {
            eprintln!("error: {}", self.message);
            for cause in &self.causes {
                eprintln!("caused by: {cause}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    #[cfg(feature = "metrics")]
    use clap::Parser;

    use super::*;
    use crate::domain::policy::{PolicyRejection, PolicyRejectionCode};

    #[test]
    fn error_report_deduplicates_causes_and_keeps_engine_kind() {
        let source = anyhow::anyhow!("duplicate");
        let err = anyhow::Error::from(EngineError::PacketSpecBuild(source.context("duplicate")));

        let report = ErrorReport::from_error(&err);

        assert_eq!(report.kind, "packet_spec_build");
        assert_eq!(report.message, "failed to build packet specification");
        assert_eq!(report.causes, ["duplicate"]);
        assert_eq!(report.policy_code, None);
    }

    #[test]
    fn error_report_json_envelope_includes_policy_code() {
        let rejection = PolicyRejection::new(PolicyRejectionCode::PublicTarget, "public target");
        let err = anyhow::Error::from(EngineError::TransmissionPlan(rejection.into()));
        let report = ErrorReport::from_error(&err);
        let json = serde_json::to_value(ErrorEnvelope {
            status: "error",
            error: &report,
        })
        .unwrap();

        assert_eq!(json["status"], "error");
        assert_eq!(json["error"]["kind"], "transmission_plan");
        assert_eq!(json["error"]["message"], "failed to plan transmission");
        assert_eq!(json["error"]["policy_code"], "public_target");
        assert_eq!(json["error"]["causes"][0], "public_target: public target");
    }

    #[test]
    fn json_error_output_selection_uses_error_envelope_shape() {
        let err = anyhow::anyhow!("runtime failure");
        let report = ErrorReport::from_error(&err);
        let output_format = Some(crate::cli::enums::OutputFormat::Json);

        let json = if matches!(output_format, Some(crate::cli::enums::OutputFormat::Json)) {
            serde_json::to_value(ErrorEnvelope {
                status: "error",
                error: &report,
            })
            .unwrap()
        } else {
            serde_json::json!({ "error": report.message.clone() })
        };

        assert_eq!(json["status"], "error");
        assert_eq!(json["error"]["kind"], "runtime");
        assert_eq!(json["error"]["message"], "runtime failure");
        assert!(json["error"]["policy_code"].is_null());
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn run_starts_prometheus_exporter_inside_runtime_for_dns_dry_run() {
        let args = PacketcraftArgs::try_parse_from([
            "packetcraftr",
            "dns-query",
            "--domain",
            "example.test",
            "--prometheus-bind",
            "127.0.0.1:0",
            "--dry-run",
        ])
        .unwrap();

        run_args(args).unwrap();
    }

    #[tokio::test]
    async fn await_with_shutdown_preserves_success_and_runs_shutdown_afterwards() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let run_events = Arc::clone(&events);
        let shutdown_events = Arc::clone(&events);

        let result: std::result::Result<&'static str, &'static str> = await_with_shutdown(
            async move {
                run_events.lock().unwrap().push("run");
                Ok("done")
            },
            async move {
                shutdown_events.lock().unwrap().push("shutdown");
            },
        )
        .await;

        assert_eq!(result.unwrap(), "done");
        assert_eq!(*events.lock().unwrap(), ["run", "shutdown"]);
    }

    #[tokio::test]
    async fn await_with_shutdown_preserves_failure_and_runs_shutdown_afterwards() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let run_events = Arc::clone(&events);
        let shutdown_events = Arc::clone(&events);

        let result: std::result::Result<(), &'static str> = await_with_shutdown(
            async move {
                run_events.lock().unwrap().push("run");
                Err("dispatch failed")
            },
            async move {
                shutdown_events.lock().unwrap().push("shutdown");
            },
        )
        .await;

        assert_eq!(result.unwrap_err(), "dispatch failed");
        assert_eq!(*events.lock().unwrap(), ["run", "shutdown"]);
    }
}
