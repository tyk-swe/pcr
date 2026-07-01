// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use anyhow::Result;
use std::sync::Arc;

use crate::domain::command::EngineCommand;
use crate::engine::core::Engine;
use crate::engine::mode::ExecutionMode;

pub(crate) async fn run(engine: &mut Engine, command: EngineCommand) -> Result<()> {
    match command {
        EngineCommand::Send(request) => {
            engine.run_one_shot(request).await?;
        }
        EngineCommand::DryRun(request) => {
            engine
                .run_one_shot_with_mode(request, ExecutionMode::Plan)
                .await?;
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
            engine.run_dns_query(&opts).await?;
        }
        EngineCommand::Doctor(opts) => {
            let output = Arc::clone(&engine.dependencies.output);
            crate::app::support::run_doctor(&output, &opts)?;
        }
        EngineCommand::Features(opts) => {
            let output = Arc::clone(&engine.dependencies.output);
            crate::app::support::run_features(&output, &opts)?;
        }
        EngineCommand::Examples(opts) => {
            let output = Arc::clone(&engine.dependencies.output);
            crate::app::support::run_examples(&output, &opts)?;
        }
        EngineCommand::Completions(opts) => {
            let output = Arc::clone(&engine.dependencies.output);
            crate::app::support::run_completions(&output, &opts)?;
        }
        EngineCommand::Man => {
            let output = Arc::clone(&engine.dependencies.output);
            crate::app::support::run_man(&output)?;
        }
        #[cfg(feature = "fuzz")]
        EngineCommand::Fuzz(opts) => {
            engine.run_fuzz(&opts).await?;
        }
    }

    Ok(())
}
