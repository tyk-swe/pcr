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
            println!("{}", result);
        }
        #[cfg(feature = "fuzz")]
        EngineCommand::Fuzz(opts) => {
            engine.run_fuzz(&opts).await?;
        }
    }

    Ok(())
}
