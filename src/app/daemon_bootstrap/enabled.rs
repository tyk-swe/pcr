// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use anyhow::Result;

use crate::cli::commands::PacketcraftCommand;
use crate::cli::PacketcraftArgs;
use crate::domain::command::EngineCommand;
use crate::engine::core::Engine;
use crate::engine::daemon::DaemonStartupPreflight;
use crate::util;

pub(crate) struct DaemonBootstrap {
    preflight: Option<DaemonStartupPreflight>,
}

impl DaemonBootstrap {
    pub(crate) fn prepare(args: &PacketcraftArgs, command: &EngineCommand) -> Result<Self> {
        let preflight = if args.effective_dry_run() {
            None
        } else if let EngineCommand::Daemon(opts) = command {
            Some(crate::engine::daemon::preflight(opts)?)
        } else {
            None
        };

        Ok(Self { preflight })
    }

    pub(crate) fn daemonize_if_needed(args: &PacketcraftArgs) -> Result<()> {
        if args.effective_dry_run() {
            return Ok(());
        }

        if let PacketcraftCommand::Daemon(opts) = &args.command {
            util::daemon::ensure_daemonized(opts.foreground.unwrap_or(false))?;
        }

        Ok(())
    }

    pub(crate) fn apply_to(self, engine: &mut Engine) {
        if let Some(preflight) = self.preflight {
            engine.apply_daemon_preflight(preflight);
        }
    }
}
