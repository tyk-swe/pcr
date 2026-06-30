// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use anyhow::Result;

use crate::cli::PacketcraftArgs;
use crate::domain::command::EngineCommand;
use crate::engine::core::Engine;

pub(crate) struct DaemonBootstrap;

impl DaemonBootstrap {
    pub(crate) fn prepare(_args: &PacketcraftArgs, _command: &EngineCommand) -> Result<Self> {
        Ok(Self)
    }

    pub(crate) fn daemonize_if_needed(_args: &PacketcraftArgs) -> Result<()> {
        Ok(())
    }

    pub(crate) fn apply_to(self, _engine: &mut Engine) {}
}
