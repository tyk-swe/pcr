// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use crate::errors::CliError;
use crate::system::{Client, DeferredInterface};

pub(super) struct Executor {
    pub(super) client: Client,
    pub(super) exchange: packetcraftr::exchange::Options,
    pub(super) interface: DeferredInterface,
}

impl packetcraftr::fuzz::Executor for Executor {
    fn execute(
        &mut self,
        case: &packetcraftr::fuzz::ExecutionCase,
        timeout: Duration,
    ) -> Result<packetcraftr::fuzz::Execution, packetcraftr::BoundaryError> {
        self.interface
            .apply(&mut self.exchange.send.plan)
            .map_err(CliError::into_boundary_error)?;
        packetcraftr::ExchangeExecutor::new(&self.client, self.exchange.clone())
            .execute(case, timeout)
    }
}
