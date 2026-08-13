// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use crate::errors::CliError;
use crate::system::{DeferredInterface, SystemClient};

pub(super) struct CliFuzzExecutor {
    pub(super) client: SystemClient,
    pub(super) exchange: packetcraftr::exchange::Options,
    pub(super) interface: DeferredInterface,
}

impl packetcraftr::fuzz::Executor for CliFuzzExecutor {
    fn execute(
        &mut self,
        case: &packetcraftr::fuzz::ExecutionCase,
        timeout: Duration,
    ) -> Result<packetcraftr::fuzz::Execution, packetcraftr::BoundaryError> {
        self.interface
            .resolve_into(&mut self.exchange.send.plan)
            .map_err(CliError::into_boundary_error)?;
        packetcraftr::ExchangeExecutor::new(&self.client, self.exchange.clone())
            .execute(case, timeout)
    }
}
