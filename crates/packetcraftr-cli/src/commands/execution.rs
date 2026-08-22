// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Live workflow executor shared by the probe-driven commands. Each workflow
//! trait resolves the deferred interface once, then delegates to the exchange.

use std::time::Duration;

use crate::errors::CliError;
use crate::system::{Client, DeferredInterface, Exchange};

pub(super) struct Executor {
    pub(super) client: Client,
    pub(super) exchange: packetcraftr::exchange::Options,
    pub(super) interface: DeferredInterface,
}

impl Executor {
    fn prepared(&mut self) -> Result<Exchange<'_>, CliError> {
        self.interface.apply(&mut self.exchange.send.plan)?;
        Ok(packetcraftr::ExchangeExecutor::new(
            &self.client,
            self.exchange.clone(),
        ))
    }
}

impl packetcraftr::dns::Executor for Executor {
    fn execute(
        &mut self,
        exchange: &packetcraftr::dns::Exchange,
    ) -> Result<packetcraftr::dns::Execution, packetcraftr::BoundaryError> {
        self.prepared()
            .map_err(CliError::into_boundary_error)?
            .execute(exchange)
    }
}

impl packetcraftr::scan::Executor for Executor {
    fn execute(
        &mut self,
        batch: &packetcraftr::scan::Batch,
    ) -> Result<packetcraftr::scan::Execution, packetcraftr::BoundaryError> {
        self.prepared()
            .map_err(CliError::into_boundary_error)?
            .execute(batch)
    }
}

impl packetcraftr::traceroute::Executor for Executor {
    fn execute(
        &mut self,
        batch: &packetcraftr::traceroute::Batch,
    ) -> Result<packetcraftr::traceroute::Execution, packetcraftr::BoundaryError> {
        self.prepared()
            .map_err(CliError::into_boundary_error)?
            .execute(batch)
    }
}

impl packetcraftr::fuzz::Executor for Executor {
    fn execute(
        &mut self,
        case: &packetcraftr::fuzz::ExecutionCase,
        timeout: Duration,
    ) -> Result<packetcraftr::fuzz::Execution, packetcraftr::BoundaryError> {
        self.prepared()
            .map_err(CliError::into_boundary_error)?
            .execute(case, timeout)
    }
}
