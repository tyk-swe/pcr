// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::{client, workflow};

use crate::errors::CliError;
use crate::runtime::{DeferredInterface, SystemClient};

pub(super) struct CliTracerouteExecutor {
    pub(super) client: SystemClient,
    pub(super) exchange: client::exchange::Options,
    pub(super) interface: DeferredInterface,
}

impl workflow::traceroute::Executor for CliTracerouteExecutor {
    fn execute(
        &mut self,
        batch: &workflow::traceroute::Batch,
    ) -> Result<workflow::traceroute::Execution, workflow::BoundaryError> {
        self.interface
            .resolve_into(&mut self.exchange.send.plan)
            .map_err(CliError::into_boundary_error)?;
        workflow::traceroute::ClientExecutor::new(&self.client, self.exchange.clone())
            .execute(batch)
    }
}
