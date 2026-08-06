// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::Duration;

use packetcraftr::{client, packet, workflow};

use crate::errors::CliError;
use crate::system::{DeferredInterface, system_client};

pub(super) struct CliFuzzExecutor {
    pub(super) registry: Arc<packet::registry::Registry>,
    pub(super) policy: client::policy::Policy,
    pub(super) exchange: client::exchange::Options,
    pub(super) interface: DeferredInterface,
}

impl workflow::fuzz::Executor for CliFuzzExecutor {
    fn execute(
        &mut self,
        case: &workflow::fuzz::ExecutionCase,
        timeout: Duration,
    ) -> Result<workflow::fuzz::Execution, workflow::BoundaryError> {
        self.interface
            .resolve_into(&mut self.exchange.send.plan)
            .map_err(CliError::into_boundary_error)?;
        let client = system_client(Arc::clone(&self.registry), self.policy.clone());
        workflow::fuzz::ClientExecutor::new(&client, self.exchange.clone()).execute(case, timeout)
    }
}
