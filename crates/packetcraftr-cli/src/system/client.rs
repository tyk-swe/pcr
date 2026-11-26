// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use packetcraftr::SystemProviders;
use packetcraftr_core as core;

pub(crate) type Client = packetcraftr::Client<SystemProviders>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Runtime {
    Client,
    Workflow,
    Fuzz,
    Capture,
    ScanConnect,
}

impl Runtime {
    const fn name(self) -> &'static str {
        match self {
            Self::Client => "client_progress",
            Self::Workflow => "workflow_progress",
            Self::Fuzz => "fuzz_progress",
            Self::Capture => "capture_progress",
            Self::ScanConnect => "scan_connect",
        }
    }
}

pub(crate) fn runtime(
    invocation: &crate::invocation::Invocation,
    runtime: Runtime,
) -> packetcraftr::runtime::Runtime {
    let instance = packetcraftr::runtime::Runtime::default();
    invocation.register_runtime(runtime.name(), &instance);
    instance
}

pub(crate) fn load_scope(
    invocation: &crate::invocation::Invocation,
    scope: &crate::command_options::ScopeArgs,
) -> Result<Option<packetcraftr::policy::Scope>, crate::errors::CliError> {
    let Some(path) = scope.path() else {
        return Ok(None);
    };
    let loaded = crate::input::read_scope(&invocation.control, path)?;
    invocation.apply_scope(&loaded);
    Ok(Some(loaded))
}

pub(crate) fn resolve_policy(
    invocation: &crate::invocation::Invocation,
    options: impl crate::command_options::PolicyOptions,
) -> Result<packetcraftr::policy::Policy, crate::errors::CliError> {
    let (policy, scope) = options.into_base_policy();
    match load_scope(invocation, &scope)? {
        Some(scope) => Ok(scope.narrow(&policy)),
        None => Ok(policy),
    }
}

pub(crate) fn client(
    invocation: &crate::invocation::Invocation,
    registry: Arc<core::registry::Registry>,
    policy: impl Into<Arc<packetcraftr::policy::Policy>>,
    runtime: Runtime,
) -> Client {
    let client = Client::new(registry, policy, SystemProviders)
        .with_runtime(self::runtime(invocation, runtime))
        .with_cancellation(invocation.control.cancellation.clone());
    match &invocation.control.deadline {
        Some(deadline) => client.with_deadline((**deadline).clone()),
        None => client,
    }
}
