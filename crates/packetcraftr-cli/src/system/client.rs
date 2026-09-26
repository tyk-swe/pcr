// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use packetcraftr::SystemProviders;
use packetcraftr_core as core;

pub(crate) type Client = packetcraftr::Client<SystemProviders>;

/// The event runtimes a command registers, each published as one worker row
/// of the `resources` report. This table is the only place their published
/// names are spelled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Runtime {
    /// A single live operation: `send`, `exchange`, `plan`, and `replay`.
    Client,
    /// A probe workflow: `dns`, `scan`, and `traceroute`.
    Workflow,
    /// A `fuzz` campaign, live or offline.
    Fuzz,
    /// A live `capture`.
    Capture,
    /// A TCP connect `scan`.
    ScanConnect,
}

impl Runtime {
    /// The worker row name `--resource-diagnostics` publishes.
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

/// Registers `runtime` for the `resources` report and returns it.
pub(crate) fn runtime(runtime: Runtime) -> packetcraftr::runtime::Runtime {
    crate::resources::runtime(runtime.name(), packetcraftr::runtime::MAX_WORKER_CAPACITY)
}

/// The one client a command runs its workflows on: every system provider,
/// the installed cancellation signal, and its one event `runtime`.
pub(crate) fn client(
    registry: Arc<core::registry::Registry>,
    policy: impl Into<Arc<packetcraftr::policy::Policy>>,
    runtime: Runtime,
) -> Client {
    Client::new(registry, policy, SystemProviders)
        .with_runtime(self::runtime(runtime))
        .with_cancellation(crate::cancellation::signal().clone())
}
