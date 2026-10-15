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
    OutputWriter,
}

impl Runtime {
    const fn name(self) -> &'static str {
        match self {
            Self::Client => "client_progress",
            Self::Workflow => "workflow_progress",
            Self::Fuzz => "fuzz_progress",
            Self::Capture => "capture_progress",
            Self::ScanConnect => "scan_connect",
            Self::OutputWriter => "output_writer",
        }
    }
}

pub(crate) fn runtime(
    invocation: &crate::invocation::Invocation,
    runtime: Runtime,
) -> packetcraftr::runtime::Runtime {
    let instance = match runtime {
        Runtime::OutputWriter => {
            packetcraftr::runtime::Runtime::new(1).expect("a capacity of one is within the ceiling")
        }
        _ => packetcraftr::runtime::Runtime::default(),
    };
    invocation.register_runtime(runtime.name(), &instance);
    instance
}

pub(crate) fn client(
    invocation: &crate::invocation::Invocation,
    registry: Arc<core::registry::Registry>,
    policy: impl Into<Arc<packetcraftr::policy::Policy>>,
    runtime: Runtime,
) -> Client {
    let client = Client::new(registry, policy, SystemProviders)
        .with_runtime(self::runtime(invocation, runtime))
        .with_cancellation(invocation.cancellation.clone());
    match &invocation.deadline {
        Some(deadline) => client.with_deadline((**deadline).clone()),
        None => client,
    }
}
