// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_core::error::Kind;

use crate::command_options::Bounded;
use crate::errors::CliError;
use crate::output::contract::{Format, FormatSubset};
use crate::rendering::StreamEncoder;
use crate::resources::Settings;

pub(crate) use dispatch::run;
pub use registry::Command;
pub(crate) use registry::CommandLine;

mod build;
mod capture;
mod dispatch;
mod dissect;
mod dns;
mod dns_read;
mod documentation;
mod exchange;
mod execution;
mod expert;
mod export;
mod follow;
mod fragment;
mod fuzz;
mod http;
mod interfaces;
mod merge;
mod offline_analysis;
mod plan;
mod protocols;
mod read;
mod registry;
mod replay;
mod rewrite;
mod routes;
mod scan;
mod send;
mod stats;
#[cfg(test)]
mod test_support;
mod tls;
mod topics;
mod traceroute;
mod verify_forwarding;

pub(crate) trait Spec: Sized {
    type Format: FormatSubset;

    /// Whether shared cancellation is installed before dispatch.
    const CANCELLATION: bool;

    const OFFLINE: bool = false;

    fn run_time(&self) -> Option<&dyn Bounded> {
        None
    }

    fn publication_duration(&self) -> Option<Duration> {
        self.run_time().map(Bounded::max_duration)
    }

    fn resources(&self, _settings: &mut Settings<'_>) {}

    fn run(self, format: Self::Format, stream: &StreamEncoder) -> Result<CommandExit, CliError>;
}

/// An unpublished command that writes files or static text itself, so it has
/// no entry in the output schema or `Command::ALL`.
pub(crate) trait Generate: Sized {
    fn generate(self, format: Format) -> Result<(), CliError>;
}

pub(crate) struct CommandExit(u8);

impl CommandExit {
    pub(crate) const SUCCESS: Self = Self(0);

    pub(crate) const fn status(code: u8) -> Self {
        Self(code)
    }

    pub(crate) const fn get(self) -> u8 {
        self.0
    }
}

fn increment_counter(value: u64, counter: &'static str) -> Result<u64, CliError> {
    value
        .checked_add(1)
        .ok_or_else(|| CliError::new(Kind::Internal, format!("{counter} overflowed")))
}
