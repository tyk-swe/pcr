// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! One module per CLI command, plus the pieces several of them share.
//!
//! Every command has the same shape: `commands/<cmd>.rs` drives the command
//! (validation, composition, the workflow run, and the format dispatch),
//! `commands/<cmd>/arguments.rs` holds its clap `Args` and `--help` text, and
//! `commands/<cmd>/rendering.rs` formats text from the command's output
//! types and never runs a workflow. A command may add helper modules beside
//! them (`capture/files.rs`, `replay/selection.rs`). Clap groups several
//! commands share live under `command_options` (`SendArgs` serves `send` and
//! `exchange`; `--max-duration-ms`, `--timeout-ms`, and `--compression` are
//! one group each); a group only one command uses lives in that command's
//! `arguments`.
//!
//! Every command's `Args` implements [`Spec`], and the `commands!` declaration
//! in [`registry`] lists each command once. Dispatch, the output contract,
//! presets, and resource diagnostics read their facts from those two places, so
//! adding a command is one [`Spec`] implementation plus one declared variant.
//! [`dispatch`] owns the command lifecycle; [`execution`] selects streaming
//! or collecting workflow entry points. Shared output mechanics live in
//! `rendering`, while `system` composes providers and runtimes.

use std::time::Duration;

use packetcraftr_core::error::Kind;

use crate::command_options::Bounded;
use crate::errors::CliError;
use crate::output::contract::FormatSubset;
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
mod tls;
mod traceroute;
mod verify_forwarding;

/// What one command declares about itself, and how it runs.
///
/// Implemented by each command's `Args`. Dispatch, the output contract,
/// `--resource-preset`, and `--resource-diagnostics` read these facts instead
/// of keeping per-command tables of their own.
pub(crate) trait Spec: Sized {
    /// The narrow format enum `run` matches; its
    /// [`FORMATS`](FormatSubset::FORMATS) are the formats the command's
    /// output contract admits.
    type Format: FormatSubset;

    /// Whether shared cancellation is installed before dispatch. Build
    /// installs its own handler after loading its blocking recipe input.
    const CANCELLATION: bool;

    /// Whether the command analyzes capture files offline. Only offline
    /// commands accept `--resource-preset`, and their capture-reader bounds
    /// are physical-input settings rather than operation settings.
    const OFFLINE: bool = false;

    /// The argument group whose `--max-duration-ms` bounds the command's run
    /// time, if the command has one.
    fn run_time(&self) -> Option<&dyn Bounded> {
        None
    }

    /// The operation deadline the invocation publishes under, if the command
    /// bounds its run time.
    fn publication_duration(&self) -> Option<Duration> {
        self.run_time().map(Bounded::max_duration)
    }

    /// Declares the command's resource settings for `--resource-diagnostics`.
    fn resources(&self, _settings: &mut Settings<'_>) {}

    /// Runs the command with its format already narrowed and checked.
    fn run(self, format: Self::Format, stream: &StreamEncoder) -> Result<CommandExit, CliError>;
}

/// The process status of a command that published its output.
///
/// Almost every successful command exits [`CommandExit::SUCCESS`]. A command
/// whose result is a verdict rather than an operation — `verify-forwarding` —
/// reports the verdict's status through this without emitting a second,
/// contradictory error record over its completed output.
pub(crate) struct CommandExit(u8);

impl CommandExit {
    /// Exit status 0.
    pub(crate) const SUCCESS: Self = Self(0);

    /// An explicit non-success status for a completed command.
    pub(crate) const fn status(code: u8) -> Self {
        Self(code)
    }

    /// The process exit code.
    pub(crate) const fn get(self) -> u8 {
        self.0
    }
}

fn increment_counter(value: u64, counter: &'static str) -> Result<u64, CliError> {
    value
        .checked_add(1)
        .ok_or_else(|| CliError::new(Kind::Internal, format!("{counter} overflowed")))
}
