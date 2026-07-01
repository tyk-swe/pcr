// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

mod controller;
mod diagnostic;
mod dns;
mod format;
mod report;
mod writer;
pub(crate) use controller::OutputController;
pub(crate) use diagnostic::CliDiagnostic;
pub(crate) use dns::{
    format_dns_dry_run, format_dns_dry_run_json, format_dns_message, format_dns_message_json,
};
pub(crate) use format::OutputFormat;
#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use writer::BufferOutputWriter;
pub(crate) use writer::{OutputWriter, StdOutputWriter};
