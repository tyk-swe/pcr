// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

mod controller;
mod dns;
mod format;
mod report;
pub use controller::OutputController;
pub use dns::{
    format_dns_dry_run, format_dns_dry_run_json, format_dns_message, format_dns_message_json,
};
pub use format::OutputFormat;
