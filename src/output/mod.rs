mod controller;
mod dns;
mod format;
mod report;
#[cfg(any(test, feature = "test_utils"))]
pub mod test_utils;

pub use crate::engine::{ListenerEvent, ProtocolLabel};
pub use controller::OutputController;
pub use dns::{
    format_dns_dry_run, format_dns_dry_run_json, format_dns_message, format_dns_message_json,
};
pub use format::OutputFormat;
pub use report::PreflightReport;
