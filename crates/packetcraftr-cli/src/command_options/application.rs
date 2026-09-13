// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::errors::CliError;
use packetcraftr_core::analysis::application::Limits;
#[derive(Clone, Copy, Debug, clap::Args)]
pub(crate) struct ApplicationLimitsArgs {
    #[arg(long,default_value_t=Limits::default().max_messages)]
    pub(crate) max_application_messages: usize,
    #[arg(long,default_value_t=Limits::default().max_streams)]
    pub(crate) max_application_streams: usize,
    #[arg(long,default_value_t=Limits::default().max_buffer_bytes)]
    pub(crate) max_application_buffer_bytes: usize,
    #[arg(long,default_value_t=Limits::default().max_retained_bytes)]
    pub(crate) max_application_retained_bytes: usize,
    #[arg(long,default_value_t=Limits::default().max_source_spans)]
    pub(crate) max_application_source_spans: usize,
    /// Total serialized message, transaction, and issue bytes, in every format.
    #[arg(long,default_value_t=64*1024*1024)]
    pub(crate) max_application_output_bytes: usize,
}
impl ApplicationLimitsArgs {
    pub(crate) fn core(self) -> Limits {
        Limits {
            max_messages: self.max_application_messages,
            max_streams: self.max_application_streams,
            max_buffer_bytes: self.max_application_buffer_bytes,
            max_retained_bytes: self.max_application_retained_bytes,
            max_source_spans: self.max_application_source_spans,
        }
    }
    pub(crate) fn validate_output(self) -> Result<(), CliError> {
        if self.max_application_output_bytes == 0
            || self.max_application_output_bytes > 256 * 1024 * 1024
        {
            return Err(CliError::new(
                packetcraftr_core::error::Kind::Cli,
                "--max-application-output-bytes must be in 1..=268435456",
            ));
        }
        Ok(())
    }
}
