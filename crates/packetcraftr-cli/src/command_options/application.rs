// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::OutputBytes;
use crate::errors::CliError;
use packetcraftr_core::analysis::application::Limits;
#[derive(Clone, Copy, Debug, clap::Args)]
pub(crate) struct ApplicationLimitsArgs {
    /// Distinct application messages the collector may count across all
    /// streams over the whole run.
    #[arg(long, default_value_t = Limits::default().max_messages)]
    pub(crate) max_application_messages: usize,
    /// Distinct transport streams the collector may track over the whole run,
    /// closed streams included (TCP conversations; DNS also counts UDP flows).
    #[arg(long, default_value_t = Limits::default().max_streams)]
    pub(crate) max_application_streams: usize,
    /// Bytes buffered at once across all in-flight message parses (partial
    /// heads, body decoders, length prefixes).
    #[arg(long, default_value_t = Limits::default().max_buffer_bytes)]
    pub(crate) max_application_buffer_bytes: usize,
    /// Cumulative byte charge for retained and emitted evidence, including a
    /// flat decoded-object expansion multiplier (DNS name compression can
    /// exceed it); bounds analysis state, not serialized output (see
    /// --max-application-output-bytes).
    #[arg(long, default_value_t = Limits::default().max_retained_bytes)]
    pub(crate) max_application_retained_bytes: usize,
    /// TCP sequence spans retained to attribute deliveries to physical source
    /// frames; HTTP also bounds one message's distinct source frames.
    #[arg(long, default_value_t = Limits::default().max_source_spans)]
    pub(crate) max_application_source_spans: usize,
    /// Total serialized message, transaction, and issue bytes, in every format.
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    pub(crate) max_application_output_bytes: usize,
}
impl ApplicationLimitsArgs {
    pub(crate) fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        crate::resources::declare!(settings, self, [
            max_application_messages: Count @ ActiveState preset(256, 4096),
            max_application_streams: Count @ ActiveState preset(64, 1024),
            max_application_buffer_bytes: Bytes @ ActiveState preset(2097152, 16777216),
            max_application_retained_bytes: Bytes @ ActiveState preset(8388608, 67108864),
            max_application_source_spans: Count @ ActiveState preset(2048, 16384),
            max_application_output_bytes: Bytes @ ResultRetention preset(8388608, 67108864),
        ]);
    }

    pub(crate) fn limits(self) -> Result<ApplicationLimits, CliError> {
        Ok(ApplicationLimits {
            core: Limits {
                max_messages: self.max_application_messages,
                max_streams: self.max_application_streams,
                max_buffer_bytes: self.max_application_buffer_bytes,
                max_retained_bytes: self.max_application_retained_bytes,
                max_source_spans: self.max_application_source_spans,
            },
            max_output_bytes: OutputBytes::new(
                self.max_application_output_bytes,
                "--max-application-output-bytes",
            )?,
        })
    }
}

/// Validated `ApplicationLimitsArgs`: the analysis limits plus the bounded
/// output byte ceiling.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ApplicationLimits {
    core: Limits,
    max_output_bytes: OutputBytes,
}

impl ApplicationLimits {
    pub(crate) const fn core(self) -> Limits {
        self.core
    }

    pub(crate) const fn max_output_bytes(self) -> usize {
        self.max_output_bytes.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use packetcraftr_core::error::Kind;

    #[derive(Parser)]
    struct TestArgs {
        #[command(flatten)]
        application: ApplicationLimitsArgs,
    }

    #[test]
    fn output_byte_limits_preserve_boundaries_and_option_errors() {
        let defaults = TestArgs::parse_from(["analysis"]).application;
        for (value, valid) in [
            (0, false),
            (1, true),
            (OutputBytes::MAX, true),
            (OutputBytes::MAX + 1, false),
        ] {
            let result = ApplicationLimitsArgs {
                max_application_output_bytes: value,
                ..defaults
            }
            .limits();
            if valid {
                assert_eq!(result.unwrap().max_output_bytes(), value);
            } else {
                let error = result.unwrap_err();
                assert_eq!(error.classification.kind, Kind::Usage);
                assert_eq!(
                    error.message,
                    format!(
                        "--max-application-output-bytes must be in 1..={}",
                        OutputBytes::MAX
                    )
                );
            }
        }
    }
}
