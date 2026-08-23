// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::{
    BoundaryError,
    core::error::{Classification, Classified, Kind},
    netio as net,
};

pub(crate) const ARGUMENTS: Classification = Classification::new(
    "cli.arguments",
    Some("run the command with --help and correct the reported argument"),
);
pub(crate) const INTERFACE_SELECTOR: Classification = Classification::new(
    "cli.interface_selector",
    Some("use a non-empty interface name or a non-zero numeric interface index"),
);
pub(crate) const FOLLOW_STREAM: Classification = Classification::new(
    "cli.follow_stream",
    Some("use a stream selector in the form tcp:<stream-id> or udp:<stream-id>"),
);
pub(crate) const REPLAY_TIMING: Classification = Classification::new(
    "cli.replay_timing",
    Some("use replay timing options that do not conflict"),
);
#[allow(dead_code)]
pub(crate) const LIVE_LIMIT: Classification = Classification::new(
    "cli.live_limit",
    Some("use a valid finite non-zero live request value within the documented limit"),
);
pub(crate) const CAPTURE_LIMIT: Classification = Classification::new(
    "cli.capture_limit",
    Some("use non-zero capture limits whose snap length fits the aggregate byte ceiling"),
);
pub(crate) const INPUT_READ: Classification = Classification::new(
    "cli.input_read",
    Some("check that the input exists, is readable, and uses the expected encoding"),
);
pub(crate) const INPUT_LIMIT: Classification = Classification::new(
    "cli.input_limit",
    Some("reduce the input size or raise the applicable input limit"),
);
pub(crate) const OUTPUT_WRITE: Classification = Classification::new(
    "io.output_write",
    Some("check the output destination and available storage before retrying"),
);
pub(crate) const CAPTURE_OUTPUT: Classification = Classification::new(
    "io.capture_output",
    Some("inspect the capture output destination and metadata before retrying"),
);
pub(crate) const INVARIANT: Classification = Classification::new(
    "internal.invariant",
    Some("report this internal invariant failure with the command and input that triggered it"),
);
pub(crate) const RECIPE_INPUT_SOURCE: Classification = Classification::new(
    "cli.input_source",
    Some("provide --packet, --packet-file, or pipe a non-empty packet recipe to stdin"),
);
pub(crate) const FRAME_INPUT_SOURCE: Classification = Classification::new(
    "cli.input_source",
    Some("provide --hex, --file, or pipe non-empty frame bytes to stdin"),
);
pub(crate) const FILTER_UNSUPPORTED_FIELD: Classification = Classification::new(
    "cli.filter_unsupported_field",
    Some(
        "use `follow`, `stats`, or `expert` for stream-aware filters, or filter on header fields instead",
    ),
);
pub(crate) const DISSECT_UNSUPPORTED_FORMAT: Classification = Classification::new(
    "cli.dissect_unsupported_format",
    Some("use --output text or --output ndjson to show the layer stack"),
);
pub(crate) const CAPTURE_REWRITE_FILTER: Classification = Classification::new(
    "cli.capture_rewrite_filter",
    Some("use text, hex, or ndjson output to filter frames"),
);
pub(crate) const CAPTURE_REWRITE_FORMAT: Classification = Classification::new(
    "cli.capture_rewrite_format",
    Some("select the capture output format matching the input capture"),
);
pub(crate) const TIMESTAMP_UNAVAILABLE: Classification = Classification::new(
    "packet.timestamp_unavailable",
    Some("remove frame.time_epoch from the filter or use timestamped packet blocks"),
);
pub(crate) const UNKNOWN_PROTOCOL: Classification = Classification::new(
    "cli.protocol",
    Some("run `packetcraftr protocols` to list built-in protocols"),
);

pub(crate) const fn exit_code_for_kind(kind: Kind) -> u8 {
    match kind {
        Kind::Cli => 2,
        Kind::Packet => 3,
        Kind::Capability => 4,
        Kind::Io => 5,
        Kind::Policy => 6,
        Kind::Internal => 70,
    }
}

pub(crate) fn exit_code(error: &BoundaryError) -> u8 {
    exit_code_for_kind(error.classification().kind)
}

pub(crate) fn with_cleanup(error: BoundaryError, cleanup: &net::Error) -> BoundaryError {
    let operation = error.to_string();
    let classification = error.classification();
    let context = error.context();
    let mut causes = error.causes();
    if causes.is_empty() {
        causes.push(operation.clone());
    }
    causes.push(cleanup.to_string());
    BoundaryError::with_source(
        format!("{operation}; capture shutdown also failed: {cleanup}"),
        classification,
        causes,
        error,
    )
    .with_context(context)
}

pub(crate) fn failure(classification: Classification, message: impl Into<String>) -> BoundaryError {
    BoundaryError::new(message, classification, Vec::new())
}

#[cfg(test)]
pub(crate) const fn test_classification(
    code: &'static str,
    remediation: Option<&'static str>,
) -> Classification {
    Classification::new(code, remediation)
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use super::*;

    #[test]
    fn classifications_map_to_stable_exit_codes() {
        let cases = [
            (Kind::Cli, 2),
            (Kind::Packet, 3),
            (Kind::Capability, 4),
            (Kind::Io, 5),
            (Kind::Policy, 6),
            (Kind::Internal, 70),
        ];

        for (kind, exit_code) in cases {
            assert_eq!(exit_code_for_kind(kind), exit_code);
        }
    }

    #[test]
    fn cleanup_failure_keeps_the_primary_error() {
        let cleanup = net::Error::Capture {
            message: "receiver stopped".to_owned(),
        };
        let error = with_cleanup(failure(OUTPUT_WRITE, "capture failed"), &cleanup);
        assert_eq!(
            error.to_string(),
            format!("capture failed; capture shutdown also failed: {cleanup}")
        );
        assert_eq!(
            error.causes(),
            vec!["capture failed".to_owned(), cleanup.to_string()]
        );
        assert_eq!(
            error.source().map(ToString::to_string),
            Some("capture failed".to_owned())
        );

        let error = with_cleanup(
            BoundaryError::new(
                "capture failed",
                Classification::new("io.fixture", None),
                vec!["original source".to_owned()],
            ),
            &cleanup,
        );
        assert_eq!(
            error.causes(),
            vec!["original source".to_owned(), cleanup.to_string()]
        );
    }
}
