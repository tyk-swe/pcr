// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use packetcraftr_core as core;
use packetcraftr_core::error::Classification;
use packetcraftr_core::error::Coordinate;
use packetcraftr_core::error::Kind;
use packetcraftr_core::filter::Context;
use packetcraftr_core::filter::Filter;
use packetcraftr_core::filter::{FrameDecoder, FrameSelector};
use packetcraftr_core::registry::Registry;

use super::errors::CliError;

/// Filter capabilities a command declares before input is read.
///
/// Unsupported stream fields fail rather than silently matching no frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Capabilities {
    pub(crate) stream_index: bool,
}

impl Capabilities {
    /// A command that dissects frames one at a time and tracks no session.
    pub(crate) const fn frames_only() -> Self {
        Self {
            stream_index: false,
        }
    }

    /// A command that runs the analysis pipeline and assigns conversation
    /// indices, so `tcp.stream` and `udp.stream` resolve.
    pub(crate) const fn stream_capable() -> Self {
        Self { stream_index: true }
    }
}

pub(crate) fn compile(
    source: &str,
    registry: &Registry,
    capabilities: Capabilities,
) -> Result<Filter, CliError> {
    let filter = Filter::compile(
        source,
        registry,
        packetcraftr_core::filter::Options::default(),
    )
    .map_err(CliError::classified)?;
    if filter.requirements().stream_index && !capabilities.stream_index {
        return Err(CliError::from_classification(
            Classification::new(
                "cli.filter_unsupported_field",
                Kind::Usage,
                Some(
                    "use `follow`, `stats`, or `expert` for stream-aware filters, \
                     or filter on header fields instead",
                ),
            ),
            "this command assigns no conversation index, so the filter cannot read \
             `tcp.stream` or `udp.stream`",
            Vec::new(),
        ));
    }
    Ok(filter)
}

/// A frame selector over `source`, compiled for a command that judges frames
/// one at a time.
pub(crate) fn frame_selector(
    source: &str,
    registry: &Arc<Registry>,
    max_frame_bytes: usize,
) -> Result<FrameSelector, CliError> {
    let filter = compile(source, registry, Capabilities::frames_only())?;
    FrameSelector::new(Arc::clone(registry), filter, max_frame_bytes).map_err(CliError::classified)
}

/// [`frame_selector`] for an optional `--filter`.
pub(crate) fn optional_frame_selector(
    source: Option<&str>,
    registry: &Arc<Registry>,
    max_frame_bytes: usize,
) -> Result<Option<FrameSelector>, CliError> {
    source
        .map(|source| frame_selector(source, registry, max_frame_bytes))
        .transpose()
}

/// A frame decoder applying an optional `--filter`, so every frame-at-a-time
/// command dissects, budgets, and classifies identically.
pub(crate) fn frame_decoder(
    registry: &Arc<Registry>,
    source: Option<&str>,
    max_frame_bytes: usize,
) -> Result<FrameDecoder, CliError> {
    let filter = source
        .map(|source| compile(source, registry, Capabilities::frames_only()))
        .transpose()?;
    FrameDecoder::new(Arc::clone(registry), filter, max_frame_bytes).map_err(CliError::classified)
}

/// A frame-at-a-time decode or filter failure, at the one-based source frame
/// it stopped on.
pub(crate) fn frame_error(
    source_frame: u64,
    error: impl core::error::Classified + std::fmt::Display,
) -> CliError {
    CliError::classified(error).with_context(Some(Coordinate::SourceFrame(source_frame)))
}

/// Evaluates a compiled filter against a dissection the caller already owns,
/// so commands that decode a frame for output do not decode it again to filter.
pub(crate) fn matches_decoded(filter: &Filter, context: &Context<'_>) -> Result<bool, CliError> {
    filter.matches(context).map_err(CliError::classified)
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use packetcraftr_core::frame::{Frame, LinkType};
    use packetcraftr_core::protocol::builtin;

    use super::*;

    fn registry() -> Arc<Registry> {
        builtin::registry()
    }

    #[test]
    fn stream_fields_require_stream_capability() {
        let registry = registry();
        assert!(compile("tcp.stream == 1", &registry, Capabilities::stream_capable()).is_ok());

        let error = compile("udp.stream == 1", &registry, Capabilities::frames_only())
            .expect_err("frame-only commands lack stream indices");
        assert_eq!(error.classification.code, "cli.filter_unsupported_field");
        assert!(
            error
                .classification
                .remediation
                .is_some_and(|value| value.contains("stream-aware filters"))
        );
        assert!(error.message.contains("tcp.stream"));
    }

    #[test]
    fn frame_failures_keep_their_classification_at_the_source_frame() {
        let registry = registry();
        let frame = Frame::new(UNIX_EPOCH, LinkType::ETHERNET, vec![0_u8; 14])
            .expect("bounded Ethernet frame");
        let too_small = frame_selector("frame.number == 2", &registry, 13).unwrap();
        let error = frame_error(
            2,
            too_small
                .keep(2, &frame)
                .expect_err("decode errors cannot become silent mismatches"),
        );
        assert_eq!(error.classification.code, "policy.decode_resource_limit");
        assert_eq!(error.exit_code(), 6);
        assert_eq!(
            core::error::Classified::context(&error.into_boundary_error()),
            Some(Coordinate::SourceFrame(2))
        );
    }

    #[test]
    fn optional_selectors_handle_none_valid_and_invalid_filters() {
        let registry = registry();
        let none_selector =
            optional_frame_selector(None, &registry, 14).expect("absent filter compiles to None");
        assert!(none_selector.is_none());

        let some_selector = optional_frame_selector(Some("frame.len == 14"), &registry, 14)
            .expect("valid filter compiles to Some")
            .expect("selector is present");
        let frame = Frame::new(UNIX_EPOCH, LinkType::ETHERNET, vec![0_u8; 14])
            .expect("bounded Ethernet frame");
        assert!(some_selector.keep(1, &frame).expect("frame dissects"));

        let stream_error = optional_frame_selector(Some("tcp.stream == 1"), &registry, 14)
            .expect_err("stream field rejected under frames_only capability");
        assert_eq!(
            stream_error.classification.code,
            "cli.filter_unsupported_field"
        );

        let syntax_error = optional_frame_selector(Some("(ethernet"), &registry, 14)
            .expect_err("malformed filter rejected");
        assert_eq!(syntax_error.classification.code, "cli.filter");
    }
}
