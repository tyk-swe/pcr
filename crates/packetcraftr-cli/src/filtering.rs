// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use packetcraftr_core as core;
use packetcraftr_core::error::Classification;
use packetcraftr_core::error::Coordinate;
use packetcraftr_core::error::Kind;
use packetcraftr_core::filter::Context;
use packetcraftr_core::filter::Filter;
use packetcraftr_core::frame::Frame;
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

/// Compiles a display filter for a command, or reports why it cannot run there.
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
                Kind::Cli,
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

/// Decodes complete bounded frames and applies an optional display filter, so
/// every frame-at-a-time command dissects, budgets, and classifies identically.
#[derive(Debug)]
pub(crate) struct FrameDecoder {
    decoder: core::decode::Dissector,
    filter: Option<Filter>,
    max_frame_bytes: usize,
}

impl FrameDecoder {
    pub(crate) fn new(
        registry: Arc<Registry>,
        filter: Option<Filter>,
        max_frame_bytes: usize,
    ) -> Self {
        Self {
            decoder: core::decode::Dissector::new(registry),
            filter,
            max_frame_bytes,
        }
    }

    /// Compiles `source` (if any) with `Capabilities::frames_only()`.
    pub(crate) fn compile(
        registry: &Arc<Registry>,
        source: Option<&str>,
        max_frame_bytes: usize,
    ) -> Result<Self, CliError> {
        let filter = source
            .map(|source| compile(source, registry, Capabilities::frames_only()))
            .transpose()?;
        Ok(Self::new(Arc::clone(registry), filter, max_frame_bytes))
    }

    /// Dissects `frame` under this decoder's bounded packet budget.
    pub(crate) fn decode(&self, frame: &Frame) -> Result<core::decode::DecodedPacket, CliError> {
        self.decoder
            .decode(
                frame.clone(),
                core::decode::Options {
                    max_packet_size: self.max_frame_bytes,
                    ..core::decode::Options::default()
                },
            )
            .map_err(CliError::classified)
    }

    /// Decodes then evaluates the filter with `derived=&[]` and no stream
    /// indexes; `Ok(None)` means the frame decoded but was not selected.
    /// Failures carry the source frame as their coordinate.
    pub(crate) fn decode_selected(
        &self,
        source_frame: u64,
        frame: &Frame,
    ) -> Result<Option<core::decode::DecodedPacket>, CliError> {
        let context = Some(Coordinate::SourceFrame(source_frame));
        let decoded = self
            .decode(frame)
            .map_err(|error| error.with_context(context))?;
        if let Some(filter) = &self.filter {
            let keep = filter
                .matches(&Context {
                    decoded: &decoded,
                    derived: &[],
                    number: source_frame,
                    tcp_stream: None,
                    udp_stream: None,
                })
                .map_err(|error| CliError::classified(error).with_context(context))?;
            if !keep {
                return Ok(None);
            }
        }
        Ok(Some(decoded))
    }
}

/// Evaluates a compiled filter against complete bounded frames.
///
/// Undissectable frames are errors rather than silent mismatches.
#[derive(Debug)]
pub(crate) struct FrameSelector(FrameDecoder);

impl FrameSelector {
    pub(crate) fn new(registry: Arc<Registry>, filter: Filter, max_frame_bytes: usize) -> Self {
        Self(FrameDecoder::new(registry, Some(filter), max_frame_bytes))
    }

    /// Compiles an optional display filter into a [`FrameSelector`].
    pub(crate) fn compile_optional(
        source: Option<&str>,
        registry: &Arc<Registry>,
        max_frame_bytes: usize,
    ) -> Result<Option<Self>, CliError> {
        source
            .map(|source| {
                let filter = compile(source, registry, Capabilities::frames_only())?;
                Ok(Self::new(Arc::clone(registry), filter, max_frame_bytes))
            })
            .transpose()
    }

    /// Decides whether the one-based `source_frame` is kept.
    pub(crate) fn keep(&self, source_frame: u64, frame: &Frame) -> Result<bool, CliError> {
        self.0
            .decode_selected(source_frame, frame)
            .map(|decoded| decoded.is_some())
    }
}

impl packetcraftr::replay::Selector for FrameSelector {
    fn select(
        &mut self,
        source_frame: u64,
        frame: &Frame,
    ) -> Result<bool, packetcraftr_core::error::BoundaryError> {
        self.keep(source_frame, frame)
            .map_err(CliError::into_boundary_error)
    }
}

/// Evaluates a compiled filter against a dissection the caller already owns,
/// so commands that decode a frame for output do not decode it again to filter.
pub(crate) fn matches_decoded(filter: &Filter, context: &Context<'_>) -> Result<bool, CliError> {
    filter.matches(context).map_err(CliError::classified)
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use packetcraftr_core::{frame::LinkType, protocol::builtin};

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
    fn selector_uses_frame_context_and_surfaces_decode_limits() {
        let registry = registry();
        let filter = compile(
            "frame.number == 2 && frame.len == 14",
            &registry,
            Capabilities::frames_only(),
        )
        .expect("frame metadata filter");
        let frame = Frame::new(UNIX_EPOCH, LinkType::ETHERNET, vec![0_u8; 14])
            .expect("bounded Ethernet frame");
        let selector = FrameSelector::new(Arc::clone(&registry), filter, 14);

        assert!(!selector.keep(1, &frame).expect("frame dissects"));
        assert!(selector.keep(2, &frame).expect("frame dissects"));

        let filter = compile("frame.number == 2", &registry, Capabilities::frames_only()).unwrap();
        let too_small = FrameSelector::new(registry, filter, 13);
        let error = too_small
            .keep(2, &frame)
            .expect_err("decode errors cannot become silent mismatches");
        assert_eq!(error.classification.code, "policy.decode_resource_limit");
        assert_eq!(error.exit_code(), 6);
    }

    #[test]
    fn compile_optional_handles_none_valid_and_invalid_filters() {
        let registry = registry();
        let none_selector = FrameSelector::compile_optional(None, &registry, 14)
            .expect("absent filter compiles to None");
        assert!(none_selector.is_none());

        let some_selector = FrameSelector::compile_optional(Some("frame.len == 14"), &registry, 14)
            .expect("valid filter compiles to Some")
            .expect("selector is present");
        let frame = Frame::new(UNIX_EPOCH, LinkType::ETHERNET, vec![0_u8; 14])
            .expect("bounded Ethernet frame");
        assert!(some_selector.keep(1, &frame).expect("frame dissects"));

        let stream_error = FrameSelector::compile_optional(Some("tcp.stream == 1"), &registry, 14)
            .expect_err("stream field rejected under frames_only capability");
        assert_eq!(
            stream_error.classification.code,
            "cli.filter_unsupported_field"
        );

        let syntax_error = FrameSelector::compile_optional(Some("(ethernet"), &registry, 14)
            .expect_err("malformed filter rejected");
        assert_eq!(syntax_error.classification.code, "cli.filter");
    }
}
