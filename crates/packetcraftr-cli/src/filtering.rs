// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use packetcraftr::{
    core::error::{Classification, Kind},
    core::frame::Frame,
    core::{
        self,
        filter::{Context, Filter},
        registry::Registry,
    },
};

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
        packetcraftr::core::filter::Options::default(),
    )
    .map_err(cli_error)?;
    if filter.requirements().stream_index && !capabilities.stream_index {
        return Err(CliError::from_classification(
            Classification::new(
                "request.filter_unsupported_field",
                Kind::Request,
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

/// Evaluates a compiled filter against complete bounded frames.
///
/// Undissectable frames are errors rather than silent mismatches.
#[derive(Debug)]
pub(crate) struct FrameSelector {
    decoder: core::decode::Dissector,
    filter: Filter,
    max_frame_bytes: usize,
}

impl FrameSelector {
    pub(crate) fn new(registry: Arc<Registry>, filter: Filter, max_frame_bytes: usize) -> Self {
        Self {
            decoder: core::decode::Dissector::new(registry),
            filter,
            max_frame_bytes,
        }
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
        let decoded = self
            .decoder
            .decode(
                frame.clone(),
                core::decode::Options {
                    max_packet_size: self.max_frame_bytes,
                    ..core::decode::Options::default()
                },
            )
            .map_err(|source| CliError::new(3, source.to_string()))?;
        self.filter
            .matches(&Context {
                decoded: &decoded,
                number: source_frame,
                tcp_stream: None,
                udp_stream: None,
            })
            .map_err(cli_error)
    }
}

impl packetcraftr::replay::Selector for FrameSelector {
    fn select(
        &mut self,
        source_frame: u64,
        frame: &Frame,
    ) -> Result<bool, packetcraftr::BoundaryError> {
        self.keep(source_frame, frame)
            .map_err(CliError::into_boundary_error)
    }
}

/// Converts a filter compilation failure into the CLI error taxonomy.
fn cli_error(error: packetcraftr::core::filter::Error) -> CliError {
    let remediation = match &error {
        packetcraftr::core::filter::Error::UnknownField { .. }
        | packetcraftr::core::filter::Error::UnresolvableProtocol { .. } => {
            "run `packetcraftr protocols <PROTOCOL>` to list the fields a protocol exposes"
        }
        packetcraftr::core::filter::Error::IncompatibleLiteral { .. }
        | packetcraftr::core::filter::Error::OrderedPrefixComparison { .. } => {
            "compare the field against a value of its own type"
        }
        packetcraftr::core::filter::Error::UnsliceableField { .. } => {
            "slice only fields that hold bytes, such as an address or a byte string"
        }
        packetcraftr::core::filter::Error::SizeLimit { .. }
        | packetcraftr::core::filter::Error::NestingLimit { .. }
        | packetcraftr::core::filter::Error::TermLimit { .. }
        | packetcraftr::core::filter::Error::SetMemberLimit { .. }
        | packetcraftr::core::filter::Error::InvalidNestingLimit { .. } => {
            "simplify the filter to fit the stable bounds"
        }
        // Covers `Empty` and `Syntax`, and — because `filter::Error` is
        // non-exhaustive — any variant added later.
        _ => "check the filter syntax; see `packetcraftr read --help` for examples",
    };
    CliError::from_classification(
        Classification::new("request.filter", Kind::Request, Some(remediation)),
        error.to_string(),
        Vec::new(),
    )
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use packetcraftr::core::{frame::LinkType, protocol::builtin};

    use super::*;

    fn registry() -> Arc<Registry> {
        Arc::new(builtin::registry().expect("built-in registry"))
    }

    #[test]
    fn stream_fields_require_stream_capability() {
        let registry = registry();
        assert!(compile("tcp.stream == 1", &registry, Capabilities::stream_capable()).is_ok());

        let error = compile("udp.stream == 1", &registry, Capabilities::frames_only())
            .expect_err("frame-only commands lack stream indices");
        assert_eq!(
            error.classification.code,
            "request.filter_unsupported_field"
        );
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
        assert_eq!(error.classification.code, "packet.error");
    }

    #[test]
    fn filter_error_remediation_is_specific() {
        let registry = registry();
        let cases = [
            ("ipv4.missing == 1", "list the fields a protocol exposes"),
            ("udp.destination_port == 192.0.2.1", "value of its own type"),
            ("frame.len[0] == 1", "slice only fields that hold bytes"),
            ("(ethernet", "check the filter syntax"),
        ];

        for (source, expected_remediation) in cases {
            let error = compile(source, &registry, Capabilities::frames_only())
                .expect_err("fixture filter must fail");
            assert!(
                error
                    .classification
                    .remediation
                    .is_some_and(|value| value.contains(expected_remediation)),
                "{source}: {:?}",
                error.classification.remediation
            );
        }
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
            "request.filter_unsupported_field"
        );

        let syntax_error = FrameSelector::compile_optional(Some("(ethernet"), &registry, 14)
            .expect_err("malformed filter rejected");
        assert_eq!(syntax_error.classification.code, "request.filter");
    }
}
