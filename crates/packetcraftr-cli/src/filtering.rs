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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Capabilities {
    pub(crate) stream_index: bool,
}

impl Capabilities {
    pub(crate) const fn frames_only() -> Self {
        Self {
            stream_index: false,
        }
    }

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
        packetcraftr_core::filter::Limits::default(),
    )
    .map_err(CliError::classified)?;
    if filter.requirements().stream_index && !capabilities.stream_index {
        return Err(CliError::from_classification(
            Classification::new(
                "cli.filter_unsupported_field",
                Kind::Usage,
                Some(
                    "use `stats`, `expert`, or `export` for stream-aware filters, \
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

pub(crate) fn frame_selector(
    source: &str,
    registry: &Arc<Registry>,
    max_frame_bytes: usize,
) -> Result<FrameSelector, CliError> {
    let filter = compile(source, registry, Capabilities::frames_only())?;
    FrameSelector::new(Arc::clone(registry), filter, max_frame_bytes).map_err(CliError::classified)
}

pub(crate) fn optional_frame_selector(
    source: Option<&str>,
    registry: &Arc<Registry>,
    max_frame_bytes: usize,
) -> Result<Option<FrameSelector>, CliError> {
    source
        .map(|source| frame_selector(source, registry, max_frame_bytes))
        .transpose()
}

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

pub(crate) fn frame_error(
    source_frame: u64,
    error: impl core::error::Classified + std::fmt::Display,
) -> CliError {
    CliError::classified(error).with_context(Some(Coordinate::SourceFrame(source_frame)))
}

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
}
