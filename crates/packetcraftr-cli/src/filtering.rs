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
                    "use `analyze stats`, `analyze expert`, or `files export` for stream-aware filters, \
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
    use super::*;
    use packetcraftr_core::{
        build::Builder,
        decode::Dissector,
        frame::{Frame, LinkType},
        layer::Raw,
        packet::Packet,
        protocol::{builtin, network::Ipv4, transport::Udp},
    };

    fn frame(ttl: u8) -> Frame {
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            source: "192.0.2.1".parse().unwrap(),
            destination: "192.0.2.2".parse().unwrap(),
            ttl,
            ..Default::default()
        });
        packet.push(Udp {
            source_port: 3333,
            destination_port: 4444,
            ..Default::default()
        });
        packet.push(Raw::new(bytes::Bytes::from_static(b"filter fixture")));
        let built = Builder::new(builtin::registry())
            .build(packet, Default::default(), Default::default())
            .unwrap();
        Frame::without_timestamp(LinkType::RAW, built.bytes).unwrap()
    }

    #[test]
    fn filter_capabilities_preserve_header_and_conversation_matches() {
        let registry = builtin::registry();
        let decoded = Dissector::new(Arc::clone(&registry))
            .decode(frame(37), Default::default())
            .unwrap();
        let context = Context::frame(&decoded, 1);
        for capabilities in [Capabilities::frames_only(), Capabilities::stream_capable()] {
            let matching = compile("ipv4.ttl == 37", &registry, capabilities).unwrap();
            let different = compile("ipv4.ttl == 38", &registry, capabilities).unwrap();
            assert!(matches_decoded(&matching, &context).unwrap());
            assert!(!matches_decoded(&different, &context).unwrap());
        }
        let stream = compile("udp.stream == 7", &registry, Capabilities::stream_capable()).unwrap();
        assert!(
            matches_decoded(
                &stream,
                &Context {
                    udp_stream: Some(7),
                    ..context
                }
            )
            .unwrap()
        );
        assert!(
            !matches_decoded(
                &stream,
                &Context {
                    udp_stream: Some(8),
                    ..context
                }
            )
            .unwrap()
        );
        let refused =
            compile("udp.stream == 7", &registry, Capabilities::frames_only()).unwrap_err();
        assert_eq!(refused.classification.code, "cli.filter_unsupported_field");
        assert_eq!(refused.classification.kind, Kind::Usage);
    }

    #[test]
    fn optional_selector_applies_the_supplied_filter_to_frames() {
        let registry = builtin::registry();
        let selected = optional_frame_selector(Some("ipv4.ttl == 37"), &registry, 1024)
            .unwrap()
            .expect("an explicitly requested filter must produce a selector");
        assert!(selected.keep(1, &frame(37)).unwrap());
        assert!(!selected.keep(2, &frame(38)).unwrap());
        assert!(
            optional_frame_selector(None, &registry, 1024)
                .unwrap()
                .is_none()
        );
    }
}
