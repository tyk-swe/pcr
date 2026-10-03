// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use crate::decode::{self, DecodedPacket, Dissector};
use crate::frame::Frame;
use crate::registry::Registry;

use super::{Context, Error, Filter};

impl<'a> Context<'a> {
    /// For callers that assign no derived packets or conversation indexes.
    pub fn frame(decoded: &'a DecodedPacket, number: u64) -> Self {
        Self {
            decoded,
            derived: &[],
            number,
            tcp_stream: None,
            udp_stream: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct FrameDecoder {
    dissector: Dissector,
    filter: Option<Filter>,
    max_frame_bytes: usize,
}

impl FrameDecoder {
    pub fn new(
        registry: Arc<Registry>,
        filter: Option<Filter>,
        max_frame_bytes: usize,
    ) -> Result<Self, Error> {
        if filter
            .as_ref()
            .is_some_and(|filter| filter.requirements().stream_index)
        {
            return Err(Error::StreamIndexUnavailable);
        }
        Ok(Self {
            dissector: Dissector::new(registry),
            filter,
            max_frame_bytes,
        })
    }

    pub fn decode(&self, frame: &Frame) -> Result<DecodedPacket, decode::Error> {
        self.dissector.decode(
            frame.clone(),
            decode::Options {
                limits: crate::packet::Limits {
                    max_packet_size: self.max_frame_bytes,
                    ..crate::packet::Limits::default()
                },
            },
        )
    }

    /// `Ok(None)` means the frame decoded but was not selected.
    pub fn decode_selected(
        &self,
        number: u64,
        frame: &Frame,
    ) -> Result<Option<DecodedPacket>, Error> {
        let decoded = self.decode(frame).map_err(Error::from)?;
        if let Some(filter) = &self.filter {
            let keep = filter.matches(&Context::frame(&decoded, number))?;
            if !keep {
                return Ok(None);
            }
        }
        Ok(Some(decoded))
    }
}

#[derive(Clone, Debug)]
pub struct FrameSelector(FrameDecoder);

impl FrameSelector {
    pub fn new(
        registry: Arc<Registry>,
        filter: Filter,
        max_frame_bytes: usize,
    ) -> Result<Self, Error> {
        FrameDecoder::new(registry, Some(filter), max_frame_bytes).map(Self)
    }

    /// Whether the one-based frame `number` is kept.
    pub fn keep(&self, number: u64, frame: &Frame) -> Result<bool, Error> {
        self.0
            .decode_selected(number, frame)
            .map(|decoded| decoded.is_some())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::error::Classified;
    use crate::filter::Limits;

    use crate::protocol::builtin;

    fn compile(source: &str, registry: &Registry) -> Filter {
        Filter::compile(source, registry, Limits::default()).expect("fixture filter compiles")
    }

    #[test]
    fn stream_index_filters_are_refused_rather_than_matching_nothing() {
        let registry = builtin::registry();
        for source in ["tcp.stream == 1", "udp.stream == 1"] {
            let error = FrameSelector::new(Arc::clone(&registry), compile(source, &registry), 14)
                .expect_err("frame-at-a-time selection assigns no conversation index");
            assert!(matches!(error, Error::StreamIndexUnavailable), "{source}");
            assert_eq!(
                error.classification().code,
                "cli.filter_unsupported_field",
                "{source}"
            );
        }
    }
}
