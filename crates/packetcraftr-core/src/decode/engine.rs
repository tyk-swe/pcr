// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use crate::frame::{Frame, LinkType};
use bytes::Bytes;

use super::super::diagnostic::Diagnostic;
use super::super::layer::ProtocolId;
use super::super::registry::ProtocolRegistry;

use fallback::raw_decoded_frame;
use session::DecodeSession;

mod error;
mod fallback;
mod options;
mod session;
mod traversal;

pub use error::DecodeError;
pub use options::{DecodeOptions, DecodedPacket};

#[derive(Clone, Debug)]
pub struct Dissector {
    registry: Arc<ProtocolRegistry>,
}

impl Dissector {
    pub fn new(registry: Arc<ProtocolRegistry>) -> Self {
        Self { registry }
    }

    pub fn decode(
        &self,
        frame: Frame,
        options: DecodeOptions,
    ) -> Result<DecodedPacket, DecodeError> {
        if options.max_layers == 0 {
            return Err(DecodeError::LayerLimit { limit: 0 });
        }
        if frame.bytes().len() > options.max_packet_size {
            return Err(DecodeError::PacketSizeLimit {
                actual: frame.bytes().len(),
                limit: options.max_packet_size,
            });
        }
        let Some(root) = self.registry.root_for_link_type(frame.link_type.0).cloned() else {
            let link_type = frame.link_type.0;
            return Ok(raw_decoded_frame(
                frame,
                Diagnostic::warning(
                    "decode.unsupported_link_type",
                    format!("no root binding for link type {link_type}"),
                ),
            ));
        };
        self.decode_from_root(frame, root, options)
    }

    pub fn decode_with_root(
        &self,
        bytes: impl Into<Bytes>,
        root: ProtocolId,
        options: DecodeOptions,
    ) -> Result<DecodedPacket, DecodeError> {
        let bytes = bytes.into();
        if bytes.len() > options.max_packet_size {
            return Err(DecodeError::PacketSizeLimit {
                actual: bytes.len(),
                limit: options.max_packet_size,
            });
        }
        let frame = Frame::new(std::time::SystemTime::UNIX_EPOCH, LinkType(u32::MAX), bytes)?;
        if options.max_layers == 0 {
            return Err(DecodeError::LayerLimit { limit: 0 });
        }
        self.decode_from_root(frame, root, options)
    }

    fn decode_from_root(
        &self,
        frame: Frame,
        root: ProtocolId,
        options: DecodeOptions,
    ) -> Result<DecodedPacket, DecodeError> {
        DecodeSession::new(&self.registry, frame, root, options).run()
    }
}
