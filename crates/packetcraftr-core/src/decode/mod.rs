// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded packet decoding.

use std::sync::Arc;

use crate::diagnostic::Diagnostic;
use crate::frame::Frame;

use crate::registry::Registry;

use fallback::raw_decoded_frame;
use session::DecodeSession;

mod error;
mod fallback;
mod options;
mod session;
mod traversal;

pub use error::Error;
pub use options::{DecodedPacket, Options};

#[derive(Clone, Debug)]
pub struct Dissector {
    registry: Arc<Registry>,
}

impl Dissector {
    pub fn new(registry: Arc<Registry>) -> Self {
        Self { registry }
    }

    pub fn decode(&self, frame: Frame, options: Options) -> Result<DecodedPacket, Error> {
        if options.max_layers == 0 {
            return Err(Error::LayerLimit { limit: 0 });
        }
        if frame.bytes().len() > options.max_packet_size {
            return Err(Error::PacketSizeLimit {
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
        DecodeSession::new(&self.registry, frame, root, options).run()
    }
}
