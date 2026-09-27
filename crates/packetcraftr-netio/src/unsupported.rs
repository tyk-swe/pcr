// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::error::{Classification, Classified, Kind, Source};
use thiserror::Error as ThisError;

use crate::link::Mode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NativeCapability {
    Route,
    InterfaceEnumeration,
    Capture,
    Transmission(Mode),
}

#[derive(Debug, ThisError, Clone)]
#[error("{} is unavailable: {message}", subject(*.capability))]
pub struct Unsupported {
    pub capability: NativeCapability,
    pub message: String,
    #[source]
    pub source: Option<Source>,
}

impl Unsupported {
    pub fn new(capability: NativeCapability, message: impl Into<String>) -> Self {
        Self {
            capability,
            message: message.into(),
            source: None,
        }
    }
}

const fn subject(capability: NativeCapability) -> &'static str {
    match capability {
        NativeCapability::Route => "native route selection",
        _ => "live packet I/O",
    }
}

impl Classified for Unsupported {
    fn classification(&self) -> Classification {
        match self.capability {
            NativeCapability::Route => Classification::new(
                "capability.route",
                Kind::Capability,
                Some(
                    "enable the native-route capability on a supported target or inject a route provider",
                ),
            ),
            NativeCapability::InterfaceEnumeration
            | NativeCapability::Capture
            | NativeCapability::Transmission(_) => Classification::new(
                "capability.unsupported",
                Kind::Capability,
                Some(
                    "enable and configure the requested native capability; PacketcraftR will not change transmission modes automatically",
                ),
            ),
        }
    }
}
