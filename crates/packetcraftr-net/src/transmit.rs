// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Typed Layer 2 and Layer 3 transmission contracts.
//!
//! These traits describe how a materialized route reaches a backend; they
//! carry no policy of their own. Callers authorize a destination through the
//! client policy layer before constructing a transmitter.

use bytes::Bytes;

use super::Error;
use super::link::LinkMode;
use super::route::MaterializedRoute;

#[doc(hidden)]
pub use self::{
    Dispatch as DispatchPacketIo, Frame as TransmissionFrame, Layer2Sender as Layer2Io,
    Report as IoSendReport, Sender as PacketIo, SystemLayer2 as SystemLayer2Io,
    SystemLayer3 as SystemLayer3Io,
};

/// A complete Layer 2 frame. Construction rejects a route selected for raw
/// Layer 3 transmission.
#[derive(Clone, Copy, Debug)]
pub struct Layer2Frame<'a> {
    bytes: &'a Bytes,
    route: &'a MaterializedRoute,
}

impl<'a> Layer2Frame<'a> {
    pub fn try_new(bytes: &'a Bytes, route: &'a MaterializedRoute) -> Result<Self, Error> {
        require_link_mode(route, LinkMode::Layer2)?;
        Ok(Self { bytes, route })
    }

    pub fn bytes(self) -> &'a Bytes {
        self.bytes
    }

    pub fn route(self) -> &'a MaterializedRoute {
        self.route
    }
}

/// A raw Layer 3 packet. Construction rejects a route selected for link-layer
/// transmission, preventing an Ethernet envelope from reaching a raw socket.
#[derive(Clone, Copy, Debug)]
pub struct Layer3Frame<'a> {
    bytes: &'a Bytes,
    route: &'a MaterializedRoute,
}

impl<'a> Layer3Frame<'a> {
    pub fn try_new(bytes: &'a Bytes, route: &'a MaterializedRoute) -> Result<Self, Error> {
        require_link_mode(route, LinkMode::Layer3)?;
        Ok(Self { bytes, route })
    }

    pub fn bytes(self) -> &'a Bytes {
        self.bytes
    }

    pub fn route(self) -> &'a MaterializedRoute {
        self.route
    }
}

/// Mode-tagged transmission input used by the high-level client.
#[derive(Clone, Copy, Debug)]
pub enum Frame<'a> {
    Layer2(Layer2Frame<'a>),
    Layer3(Layer3Frame<'a>),
}

impl<'a> Frame<'a> {
    /// Selects the typed provider boundary from the already-materialized route.
    pub fn try_new(bytes: &'a Bytes, route: &'a MaterializedRoute) -> Result<Self, Error> {
        match route.plan.mode {
            LinkMode::Layer2 => Layer2Frame::try_new(bytes, route).map(Self::Layer2),
            LinkMode::Layer3 => Layer3Frame::try_new(bytes, route).map(Self::Layer3),
            LinkMode::Auto => Err(Error::UnresolvedLinkMode),
        }
    }

    pub fn bytes(self) -> &'a Bytes {
        match self {
            Self::Layer2(frame) => frame.bytes(),
            Self::Layer3(frame) => frame.bytes(),
        }
    }

    pub fn route(self) -> &'a MaterializedRoute {
        match self {
            Self::Layer2(frame) => frame.route(),
            Self::Layer3(frame) => frame.route(),
        }
    }
}

fn require_link_mode(route: &MaterializedRoute, expected: LinkMode) -> Result<(), Error> {
    let actual = route.plan.mode;
    if actual == expected {
        Ok(())
    } else {
        Err(Error::TransmissionModeMismatch { expected, actual })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub bytes_sent: usize,
    pub wire_bytes: Bytes,
}

/// Unified packet-I/O seam used by the root client and test providers.
pub trait Sender: Send + Sync {
    fn send(&self, frame: Frame<'_>) -> Result<Report, Error>;
}

/// Native or injected Layer 2 transmission implementation.
pub trait Layer2Sender: Send + Sync {
    fn send_layer2(&self, frame: Layer2Frame<'_>) -> Result<Report, Error>;
}

/// Native Layer 2 injection provider selected for the current target. Builds
/// without `native-layer2` return an actionable capability error.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemLayer2;

impl Layer2Sender for SystemLayer2 {
    fn send_layer2(&self, frame: Layer2Frame<'_>) -> Result<Report, Error> {
        super::platform::system_send_layer2(frame)
    }
}

/// Native or injected raw Layer 3 transmission implementation.
pub trait Layer3Sender: Send + Sync {
    fn send_layer3(&self, frame: Layer3Frame<'_>) -> Result<Report, Error>;
}

/// Native raw-IP provider selected for the current target. Builds without
/// `native-layer3` return an actionable capability error.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemLayer3;

impl Layer3Sender for SystemLayer3 {
    fn send_layer3(&self, frame: Layer3Frame<'_>) -> Result<Report, Error> {
        super::platform::system_send_layer3(frame)
    }
}

/// Composes independently owned Layer 2 and Layer 3 providers into [`Sender`].
#[derive(Clone, Copy, Debug)]
pub struct Dispatch<L2, L3> {
    layer2: L2,
    layer3: L3,
}

impl<L2, L3> Dispatch<L2, L3> {
    pub fn new(layer2: L2, layer3: L3) -> Self {
        Self { layer2, layer3 }
    }
}

impl<L2, L3> Sender for Dispatch<L2, L3>
where
    L2: Layer2Sender,
    L3: Layer3Sender,
{
    fn send(&self, frame: Frame<'_>) -> Result<Report, Error> {
        match frame {
            Frame::Layer2(frame) => self.layer2.send_layer2(frame),
            Frame::Layer3(frame) => self.layer3.send_layer3(frame),
        }
    }
}
