// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use bytes::Bytes;

use crate::{Error, link::Mode, route::Decision};

/// The route facts a transmission backend checks before sending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route<'a> {
    pub decision: &'a Decision,
    pub mode: Mode,
    /// Destination the route was looked up for; absent for destination-free Layer 2 frames.
    pub lookup_destination: Option<IpAddr>,
}

#[derive(Clone, Copy, Debug)]
pub struct Layer2Frame<'a> {
    bytes: &'a Bytes,
    route: Route<'a>,
}

impl<'a> Layer2Frame<'a> {
    pub fn try_new(bytes: &'a Bytes, route: Route<'a>) -> Result<Self, Error> {
        require_link_mode(route, Mode::Layer2)?;
        Ok(Self { bytes, route })
    }

    pub fn bytes(self) -> &'a Bytes {
        self.bytes
    }

    pub fn route(self) -> Route<'a> {
        self.route
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Layer3Frame<'a> {
    bytes: &'a Bytes,
    route: Route<'a>,
}

impl<'a> Layer3Frame<'a> {
    pub fn try_new(bytes: &'a Bytes, route: Route<'a>) -> Result<Self, Error> {
        require_link_mode(route, Mode::Layer3)?;
        Ok(Self { bytes, route })
    }

    pub fn bytes(self) -> &'a Bytes {
        self.bytes
    }

    pub fn route(self) -> Route<'a> {
        self.route
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Outbound<'a> {
    Layer2(Layer2Frame<'a>),
    Layer3(Layer3Frame<'a>),
}

impl<'a> Outbound<'a> {
    pub fn try_new(bytes: &'a Bytes, route: Route<'a>) -> Result<Self, Error> {
        match route.mode {
            Mode::Layer2 => Layer2Frame::try_new(bytes, route).map(Self::Layer2),
            Mode::Layer3 => Layer3Frame::try_new(bytes, route).map(Self::Layer3),
            Mode::Auto => Err(Error::UnresolvedLinkMode),
        }
    }

    pub fn bytes(self) -> &'a Bytes {
        match self {
            Self::Layer2(frame) => frame.bytes(),
            Self::Layer3(frame) => frame.bytes(),
        }
    }

    pub fn route(self) -> Route<'a> {
        match self {
            Self::Layer2(frame) => frame.route(),
            Self::Layer3(frame) => frame.route(),
        }
    }
}

fn require_link_mode(route: Route<'_>, expected: Mode) -> Result<(), Error> {
    let actual = route.mode;
    if actual == expected {
        Ok(())
    } else {
        Err(Error::TransmissionModeMismatch { expected, actual })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        interface::Id as InterfaceId,
        link::Capability,
        route::{Scope, SelectionReason},
        transmit::Report,
    };
    use packetcraftr_core::frame::LinkType;

    fn decision() -> Decision {
        Decision {
            interface: InterfaceId {
                name: "test0".to_owned(),
                index: 1,
            },
            source_mac: None,
            selected_source: None,
            preferred_source: None,
            next_hop: None,
            selection_reason: SelectionReason::OnLink,
            destination_scope: Scope::Link,
            mtu: 1500,
            capability: Capability::Layer2AndLayer3,
            link_type: LinkType::ETHERNET,
        }
    }

    fn route<'a>(decision: &'a Decision, mode: Mode) -> Route<'a> {
        Route {
            decision,
            mode,
            lookup_destination: None,
        }
    }

    #[test]
    fn frames_require_their_exact_link_mode() {
        let decision = decision();
        let bytes = Bytes::from_static(b"frame");
        assert!(Layer2Frame::try_new(&bytes, route(&decision, Mode::Layer2)).is_ok());
        assert!(matches!(
            Layer2Frame::try_new(&bytes, route(&decision, Mode::Layer3)),
            Err(Error::TransmissionModeMismatch {
                expected: Mode::Layer2,
                actual: Mode::Layer3
            })
        ));
        assert!(matches!(
            Layer2Frame::try_new(&bytes, route(&decision, Mode::Auto)),
            Err(Error::TransmissionModeMismatch {
                expected: Mode::Layer2,
                actual: Mode::Auto
            })
        ));
        assert!(matches!(
            Layer3Frame::try_new(&bytes, route(&decision, Mode::Auto)),
            Err(Error::TransmissionModeMismatch {
                expected: Mode::Layer3,
                actual: Mode::Auto
            })
        ));
        assert!(Layer3Frame::try_new(&bytes, route(&decision, Mode::Layer3)).is_ok());
        assert!(matches!(
            Layer3Frame::try_new(&bytes, route(&decision, Mode::Layer2)),
            Err(Error::TransmissionModeMismatch {
                expected: Mode::Layer3,
                actual: Mode::Layer2
            })
        ));
    }

    #[test]
    fn outbound_uses_resolved_mode() {
        let decision = decision();
        let bytes = Bytes::from_static(b"frame");
        assert!(matches!(
            Outbound::try_new(&bytes, route(&decision, Mode::Layer2)),
            Ok(Outbound::Layer2(_))
        ));
        assert!(matches!(
            Outbound::try_new(&bytes, route(&decision, Mode::Layer3)),
            Ok(Outbound::Layer3(_))
        ));
        assert!(matches!(
            Outbound::try_new(&bytes, route(&decision, Mode::Auto)),
            Err(Error::UnresolvedLinkMode)
        ));
    }

    #[test]
    fn accessors_preserve_submitted_frame_and_counts() {
        let decision = decision();
        let bytes = Bytes::from_static(b"frame");
        let frame = Layer2Frame::try_new(&bytes, route(&decision, Mode::Layer2)).unwrap();
        assert_eq!(frame.bytes(), &bytes);
        let frame = Layer3Frame::try_new(&bytes, route(&decision, Mode::Layer3)).unwrap();
        assert_eq!(frame.bytes(), &bytes);
        let outbound = Outbound::try_new(&bytes, route(&decision, Mode::Layer3)).unwrap();
        assert_eq!(outbound.bytes(), &bytes);
        assert_eq!(outbound.route().mode, Mode::Layer3);
        let report = Report::committed(5, bytes.clone());
        assert_eq!(report.bytes_sent(), 5);
        assert_eq!(report.wire_bytes(), &bytes);
    }
}
