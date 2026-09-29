// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;

use packetcraftr_core::decode::DecodedPacket;

use super::envelope::Published;
use super::frame::{Layout, Wire};

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    #[serde(flatten)]
    pub frame: Wire,
    pub link_type: u32,
    pub packet: packetcraftr_core::document::Packet,
    pub layout: Layout,
}

impl From<DecodedPacket> for Published<Report> {
    fn from(decoded: DecodedPacket) -> Self {
        let DecodedPacket {
            packet,
            frame,
            layout,
            diagnostics,
        } = decoded;
        Self::new(
            Report {
                frame: frame.bytes().clone().into(),
                link_type: frame.link_type.0,
                packet: packetcraftr_core::document::Packet::from_packet(&packet),
                layout: layout.into(),
            },
            diagnostics,
        )
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct AggregateResult {
    matched: bool,
    dissection: Option<Report>,
}

impl From<(bool, DecodedPacket)> for Published<AggregateResult> {
    fn from((matched, decoded): (bool, DecodedPacket)) -> Self {
        if matched {
            let Published {
                result,
                diagnostics,
                stats,
            } = Published::<Report>::from(decoded);
            Self {
                result: AggregateResult {
                    matched: true,
                    dissection: Some(result),
                },
                diagnostics,
                stats,
            }
        } else {
            Self::new(
                AggregateResult {
                    matched: false,
                    dissection: None,
                },
                decoded.diagnostics,
            )
        }
    }
}
