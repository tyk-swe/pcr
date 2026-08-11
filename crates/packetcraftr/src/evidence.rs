// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded diagnostic and capture-evidence retention for client operations.

use packetcraftr_core::{
    build::Result as BuiltPacket,
    diagnostic::{Diagnostic, push_diagnostic_once},
    frame::{Frame, LinkType},
};
use packetcraftr_netio::{
    Error as LiveIoError,
    link::Mode as LinkMode,
    route::Materialized as MaterializedRoute,
    transmit::{Report as TransmissionReport, Timing as TransmissionTiming},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExecutionPermit(u64);

impl ExecutionPermit {
    pub(crate) fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        Self(
            NEXT.fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |current| current.checked_add(1),
            )
            .expect("live execution permit space exhausted"),
        )
    }
}

/// Opaque evidence tying a semantic build and route to the exact bytes and
/// timing accepted by one transmission provider call.
#[derive(Clone, Debug)]
pub struct SentPacket {
    built: BuiltPacket,
    route: MaterializedRoute,
    report: TransmissionReport,
    frame: Frame,
}

impl SentPacket {
    pub(crate) fn try_new(
        built: BuiltPacket,
        route: MaterializedRoute,
        report: TransmissionReport,
    ) -> Result<Self, LiveIoError> {
        report.validate_exact(&built.bytes)?;
        let link_type = match route.plan.mode {
            LinkMode::Layer2 => route.plan.route.link_type,
            LinkMode::Layer3 => LinkType::RAW,
            LinkMode::Auto => return Err(LiveIoError::UnresolvedLinkMode),
        };
        let frame = Frame::new(
            report.timing().freshness_marker().wall_clock(),
            link_type,
            report.wire_bytes().clone(),
        )
        .map_err(|source| LiveIoError::InvalidSendEvidence {
            message: source.to_string(),
        })?;
        Ok(Self {
            built,
            route,
            report,
            frame,
        })
    }

    pub fn built(&self) -> &BuiltPacket {
        &self.built
    }

    pub fn route(&self) -> &MaterializedRoute {
        &self.route
    }

    pub fn wire_bytes(&self) -> &bytes::Bytes {
        self.report.wire_bytes()
    }

    pub fn bytes_sent(&self) -> usize {
        self.report.bytes_sent()
    }

    pub fn timing(&self) -> TransmissionTiming {
        self.report.timing()
    }

    pub fn frame(&self) -> &Frame {
        &self.frame
    }
}

#[cfg(test)]
pub(crate) fn test_sent_packet(packet: packetcraftr_core::Packet) -> SentPacket {
    use packetcraftr_netio::transmit::Submission;

    let built = test_built_packet(packet);
    let report = Submission::start().complete(built.bytes.len(), built.bytes.clone());
    SentPacket::try_new(built, test_materialized_route(), report)
        .expect("valid trusted sent fixture")
}

#[cfg(test)]
pub(crate) fn test_sent_packet_with_report(
    packet: packetcraftr_core::Packet,
    report: TransmissionReport,
) -> SentPacket {
    SentPacket::try_new(test_built_packet(packet), test_materialized_route(), report)
        .expect("valid trusted sent fixture")
}

#[cfg(test)]
fn test_built_packet(packet: packetcraftr_core::Packet) -> BuiltPacket {
    use std::sync::Arc;

    use packetcraftr_core::build::{Builder, Context, Options};

    Builder::new(Arc::new(
        packetcraftr_core::protocol::builtin::registry().expect("built-in registry"),
    ))
    .build(packet, Context::default(), Options::default())
    .expect("sent-packet fixture must build")
}

#[cfg(test)]
fn test_materialized_route() -> MaterializedRoute {
    use packetcraftr_core::frame::LinkType;
    use packetcraftr_netio::{
        interface::Id as InterfaceId,
        link::{Capability, Mode},
        route::{
            Decision, Materialized, Plan, Scope as DestinationScope,
            SelectionReason as RouteSelectionReason,
        },
    };

    Materialized {
        plan: Plan {
            route: Decision {
                interface: InterfaceId {
                    name: "fixture0".to_owned(),
                    index: 1,
                },
                source_mac: None,
                selected_address: None,
                preferred_source: None,
                next_hop: None,
                selection_reason: RouteSelectionReason::InterfaceOnly,
                destination_scope: DestinationScope::Link,
                mtu: u32::MAX,
                capability: Capability::Layer3,
                link_type: LinkType::RAW,
            },
            mode: Mode::Layer3,
            lookup_destination: None,
            final_destination: None,
            visited_destinations: Vec::new(),
            packet_source: None,
            neighbor_source: None,
            neighbor_target: None,
            destination_mac: None,
            source_mac: None,
            neighbor_vlan_tags: Vec::new(),
            synthesized_ethernet: false,
        },
        neighbor_resolution: None,
    }
}

pub(super) fn reserve_capture_evidence(
    retained_frames: &mut usize,
    retained_bytes: &mut usize,
    additional: usize,
    frame_limit: usize,
    byte_limit: usize,
    diagnostics: &mut Vec<Diagnostic>,
) -> bool {
    let Some(frame_total) = retained_frames.checked_add(1) else {
        push_diagnostic_once(
            diagnostics,
            Diagnostic::warning(
                "exchange.capture_frame_limit",
                "retained capture frame accounting overflowed; frame was not retained",
            ),
        );
        return false;
    };
    if frame_total > frame_limit {
        push_diagnostic_once(
            diagnostics,
            Diagnostic::warning(
                "exchange.capture_frame_limit",
                format!(
                    "aggregate retained capture frame limit {frame_limit} reached; later frames were not retained"
                ),
            ),
        );
        return false;
    }
    let Some(byte_total) = retained_bytes.checked_add(additional) else {
        push_diagnostic_once(
            diagnostics,
            Diagnostic::warning(
                "exchange.capture_byte_limit",
                "retained capture byte accounting overflowed; frame was not retained",
            ),
        );
        return false;
    };
    if byte_total > byte_limit {
        push_diagnostic_once(
            diagnostics,
            Diagnostic::warning(
                "exchange.capture_byte_limit",
                format!(
                    "retained capture byte limit {byte_limit} reached; later frames were not retained"
                ),
            ),
        );
        return false;
    }
    *retained_frames = frame_total;
    *retained_bytes = byte_total;
    true
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use packetcraftr_core::{Packet, layer::Raw};
    use packetcraftr_netio::transmit::Submission;

    use super::*;

    #[test]
    fn sent_receipt_rejects_semantic_build_with_different_accepted_bytes() {
        let mut packet = Packet::new();
        packet.push(Raw::new(Bytes::from_static(&[1, 2, 3])));
        let fixture = test_sent_packet(packet);
        let built = fixture.built.clone();
        let route = fixture.route.clone();
        let report = Submission::start().complete(3, Bytes::from_static(&[3, 2, 1]));

        assert!(matches!(
            SentPacket::try_new(built, route, report),
            Err(LiveIoError::InvalidSendEvidence { .. })
        ));
    }

    #[test]
    fn reservation_commits_both_counters_only_when_every_bound_fits() {
        let mut frames = 1;
        let mut bytes = 10;
        let mut diagnostics = Vec::new();
        assert!(reserve_capture_evidence(
            &mut frames,
            &mut bytes,
            5,
            2,
            15,
            &mut diagnostics,
        ));
        assert_eq!((frames, bytes), (2, 15));
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn frame_limit_and_overflow_leave_counters_untouched_and_deduplicate_diagnostics() {
        let mut frames = 1;
        let mut bytes = 3;
        let mut diagnostics = Vec::new();
        assert!(!reserve_capture_evidence(
            &mut frames,
            &mut bytes,
            1,
            1,
            10,
            &mut diagnostics,
        ));
        assert!(!reserve_capture_evidence(
            &mut frames,
            &mut bytes,
            1,
            1,
            10,
            &mut diagnostics,
        ));
        assert_eq!((frames, bytes), (1, 3));
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "exchange.capture_frame_limit");

        frames = usize::MAX;
        diagnostics.clear();
        assert!(!reserve_capture_evidence(
            &mut frames,
            &mut bytes,
            1,
            usize::MAX,
            10,
            &mut diagnostics,
        ));
        assert_eq!(frames, usize::MAX);
        assert_eq!(bytes, 3);
        assert_eq!(diagnostics[0].code, "exchange.capture_frame_limit");
    }

    #[test]
    fn byte_limit_and_overflow_leave_counters_untouched() {
        let mut frames = 1;
        let mut bytes = 9;
        let mut diagnostics = Vec::new();
        assert!(!reserve_capture_evidence(
            &mut frames,
            &mut bytes,
            2,
            10,
            10,
            &mut diagnostics,
        ));
        assert_eq!((frames, bytes), (1, 9));
        assert_eq!(diagnostics[0].code, "exchange.capture_byte_limit");

        bytes = usize::MAX;
        diagnostics.clear();
        assert!(!reserve_capture_evidence(
            &mut frames,
            &mut bytes,
            1,
            10,
            usize::MAX,
            &mut diagnostics,
        ));
        assert_eq!((frames, bytes), (1, usize::MAX));
        assert_eq!(diagnostics[0].code, "exchange.capture_byte_limit");
    }
}
