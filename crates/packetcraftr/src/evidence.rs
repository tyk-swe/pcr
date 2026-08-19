// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded diagnostic and capture-evidence retention for client operations.

use packetcraftr_core::{
    build::BuiltPacket,
    frame::{Frame, LinkType},
};
use packetcraftr_netio::{
    Error as LiveIoError,
    link::Mode as LinkMode,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BudgetError {
    FrameCountOverflow,
    FrameLimit,
    ByteCountOverflow,
    ByteLimit,
}

#[derive(Default)]
pub(crate) struct Budget {
    retained_frames: usize,
    retained_bytes: usize,
}

impl Budget {
    pub(crate) fn reserve(
        &mut self,
        additional_bytes: usize,
        max_frames: usize,
        max_bytes: usize,
    ) -> Result<(), BudgetError> {
        let next_frames = self
            .retained_frames
            .checked_add(1)
            .ok_or(BudgetError::FrameCountOverflow)?;
        if next_frames > max_frames {
            return Err(BudgetError::FrameLimit);
        }
        let next_bytes = self
            .retained_bytes
            .checked_add(additional_bytes)
            .ok_or(BudgetError::ByteCountOverflow)?;
        if next_bytes > max_bytes {
            return Err(BudgetError::ByteLimit);
        }
        self.retained_frames = next_frames;
        self.retained_bytes = next_bytes;
        Ok(())
    }
}

/// Opaque evidence tying a semantic build and route to the exact bytes and
/// timing accepted by one transmission provider call.
#[derive(Clone, Debug)]
pub struct SentPacket {
    built: BuiltPacket,
    route: packetcraftr_netio::route::Materialized,
    report: TransmissionReport,
    frame: Frame,
}

impl SentPacket {
    /// Validates a provider receipt against the exact built bytes and route,
    /// then creates trusted sent evidence.
    ///
    /// # Errors
    ///
    /// Returns an I/O contract error when the receipt does not confirm the
    /// complete exact transmission or the route has no resolved link mode.
    pub fn try_new(
        built: BuiltPacket,
        route: packetcraftr_netio::route::Materialized,
        report: TransmissionReport,
    ) -> Result<Self, LiveIoError> {
        report.validate_exact(&built.bytes)?;
        let link_type = match route.plan.mode {
            LinkMode::Layer2 => route.plan.decision.link_type,
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

    pub fn route(&self) -> &packetcraftr_netio::route::Materialized {
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
fn test_materialized_route() -> packetcraftr_netio::route::Materialized {
    use packetcraftr_core::frame::LinkType;
    use packetcraftr_netio::{
        interface::Id as InterfaceId,
        link::{Capability, Mode},
        route::{Decision, Materialized, Plan},
    };

    Materialized {
        plan: Plan {
            decision: Decision {
                interface: InterfaceId {
                    name: "fixture0".to_owned(),
                    index: 1,
                },
                source_mac: None,
                selected_source: None,
                preferred_source: None,
                next_hop: None,
                selection_reason: packetcraftr_netio::route::SelectionReason::InterfaceOnly,
                destination_scope: packetcraftr_netio::route::Scope::Link,
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
        let mut budget = Budget {
            retained_frames: 1,
            retained_bytes: 10,
        };
        assert_eq!(budget.reserve(5, 2, 15), Ok(()));
        assert_eq!((budget.retained_frames, budget.retained_bytes), (2, 15));
    }

    #[test]
    fn frame_limit_and_overflow_leave_counters_untouched() {
        let mut budget = Budget {
            retained_frames: 1,
            retained_bytes: 3,
        };
        assert_eq!(budget.reserve(1, 1, 10), Err(BudgetError::FrameLimit));
        assert_eq!((budget.retained_frames, budget.retained_bytes), (1, 3));

        budget.retained_frames = usize::MAX;
        assert_eq!(
            budget.reserve(1, usize::MAX, 10),
            Err(BudgetError::FrameCountOverflow)
        );
        assert_eq!(
            (budget.retained_frames, budget.retained_bytes),
            (usize::MAX, 3)
        );
    }

    #[test]
    fn byte_limit_and_overflow_leave_counters_untouched() {
        let mut budget = Budget {
            retained_frames: 1,
            retained_bytes: 9,
        };
        assert_eq!(budget.reserve(2, 10, 10), Err(BudgetError::ByteLimit));
        assert_eq!((budget.retained_frames, budget.retained_bytes), (1, 9));

        budget.retained_bytes = usize::MAX;
        assert_eq!(
            budget.reserve(1, 10, usize::MAX),
            Err(BudgetError::ByteCountOverflow)
        );
        assert_eq!(
            (budget.retained_frames, budget.retained_bytes),
            (1, usize::MAX)
        );
    }
}
