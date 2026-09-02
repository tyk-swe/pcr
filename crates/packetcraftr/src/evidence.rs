// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded diagnostic and capture-evidence retention for client operations.

use packetcraftr_core::{
    build::BuiltPacket,
    diagnostic::Diagnostic,
    frame::{Frame, LinkType},
};
use packetcraftr_netio::{
    Error as LiveIoError, SendEvidenceFault,
    link::Mode as LinkMode,
    transmit::{Report as TransmissionReport, Timing as TransmissionTiming},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExecutionPermit(u64);

impl ExecutionPermit {
    /// Issues a process-unique permit. The 64-bit counter cannot wrap within
    /// the lifetime of a process, so no overflow branch exists.
    pub(crate) fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        Self(NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }
}

/// One operation's append-only diagnostic log, together with the cursor that
/// says how much of it the caller has already published.
///
/// Every long-running workflow raises diagnostics from several places and then
/// has to hand out exactly the ones raised since it last looked. Owning the
/// cursor here is what keeps callers from snapshotting `len()` and slicing
/// with it afterwards.
#[derive(Debug, Default)]
pub(crate) struct DiagnosticLog {
    entries: Vec<Diagnostic>,
    published: usize,
}

impl DiagnosticLog {
    /// Records `diagnostic` unless an identical one is already logged.
    pub(crate) fn push_once(&mut self, diagnostic: Diagnostic) {
        packetcraftr_core::diagnostic::push_once(&mut self.entries, diagnostic);
    }

    /// Every diagnostic recorded so far, published or not.
    #[cfg(test)]
    pub(crate) fn as_slice(&self) -> &[Diagnostic] {
        &self.entries
    }

    /// Hands `publish` each diagnostic recorded since the previous call and
    /// advances the cursor past it.
    ///
    /// The cursor advances one entry at a time, so a failing `publish` leaves
    /// the entry it failed on unpublished rather than skipping the remainder.
    pub(crate) fn publish_new<E>(
        &mut self,
        mut publish: impl FnMut(Diagnostic) -> Result<(), E>,
    ) -> Result<(), E> {
        while let Some(diagnostic) = self.entries.get(self.published).cloned() {
            publish(diagnostic)?;
            self.published = self.published.saturating_add(1);
        }
        Ok(())
    }
}

/// Total wire bytes across trusted send receipts, or [`None`] when the sum
/// overflows.
///
/// The single fold behind both the statistics an exchange publishes and the
/// evidence validator that re-checks them, so the two can never disagree about
/// how the total is computed.
pub(crate) fn total_bytes_sent<'a>(sent: impl IntoIterator<Item = &'a SentPacket>) -> Option<u64> {
    sent.into_iter().try_fold(0_u64, |total, sent| {
        total.checked_add(u64::try_from(sent.bytes_sent()).unwrap_or(u64::MAX))
    })
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
            fault: SendEvidenceFault::from(source),
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
    use packetcraftr_core::build::{Builder, Context, Options};

    Builder::new(packetcraftr_core::protocol::builtin::registry())
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
    fn a_diagnostic_log_publishes_each_entry_once_and_deduplicates_repeats() {
        let mut log = DiagnosticLog::default();
        let mut published: Vec<String> = Vec::new();

        log.push_once(Diagnostic::warning("test.one", "first"));
        log.push_once(Diagnostic::warning("test.one", "first"));
        log.publish_new::<()>(|diagnostic| {
            published.push(diagnostic.code.to_string());
            Ok(())
        })
        .expect("publishing cannot fail");
        assert_eq!(published, vec!["test.one".to_owned()]);

        log.publish_new::<()>(|_| panic!("already-published entries are never republished"))
            .expect("publishing cannot fail");

        log.push_once(Diagnostic::warning("test.two", "second"));
        log.publish_new::<()>(|diagnostic| {
            published.push(diagnostic.code.to_string());
            Ok(())
        })
        .expect("publishing cannot fail");
        assert_eq!(
            published,
            vec!["test.one".to_owned(), "test.two".to_owned()]
        );
        assert_eq!(log.as_slice().len(), 2);
    }

    /// A publication failure must not consume the entry it failed on, so a
    /// later retry still reports it.
    #[test]
    fn a_failed_publication_leaves_its_entry_unpublished() {
        let mut log = DiagnosticLog::default();
        log.push_once(Diagnostic::warning("test.one", "first"));
        log.push_once(Diagnostic::warning("test.two", "second"));

        let mut seen = 0_usize;
        assert_eq!(
            log.publish_new(|_| {
                seen += 1;
                Err::<(), _>("sink closed")
            }),
            Err("sink closed")
        );
        assert_eq!(seen, 1);

        let mut retried: Vec<String> = Vec::new();
        log.publish_new::<()>(|diagnostic| {
            retried.push(diagnostic.code.to_string());
            Ok(())
        })
        .expect("publishing cannot fail");
        assert_eq!(retried, vec!["test.one".to_owned(), "test.two".to_owned()]);
    }

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
