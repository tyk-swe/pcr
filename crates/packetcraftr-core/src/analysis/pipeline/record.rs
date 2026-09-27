// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The per-frame record the pipeline hands to a sink: one matched frame,
//! its elected transport views, and the datagrams it completed.

use std::time::{Duration, SystemTime};

use crate::analysis::reassembly::tcp::{Event as TcpEvent, ScopedFlowKey};
use crate::analysis::scope::{Interner, ScopeId};
use crate::decode::DecodedPacket;
use crate::protocol::transport::Tcp;

/// A complete datagram decoded separately from, and attributed to, the
/// physical fragment whose arrival filled its final gap.
#[derive(Debug)]
pub struct DerivedDatagram {
    pub sources: Option<crate::analysis::provenance::SourceSet>,
    pub decoded: DecodedPacket,
    pub scope: ScopeId,
    pub fragment_count: usize,
    pub unique_bytes: usize,
    pub payload_bytes: usize,
    pub(super) replayed_prefix_layers: usize,
}

impl DerivedDatagram {
    pub(crate) const fn replayed_prefix_layers(&self) -> usize {
        self.replayed_prefix_layers
    }
}

/// One matched frame, dispatched in capture order.
#[derive(Debug)]
pub struct FrameRecord<'a> {
    /// 1-based position in the capture, counting unmatched frames too, so
    /// numbers agree with every other command reading the same file.
    pub number: u64,
    /// The frame's capture timestamp, already validated as present by the
    /// loop that read it.
    pub timestamp: SystemTime,
    pub decoded: &'a DecodedPacket,
    pub(super) derived_datagrams: &'a [DerivedDatagram],
    pub(super) scopes: &'a Interner,
    pub(super) physical_sources: Option<&'a crate::analysis::provenance::SourceSet>,
    /// Innermost TCP and UDP observations, each tied to the decoded view
    /// that supplied it. A tunnel can carry one of each.
    pub tcp: Option<TcpView<'a>>,
    pub udp: Option<UdpView<'a>>,
    /// Reassembly events in delivery order, including expiry of other flows.
    pub tcp_events: &'a [TcpEvent],
    /// The rollback this frame's timestamp showed against the capture's
    /// high-water mark, when it regressed. The shared capture clock detects
    /// the regression for every physical frame; matched frames carry it so
    /// downstream evidence can attribute it here.
    pub clock_regression: Option<Duration>,
}

/// A capture-global stream index and the scoped flow it identifies.
#[derive(Clone, Copy, Debug)]
pub struct Conversation<'a> {
    pub index: u64,
    pub flow: &'a ScopedFlowKey,
}

/// One TCP header and its exact source view. A visible carrier of a fragmented
/// TCP child has no conversation until the child can be reconstructed.
#[derive(Clone, Copy, Debug)]
pub struct TcpView<'a> {
    pub decoded: &'a DecodedPacket,
    pub layer: usize,
    pub header: &'a Tcp,
    pub conversation: Option<Conversation<'a>>,
    /// Indexed segment bytes; control segments and unindexed carriers are empty.
    pub payload: &'a [u8],
}

/// One UDP header and its exact source view, with the same carrier convention
/// as [`TcpView`].
#[derive(Clone, Copy, Debug)]
pub struct UdpView<'a> {
    pub decoded: &'a DecodedPacket,
    pub layer: usize,
    pub conversation: Option<Conversation<'a>>,
}

impl FrameRecord<'_> {
    pub fn physical_sources(&self) -> Option<&crate::analysis::provenance::SourceSet> {
        self.physical_sources
    }
    pub fn tcp_sources(&self) -> Option<&crate::analysis::provenance::SourceSet> {
        self.tcp.and_then(|view| self.sources_of(view.decoded))
    }
    pub fn udp_sources(&self) -> Option<&crate::analysis::provenance::SourceSet> {
        self.udp.and_then(|view| self.sources_of(view.decoded))
    }
    fn sources_of(
        &self,
        decoded: &DecodedPacket,
    ) -> Option<&crate::analysis::provenance::SourceSet> {
        if std::ptr::eq(decoded, self.decoded) {
            return self.physical_sources;
        }
        self.derived_datagrams
            .iter()
            .find(|datagram| std::ptr::eq(&datagram.decoded, decoded))
            .and_then(|datagram| datagram.sources.as_ref())
    }

    /// Filter context containing only this physical frame's packet and indexes.
    pub fn physical_context(&self) -> crate::filter::Context<'_> {
        crate::filter::Context {
            decoded: self.decoded,
            derived: &[],
            number: self.number,
            tcp_stream: self
                .tcp
                .filter(|view| std::ptr::eq(view.decoded, self.decoded))
                .and_then(|view| view.conversation.map(|conversation| conversation.index)),
            udp_stream: self
                .udp
                .filter(|view| std::ptr::eq(view.decoded, self.decoded))
                .and_then(|view| view.conversation.map(|conversation| conversation.index)),
        }
    }

    /// Projects physical and newly reconstructed fields using scoped stream indexes.
    pub fn project(
        &self,
        projection: &crate::filter::Projection,
        max_bytes: usize,
    ) -> Result<Vec<Option<crate::field::FieldValue>>, crate::filter::Error> {
        self.with_filter_context(|context| projection.values(context, max_bytes))
    }

    /// Evaluates a filter against this physical record and its reconstructed children.
    pub fn matches(&self, filter: &crate::filter::Filter) -> Result<bool, crate::filter::Error> {
        self.with_filter_context(|context| filter.matches(context))
    }

    fn with_filter_context<T>(&self, visit: impl FnOnce(&crate::filter::Context<'_>) -> T) -> T {
        let derived: Vec<_> = self
            .derived_datagrams
            .iter()
            .map(|datagram| crate::filter::DerivedPacket {
                decoded: &datagram.decoded,
                replayed_prefix_layers: datagram.replayed_prefix_layers,
            })
            .collect();
        visit(&crate::filter::Context {
            decoded: self.decoded,
            derived: &derived,
            number: self.number,
            tcp_stream: self
                .tcp
                .and_then(|view| view.conversation.map(|conversation| conversation.index)),
            udp_stream: self
                .udp
                .and_then(|view| view.conversation.map(|conversation| conversation.index)),
        })
    }

    /// Resolves a run-local scope into its capture interface and tunnel path.
    pub fn scope_definition(&self, id: ScopeId) -> Option<&crate::analysis::scope::Definition> {
        self.scopes.definition(id)
    }

    /// Capture-global scope definitions observed through this frame.
    pub fn scope_definitions(&self) -> &[crate::analysis::scope::Definition] {
        self.scopes.definitions()
    }

    /// Innermost completed network-layer view attached to this physical
    /// frame. It is never a second physical pipeline record and never
    /// contributes bytes to physical capture accounting.
    #[must_use]
    pub fn derived(&self) -> Option<&DerivedDatagram> {
        self.derived_datagrams.last()
    }

    /// All completed datagram views attached to this physical frame, ordered
    /// from outermost to innermost.
    #[must_use]
    pub fn derived_datagrams(&self) -> &[DerivedDatagram] {
        self.derived_datagrams
    }
}
