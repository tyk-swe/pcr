// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Plans physical source-record selections with stream and IP dependencies.
//! Copy from the same immutable capture using `pcap::select` after rewinding.

use super::{
    Options, StreamRef, StreamTransport,
    pcap::Reader,
    provenance::{IncompleteSources, SourceSet},
};
use crate::{
    error::{BoundaryError, Classification, Classified, Kind},
    filter::Filter,
    registry::Registry,
};
use std::{collections::BTreeSet, io::Read, sync::Arc};

pub const MAX_SELECTORS: usize = 4096;
pub const MAX_SELECTED_FRAMES: usize = 1_000_000;
#[derive(Clone, Debug)]
pub struct Selection<'a> {
    pub streams: Vec<StreamRef>,
    /// Include every known IP datagram whose physical source set contains one
    /// of these frame positions, including incomplete groups at capture end.
    pub datagram_frames: Vec<u64>,
    /// Matching physical records also include every datagram reconstructed on
    /// that record. Stream indexes and derived protocol fields are available.
    pub filter: Option<&'a Filter>,
    pub max_selected_frames: usize,
}
impl Default for Selection<'_> {
    fn default() -> Self {
        Self {
            streams: Vec::new(),
            datagram_frames: Vec::new(),
            filter: None,
            max_selected_frames: 100_000,
        }
    }
}
impl Selection<'_> {
    pub fn validate(&self) -> Result<(), Error> {
        if self
            .streams
            .len()
            .saturating_add(self.datagram_frames.len())
            > MAX_SELECTORS
        {
            return Err(Error::Limit {
                field: "selectors",
                limit: MAX_SELECTORS,
            });
        }
        if self.max_selected_frames == 0 || self.max_selected_frames > MAX_SELECTED_FRAMES {
            return Err(Error::Limit {
                field: "max_selected_frames",
                limit: MAX_SELECTED_FRAMES,
            });
        }
        if self.datagram_frames.contains(&0)
            || (self.streams.is_empty() && self.datagram_frames.is_empty() && self.filter.is_none())
        {
            return Err(Error::Selection);
        }
        Ok(())
    }
}
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Analysis(#[from] super::Error),
    #[error("capture dependency selection exceeds {field}={limit}")]
    Limit { field: &'static str, limit: usize },
    #[error("capture dependency selection needs a filter, stream, or nonzero datagram frame")]
    Selection,
    #[error("capture dependency analysis lacks source records at frame {number}")]
    Sources { number: u64 },
}
impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Analysis(error) => error.classification(),
            Self::Limit { .. } => Classification::new("policy.export_limit", Kind::Policy, None),
            Self::Selection => Classification::new("cli.export_selection", Kind::Cli, None),
            Self::Sources { .. } => {
                Classification::new("internal.export_sources", Kind::Internal, None)
            }
        }
    }
}
#[derive(Debug)]
pub struct Plan {
    /// Sorted, one-based physical positions in the original capture.
    pub source_frames: BTreeSet<u64>,
    pub matched_streams: Vec<StreamRef>,
    pub unmatched_streams: Vec<StreamRef>,
    pub unmatched_datagram_frames: Vec<u64>,
    pub selected_complete_datagrams: u64,
    pub selected_incomplete_datagrams: Vec<IncompleteSources>,
    /// Incomplete groups not attributable to the requested selection. Missing
    /// transport headers cannot be used to guess their conversation index.
    pub unselected_incomplete_datagrams: usize,
    pub source_outcomes_omitted: u64,
    pub frames_read: u64,
    pub scopes: Vec<super::scope::Definition>,
    pub ip_reassembly: super::IpReassemblyReport,
}
/// Analyze all physical records before selecting; filtering the reassembly input
/// would discard exactly the dependencies this operation is intended to keep.
pub fn plan<R: Read>(
    reader: &mut Reader<R>,
    registry: Arc<Registry>,
    options: &Options<'_>,
    selection: &Selection<'_>,
) -> Result<Plan, Error> {
    selection.validate()?;
    let requested_streams: BTreeSet<_> = selection.streams.iter().copied().collect();
    let requested_datagrams: BTreeSet<_> = selection.datagram_frames.iter().copied().collect();
    let mut matched_streams = BTreeSet::new();
    let mut matched_datagrams = BTreeSet::new();
    let mut frames = BTreeSet::new();
    let mut selected_complete_datagrams = 0;
    let run_options = Options {
        track_sources: true,
        tcp_events: false,
        filter: None,
        ..options.clone()
    };
    let run = super::run(reader, registry, &run_options, |record| {
        let mut selected_views = Vec::new();
        let matched_filter = selection
            .filter
            .map(|filter| record.matches(filter))
            .transpose()
            .map_err(|source| {
                BoundaryError::from_error(super::Error::Filter {
                    number: record.number,
                    source,
                })
            })?
            .unwrap_or(false);
        if matched_filter {
            insert(&mut frames, record.number, selection.max_selected_frames)
                .map_err(BoundaryError::from_error)?;
        }
        for (transport, conversation, sources) in [
            (
                StreamTransport::Tcp,
                record.tcp.and_then(|view| view.conversation),
                record.tcp_sources(),
            ),
            (
                StreamTransport::Udp,
                record.udp.and_then(|view| view.conversation),
                record.udp_sources(),
            ),
        ] {
            if let Some(conversation) = conversation {
                let stream = StreamRef {
                    transport,
                    index: conversation.index,
                };
                if requested_streams.contains(&stream) {
                    matched_streams.insert(stream);
                    selected_views.push(match transport {
                        StreamTransport::Tcp => {
                            record.tcp.expect("conversation came from TCP").decoded
                        }
                        StreamTransport::Udp => {
                            record.udp.expect("conversation came from UDP").decoded
                        }
                    });
                    let sources = sources.ok_or_else(|| {
                        BoundaryError::from_error(Error::Sources {
                            number: record.number,
                        })
                    })?;
                    include(&mut frames, sources, selection.max_selected_frames)
                        .map_err(BoundaryError::from_error)?;
                }
            }
        }
        for datagram in record.derived_datagrams() {
            let sources = datagram.sources.as_ref().ok_or_else(|| {
                BoundaryError::from_error(Error::Sources {
                    number: record.number,
                })
            })?;
            let selected = matches_sources(sources, &requested_datagrams, &mut matched_datagrams);
            if selected
                || matched_filter
                || selected_views
                    .iter()
                    .any(|decoded| std::ptr::eq(*decoded, &datagram.decoded))
            {
                selected_complete_datagrams += 1;
                include(&mut frames, sources, selection.max_selected_frames)
                    .map_err(BoundaryError::from_error)?;
            }
        }
        Ok(())
    })?;
    let mut selected_incomplete_datagrams = Vec::new();
    let mut unselected_incomplete_datagrams = 0;
    for group in run.incomplete_sources {
        if matches_sources(&group.sources, &requested_datagrams, &mut matched_datagrams) {
            include(&mut frames, &group.sources, selection.max_selected_frames)?;
            selected_incomplete_datagrams.push(group);
        } else {
            unselected_incomplete_datagrams += 1;
        }
    }
    Ok(Plan {
        source_frames: frames,
        unmatched_streams: requested_streams
            .difference(&matched_streams)
            .copied()
            .collect(),
        matched_streams: matched_streams.into_iter().collect(),
        unmatched_datagram_frames: requested_datagrams
            .difference(&matched_datagrams)
            .copied()
            .collect(),
        selected_complete_datagrams,
        selected_incomplete_datagrams,
        unselected_incomplete_datagrams,
        source_outcomes_omitted: run.source_outcomes_omitted,
        frames_read: run.frames_read,
        scopes: run.scopes,
        ip_reassembly: run.ip_reassembly,
    })
}
fn matches_sources(
    sources: &SourceSet,
    requested: &BTreeSet<u64>,
    matched: &mut BTreeSet<u64>,
) -> bool {
    let mut found = false;
    for frame in sources.frames() {
        if requested.contains(&frame.number) {
            matched.insert(frame.number);
            found = true;
        }
    }
    found
}
fn include(frames: &mut BTreeSet<u64>, sources: &SourceSet, limit: usize) -> Result<(), Error> {
    for source in sources.frames() {
        insert(frames, source.number, limit)?;
    }
    Ok(())
}
fn insert(frames: &mut BTreeSet<u64>, number: u64, limit: usize) -> Result<(), Error> {
    if !frames.contains(&number) && frames.len() >= limit {
        return Err(Error::Limit {
            field: "max_selected_frames",
            limit,
        });
    }
    frames.insert(number);
    Ok(())
}
