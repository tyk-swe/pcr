// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    FrameRecord, Options, StreamRef, StreamTransport,
    provenance::{IncompleteSources, SourceSet},
};
use crate::{
    capture_file::Reader,
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
    pub datagram_frames: Vec<u64>,
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
        super::error::check_ceiling(
            "max_selected_frames",
            self.max_selected_frames as u64,
            MAX_SELECTED_FRAMES as u64,
        )?;
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
            Self::Selection => Classification::new("cli.export_selection", Kind::Usage, None),
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
    let mut selected = Selected::new(selection);
    let run_options = Options {
        track_sources: true,
        tcp_events: false,
        filter: None,
        stream: None,
        plan: super::Plan::default(),
        ..options.clone()
    };
    let run = super::run(reader, registry, &run_options, |record| {
        selected.visit(&record)
    })?;
    let mut selected_incomplete_datagrams = Vec::new();
    let mut unselected_incomplete_datagrams = 0;
    for group in run.incomplete_sources {
        if selected.matches(&group.sources) {
            selected.include(&group.sources)?;
            selected_incomplete_datagrams.push(group);
        } else {
            unselected_incomplete_datagrams += 1;
        }
    }
    Ok(Plan {
        source_frames: selected.frames,
        unmatched_streams: selected
            .requested_streams
            .difference(&selected.matched_streams)
            .copied()
            .collect(),
        matched_streams: selected.matched_streams.into_iter().collect(),
        unmatched_datagram_frames: selected
            .requested_datagrams
            .difference(&selected.matched_datagrams)
            .copied()
            .collect(),
        selected_complete_datagrams: selected.complete_datagrams,
        selected_incomplete_datagrams,
        unselected_incomplete_datagrams,
        source_outcomes_omitted: run.source_outcomes_omitted,
        frames_read: run.frames_read,
        scopes: run.scopes,
        ip_reassembly: run.ip_reassembly,
    })
}
struct Selected<'a> {
    filter: Option<&'a Filter>,
    limit: usize,
    requested_streams: BTreeSet<StreamRef>,
    requested_datagrams: BTreeSet<u64>,
    frames: BTreeSet<u64>,
    matched_streams: BTreeSet<StreamRef>,
    matched_datagrams: BTreeSet<u64>,
    complete_datagrams: u64,
}
impl<'a> Selected<'a> {
    fn new(selection: &Selection<'a>) -> Self {
        Self {
            filter: selection.filter,
            limit: selection.max_selected_frames,
            requested_streams: selection.streams.iter().copied().collect(),
            requested_datagrams: selection.datagram_frames.iter().copied().collect(),
            frames: BTreeSet::new(),
            matched_streams: BTreeSet::new(),
            matched_datagrams: BTreeSet::new(),
            complete_datagrams: 0,
        }
    }
    fn visit(&mut self, record: &FrameRecord<'_>) -> Result<(), BoundaryError> {
        let matched_filter = self
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
            self.insert(record.number)
                .map_err(BoundaryError::from_error)?;
        }
        let mut selected_views = Vec::new();
        for (transport, view, sources) in [
            (
                StreamTransport::Tcp,
                record
                    .tcp
                    .and_then(|view| Some((view.conversation?, view.decoded))),
                record.tcp_sources(),
            ),
            (
                StreamTransport::Udp,
                record
                    .udp
                    .and_then(|view| Some((view.conversation?, view.decoded))),
                record.udp_sources(),
            ),
        ] {
            if let Some((conversation, decoded)) = view {
                let stream = StreamRef {
                    transport,
                    index: conversation.index,
                };
                if self.requested_streams.contains(&stream) {
                    self.matched_streams.insert(stream);
                    selected_views.push(decoded);
                    let sources = sources.ok_or_else(|| {
                        BoundaryError::from_error(Error::Sources {
                            number: record.number,
                        })
                    })?;
                    self.include(sources).map_err(BoundaryError::from_error)?;
                }
            }
        }
        for datagram in record.derived_datagrams() {
            let sources = datagram.sources.as_ref().ok_or_else(|| {
                BoundaryError::from_error(Error::Sources {
                    number: record.number,
                })
            })?;
            let selected = self.matches(sources);
            if selected
                || matched_filter
                || selected_views
                    .iter()
                    .any(|decoded| std::ptr::eq(*decoded, &datagram.decoded))
            {
                self.complete_datagrams += 1;
                self.include(sources).map_err(BoundaryError::from_error)?;
            }
        }
        Ok(())
    }
    fn matches(&mut self, sources: &SourceSet) -> bool {
        let mut found = false;
        for frame in sources.frames() {
            if self.requested_datagrams.contains(&frame.number) {
                self.matched_datagrams.insert(frame.number);
                found = true;
            }
        }
        found
    }
    fn include(&mut self, sources: &SourceSet) -> Result<(), Error> {
        for source in sources.frames() {
            self.insert(source.number)?;
        }
        Ok(())
    }
    fn insert(&mut self, number: u64) -> Result<(), Error> {
        if !self.frames.contains(&number) && self.frames.len() >= self.limit {
            return Err(Error::Limit {
                field: "max_selected_frames",
                limit: self.limit,
            });
        }
        self.frames.insert(number);
        Ok(())
    }
}
