// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use super::{
    analysis::{Scope, StreamRef},
    contract::Error,
    provenance::Source,
    reassembly::DatagramKey,
};
use packetcraftr_core::analysis::export::Plan;
use packetcraftr_core::capture_file;
use serde::Serialize;
#[derive(Debug, Serialize)]
pub struct Incomplete {
    pub key: DatagramKey,
    pub sources: Vec<Source>,
}
/// What the physical selection read and copied.
#[derive(Debug, Serialize)]
pub struct Selection {
    pub format: &'static str,
    pub frames_read: u64,
    pub frames_selected: u64,
    pub captured_bytes_read: u64,
    pub captured_bytes_selected: u64,
    pub interfaces: usize,
    pub metadata_records: u64,
}
impl From<capture_file::SelectionReport> for Selection {
    fn from(value: capture_file::SelectionReport) -> Self {
        Self {
            format: value.format.as_str(),
            frames_read: value.frames_read,
            frames_selected: value.frames_selected,
            captured_bytes_read: value.captured_bytes_read,
            captured_bytes_selected: value.captured_bytes_selected,
            interfaces: value.interfaces,
            metadata_records: value.metadata_records,
        }
    }
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub path: String,
    #[serde(flatten)]
    pub capture: Selection,
    pub source_frames: Vec<u64>,
    pub matched_streams: Vec<StreamRef>,
    pub unmatched_streams: Vec<StreamRef>,
    pub unmatched_datagram_frames: Vec<u64>,
    pub selected_complete_datagrams: u64,
    pub selected_incomplete_datagrams: Vec<Incomplete>,
    pub unselected_incomplete_datagrams: usize,
    pub source_outcomes_omitted: u64,
    pub scopes: Vec<Scope>,
    pub ip_reassembly: super::reassembly::Report,
}
/// The destination path, the physical selection, and the plan it executed.
impl TryFrom<(String, capture_file::SelectionReport, Plan)> for Report {
    type Error = Error;
    fn try_from(
        (path, capture, plan): (String, capture_file::SelectionReport, Plan),
    ) -> Result<Self, Error> {
        Ok(Self {
            path,
            capture: capture.into(),
            source_frames: plan.source_frames.into_iter().collect(),
            matched_streams: plan.matched_streams.into_iter().map(Into::into).collect(),
            unmatched_streams: plan.unmatched_streams.into_iter().map(Into::into).collect(),
            unmatched_datagram_frames: plan.unmatched_datagram_frames,
            selected_complete_datagrams: plan.selected_complete_datagrams,
            selected_incomplete_datagrams: plan
                .selected_incomplete_datagrams
                .into_iter()
                .map(|group| {
                    Ok(Incomplete {
                        key: group.key.into(),
                        sources: group
                            .sources
                            .frames()
                            .iter()
                            .map(Source::try_from)
                            .collect::<Result<_, Error>>()?,
                    })
                })
                .collect::<Result<_, Error>>()?,
            unselected_incomplete_datagrams: plan.unselected_incomplete_datagrams,
            source_outcomes_omitted: plan.source_outcomes_omitted,
            scopes: plan
                .scopes
                .into_iter()
                .map(Scope::try_from)
                .collect::<Result<_, _>>()?,
            ip_reassembly: (&plan.ip_reassembly).into(),
        })
    }
}
