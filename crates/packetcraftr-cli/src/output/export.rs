// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use super::{
    contract::Error,
    provenance::{Source, from_source_set},
};
use packetcraftr_core::analysis::{
    self, StreamRef, pcap, reassembly::ip::DatagramKey, scope::Definition,
};
use serde::Serialize;
#[derive(Debug, Serialize)]
pub struct Incomplete {
    pub key: DatagramKey,
    pub sources: Vec<Source>,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub path: String,
    #[serde(flatten, serialize_with = "capture_report")]
    pub capture: pcap::SelectionReport,
    pub source_frames: Vec<u64>,
    pub matched_streams: Vec<StreamRef>,
    pub unmatched_streams: Vec<StreamRef>,
    pub unmatched_datagram_frames: Vec<u64>,
    pub selected_complete_datagrams: u64,
    pub selected_incomplete_datagrams: Vec<Incomplete>,
    pub unselected_incomplete_datagrams: usize,
    pub source_outcomes_omitted: u64,
    pub scopes: Vec<Definition>,
    pub ip_reassembly: super::reassembly::Report,
}
impl Report {
    pub fn new(
        path: String,
        capture: pcap::SelectionReport,
        plan: analysis::export::Plan,
    ) -> Result<Self, Error> {
        Ok(Self {
            path,
            capture,
            source_frames: plan.source_frames.into_iter().collect(),
            matched_streams: plan.matched_streams,
            unmatched_streams: plan.unmatched_streams,
            unmatched_datagram_frames: plan.unmatched_datagram_frames,
            selected_complete_datagrams: plan.selected_complete_datagrams,
            selected_incomplete_datagrams: plan
                .selected_incomplete_datagrams
                .into_iter()
                .map(|group| {
                    Ok(Incomplete {
                        key: group.key,
                        sources: from_source_set(&group.sources)?,
                    })
                })
                .collect::<Result<_, Error>>()?,
            unselected_incomplete_datagrams: plan.unselected_incomplete_datagrams,
            source_outcomes_omitted: plan.source_outcomes_omitted,
            scopes: plan.scopes,
            ip_reassembly: super::reassembly::Report::from_analysis(&plan.ip_reassembly),
        })
    }
}

fn capture_report<S: serde::Serializer>(
    value: &pcap::SelectionReport,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct Capture<'a> {
        format: &'a str,
        frames_read: u64,
        frames_selected: u64,
        captured_bytes_read: u64,
        captured_bytes_selected: u64,
        interfaces: usize,
        metadata_records: u64,
    }
    Capture {
        format: value.format.as_str(),
        frames_read: value.frames_read,
        frames_selected: value.frames_selected,
        captured_bytes_read: value.captured_bytes_read,
        captured_bytes_selected: value.captured_bytes_selected,
        interfaces: value.interfaces,
        metadata_records: value.metadata_records,
    }
    .serialize(serializer)
}
