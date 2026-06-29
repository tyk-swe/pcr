// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use crate::domain::spec::TransmissionSpec;

#[derive(Debug, Clone)]
pub struct PreflightView {
    pub destination: String,
    pub selected_destination_ip: String,
    pub destination_reason: &'static str,
    pub destination_family: &'static str,
    pub interface: String,
    pub interface_reason: &'static str,
    pub source_ip: String,
    pub source_reason: &'static str,
    pub mode: &'static str,
    pub transport: &'static str,
    pub count: Option<u64>,
    pub attempts: Option<u64>,
    pub units_per_attempt: u64,
    pub total_emitted_units: Option<u64>,
    pub send_mode: &'static str,
    pub frame_count: usize,
    pub largest_frame_len: usize,
    pub transmit: TransmissionSpec,
}
