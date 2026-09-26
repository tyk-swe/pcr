// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod decode;
mod encode;

pub(in crate::capture_file) use decode::{read_next_pcap_record, read_pcap_header};
pub(in crate::capture_file) use encode::{write_pcap_frame, write_pcap_header};
