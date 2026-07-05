// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(feature = "pcap")]
mod pcap;
#[cfg(not(feature = "pcap"))]
mod unavailable;

#[cfg(feature = "pcap")]
pub(super) use pcap::CaptureWriter;
#[cfg(not(feature = "pcap"))]
pub(super) use unavailable::CaptureWriter;
