// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! One captured frame matched to the request it answers.

use std::time::Duration;

use packetcraftr_core::decode::DecodedPacket;

/// A decoded frame correlated with the request at `request_index`, received
/// `latency` after that request was sent.
#[derive(Clone, Debug)]
pub struct Response {
    pub request_index: usize,
    pub response: DecodedPacket,
    pub latency: Duration,
}
