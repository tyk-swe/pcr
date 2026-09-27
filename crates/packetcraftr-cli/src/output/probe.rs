// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Vocabulary shared by the probe-based workflows, `scan` and `traceroute`.

use packetcraftr::probe;

published_enum! {
    /// The transport a probe strategy uses.
    pub enum Transport from probe::Transport {
        Tcp => "tcp",
        Udp => "udp",
        Icmp => "icmp",
    }
}

published_enum! {
    /// Whether a probe was answered before its timeout.
    pub enum ProbeStatus from probe::ProbeStatus {
        Response => "response",
        Timeout => "timeout",
    }
}
