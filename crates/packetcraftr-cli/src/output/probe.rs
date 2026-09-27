// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::probe;

published_enum! {
    pub enum Transport from probe::Transport {
        Tcp => "tcp",
        Udp => "udp",
        Icmp => "icmp",
    }
}

published_enum! {
    pub enum ProbeStatus from probe::ProbeStatus {
        Response => "response",
        Timeout => "timeout",
    }
}
