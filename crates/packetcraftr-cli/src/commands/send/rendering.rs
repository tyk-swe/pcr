// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `send`'s text output.

pub(super) fn sent_line(frame: &packetcraftr::send::SentFrame) -> String {
    let route = frame.packet.route();
    format!(
        "sent {} bytes via {} (index {}, {})",
        frame.packet.wire_bytes().len(),
        route.plan.decision.interface.name,
        route.plan.decision.interface.index,
        route.plan.mode
    )
}
