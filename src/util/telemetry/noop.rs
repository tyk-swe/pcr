// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NoopCounter;

impl NoopCounter {
    pub(crate) fn inc(&self) {}

    pub(crate) fn inc_by(&self, _amount: u64) {}
}

pub(crate) fn get_frame_sent_counters(
    _link_type: &str,
    _transport: &str,
) -> (NoopCounter, NoopCounter) {
    (NoopCounter, NoopCounter)
}

#[cfg(feature = "pcap")]
pub(crate) fn record_listener_packet(_protocol: &str) {}

pub(crate) fn record_rule_action(_action: &str, _outcome: &str) {}

pub(crate) fn record_rule_executor_drop(_action: &str, _reason: &str) {}

#[cfg(feature = "pcap")]
pub(crate) fn record_listener_dropped_packet(_reason: &str) {}
