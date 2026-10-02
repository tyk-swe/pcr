// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::model::PeerSettings;
use crate::protocol::application::http2::Setting;
use std::collections::VecDeque;

pub(crate) const HEADER_TABLE_SIZE: u16 = 0x1;
pub(crate) const ENABLE_PUSH: u16 = 0x2;
pub(crate) const MAX_CONCURRENT_STREAMS: u16 = 0x3;
pub(crate) const INITIAL_WINDOW_SIZE: u16 = 0x4;
pub(crate) const MAX_FRAME_SIZE: u16 = 0x5;
pub(crate) const MAX_HEADER_LIST_SIZE: u16 = 0x6;
pub(crate) const WINDOW_MAX: i64 = 0x7fff_ffff;

pub(crate) fn defaults() -> PeerSettings {
    PeerSettings {
        header_table_size: 4096,
        enable_push: true,
        max_concurrent_streams: None,
        initial_window_size: 65535,
        max_frame_size: 16384,
        max_header_list_size: None,
    }
}

pub(crate) struct SettingIssue {
    pub code: &'static str,
    pub detail: &'static str,
}

pub(crate) struct PendingSettings {
    pub final_values: PeerSettings,
    pub minimum_table_size: Option<u32>,
    pub window_delta: i64,
    pub peak_window_delta: Option<i64>,
    pub charged: usize,
}

pub(crate) struct Applied {
    pub pending: PendingSettings,
    pub issues: Vec<SettingIssue>,
}

pub(crate) struct Acked {
    pub values: PeerSettings,
    pub minimum_table_size: Option<u32>,
    pub window_delta: i64,
    pub peak_window_delta: Option<i64>,
    pub charged: usize,
}

pub(crate) struct DirectionSettings {
    pub advertised: PeerSettings,
    pub acknowledged: PeerSettings,
    pub seen: bool,
    pub pending: VecDeque<PendingSettings>,
}

impl DirectionSettings {
    pub(crate) fn new() -> Self {
        Self {
            advertised: defaults(),
            acknowledged: defaults(),
            seen: false,
            pending: VecDeque::new(),
        }
    }
    pub(crate) fn permitted_frame_size(&self) -> u32 {
        self.pending.iter().fold(
            self.advertised
                .max_frame_size
                .max(self.acknowledged.max_frame_size),
            |limit, pending| limit.max(pending.final_values.max_frame_size),
        )
    }
    pub(crate) fn apply(&mut self, settings: &[Setting], server_sent: bool) -> Applied {
        self.seen = true;
        let mut pending = PendingSettings {
            final_values: self.advertised,
            minimum_table_size: None,
            window_delta: 0,
            peak_window_delta: None,
            charged: 0,
        };
        let mut issues = Vec::new();
        for setting in settings {
            let code = match setting.id {
                ENABLE_PUSH if setting.value > 1 => Some("settings_enable_push_value"),
                ENABLE_PUSH if server_sent => Some("settings_enable_push_role"),
                INITIAL_WINDOW_SIZE if setting.value > WINDOW_MAX as u32 => {
                    Some("settings_initial_window_size")
                }
                MAX_FRAME_SIZE if !(16384..=16_777_215).contains(&setting.value) => {
                    Some("settings_max_frame_size")
                }
                _ => None,
            };
            if code.is_some_and(|code| issues.iter().any(|issue: &SettingIssue| issue.code == code))
            {
                continue;
            }
            match setting.id {
                HEADER_TABLE_SIZE => {
                    pending.final_values.header_table_size = setting.value;
                    pending.minimum_table_size = Some(
                        pending
                            .minimum_table_size
                            .map_or(setting.value, |min| min.min(setting.value)),
                    );
                }
                ENABLE_PUSH => match setting.value {
                    0 | 1 => {
                        if server_sent {
                            issues.push(SettingIssue {
                                code: "settings_enable_push_role",
                                detail: "a server must not send SETTINGS_ENABLE_PUSH",
                            });
                        }
                        pending.final_values.enable_push = setting.value != 0;
                    }
                    _ => issues.push(SettingIssue {
                        code: "settings_enable_push_value",
                        detail: "SETTINGS_ENABLE_PUSH value is not 0 or 1",
                    }),
                },
                MAX_CONCURRENT_STREAMS => {
                    pending.final_values.max_concurrent_streams = Some(setting.value);
                }
                INITIAL_WINDOW_SIZE => {
                    if setting.value > WINDOW_MAX as u32 {
                        issues.push(SettingIssue {
                            code: "settings_initial_window_size",
                            detail: "SETTINGS_INITIAL_WINDOW_SIZE exceeds 2^31-1",
                        });
                    } else {
                        pending.window_delta += i64::from(setting.value)
                            - i64::from(pending.final_values.initial_window_size);
                        // Preserve intermediate overflow checks without retaining
                        // one update per duplicate setting for every open stream.
                        pending.peak_window_delta = Some(
                            pending
                                .peak_window_delta
                                .map_or(pending.window_delta, |peak| {
                                    peak.max(pending.window_delta)
                                }),
                        );
                        pending.final_values.initial_window_size = setting.value;
                    }
                }
                MAX_FRAME_SIZE => {
                    if !(16384..=16_777_215).contains(&setting.value) {
                        issues.push(SettingIssue {
                            code: "settings_max_frame_size",
                            detail: "SETTINGS_MAX_FRAME_SIZE is outside 16384..=16777215",
                        });
                    } else {
                        pending.final_values.max_frame_size = setting.value;
                    }
                }
                MAX_HEADER_LIST_SIZE => {
                    pending.final_values.max_header_list_size = Some(setting.value);
                }
                _ => {}
            }
        }
        self.advertised = pending.final_values;
        Applied { pending, issues }
    }
    /// A size above every earlier ceiling proves receipt of the first pending
    /// SETTINGS that permits it, including that frame's ordered decreases.
    pub(crate) fn causal_table_minimum(&self, maximum: u32) -> (Option<u32>, usize) {
        let mut ceiling = self.acknowledged.header_table_size;
        if maximum <= ceiling {
            return (None, 0);
        }
        let mut minimum: Option<u32> = None;
        for (index, pending) in self.pending.iter().enumerate() {
            if let Some(value) = pending.minimum_table_size {
                minimum = Some(minimum.map_or(value, |old| old.min(value)));
            }
            ceiling = ceiling.max(pending.final_values.header_table_size);
            if maximum <= ceiling {
                return (minimum, index + 1);
            }
        }
        (None, 0)
    }

    pub(crate) fn observed_table_updates(&mut self, minimum: u32, confirmed_prefix: usize) {
        for (index, pending) in self.pending.iter_mut().enumerate() {
            if index < confirmed_prefix
                || pending
                    .minimum_table_size
                    .is_some_and(|bound| minimum <= bound)
            {
                // Do not require an already observed shrink a second time on ACK.
                pending.minimum_table_size = None;
            }
        }
    }

    pub(crate) fn acknowledge(&mut self) -> Option<Acked> {
        let pending = self.pending.pop_front()?;
        self.acknowledged = pending.final_values;
        Some(Acked {
            values: pending.final_values,
            minimum_table_size: pending.minimum_table_size,
            window_delta: pending.window_delta,
            peak_window_delta: pending.peak_window_delta,
            charged: pending.charged,
        })
    }
}
