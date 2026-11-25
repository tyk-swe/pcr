// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::budget::Charge;
use super::model::PeerSettings;
use crate::analysis::http2::IssueCode;
use crate::protocol::application::http2::Setting;
use std::collections::{BTreeMap, VecDeque};

pub(crate) const HEADER_TABLE_SIZE: u16 = 0x1;
pub(crate) const ENABLE_PUSH: u16 = 0x2;
pub(crate) const MAX_CONCURRENT_STREAMS: u16 = 0x3;
pub(crate) const INITIAL_WINDOW_SIZE: u16 = 0x4;
pub(crate) const MAX_FRAME_SIZE: u16 = 0x5;
pub(crate) const MAX_HEADER_LIST_SIZE: u16 = 0x6;
pub(crate) const WINDOW_MAX: i64 = 0x7fff_ffff;
const MIN_FRAME_SIZE: u32 = 16_384;
const MAX_FRAME_SIZE_LIMIT: u32 = 16_777_215;

pub(crate) struct SettingIssue {
    pub code: IssueCode,
    pub detail: &'static str,
}

pub(crate) struct PendingSettings {
    pub final_values: PeerSettings,
    pub minimum_table_size: Option<u32>,
    pub possibly_applied_table_minimum: bool,
    pub window_delta: i64,
    pub peak_window_delta: Option<i64>,
    pub sender_stream_limit: u32,
    pub window_grants: BTreeMap<u32, i64>,
    pub charge: Charge,
}

pub(crate) struct Applied {
    pub pending: PendingSettings,
    pub issues: Vec<SettingIssue>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CausalTableMinimum {
    pub required: Option<u32>,
    pub confirmed_prefix: usize,
    pub uncertain: Option<u32>,
}

pub(crate) struct DirectionSettings {
    pub advertised: PeerSettings,
    pub acknowledged: PeerSettings,
    pub seen: bool,
    pub pending: VecDeque<PendingSettings>,
    pub uncertain_table_minimum: Option<u32>,
}

impl DirectionSettings {
    pub(crate) fn new() -> Self {
        Self {
            advertised: PeerSettings::default(),
            acknowledged: PeerSettings::default(),
            seen: false,
            pending: VecDeque::new(),
            uncertain_table_minimum: None,
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
            possibly_applied_table_minimum: false,
            window_delta: 0,
            peak_window_delta: None,
            sender_stream_limit: 0,
            window_grants: BTreeMap::new(),
            charge: Charge::default(),
        };
        let mut issues: Vec<SettingIssue> = Vec::new();
        for &setting in settings {
            if let Err(issue) = validate_setting(setting, server_sent) {
                if issues.iter().any(|existing| existing.code == issue.code) {
                    continue;
                }
                issues.push(issue);
                if setting.id == ENABLE_PUSH && setting.value <= 1 {
                    pending.final_values.enable_push = setting.value != 0;
                }
                continue;
            }
            apply_valid_setting(&mut pending, setting);
        }
        self.advertised = pending.final_values;
        Applied { pending, issues }
    }

    /// A size above every earlier ceiling proves receipt of the first pending
    /// SETTINGS that permits it, including that frame's ordered decreases.
    pub(crate) fn causal_table_minimum(&self, maximum: u32) -> CausalTableMinimum {
        let mut ceiling = self.acknowledged.header_table_size;
        if maximum <= ceiling {
            return CausalTableMinimum::default();
        }
        let mut required: Option<u32> = None;
        let mut uncertain: Option<u32> = None;
        for (index, pending) in self.pending.iter().enumerate() {
            if let Some(value) = pending.minimum_table_size {
                let target = if pending.possibly_applied_table_minimum {
                    &mut uncertain
                } else {
                    &mut required
                };
                *target = Some(target.map_or(value, |old| old.min(value)));
            }
            ceiling = ceiling.max(pending.final_values.header_table_size);
            if maximum <= ceiling {
                return CausalTableMinimum {
                    required,
                    confirmed_prefix: index + 1,
                    uncertain,
                };
            }
        }
        CausalTableMinimum::default()
    }

    pub(crate) fn observed_table_updates(&mut self, minimum: u32, confirmed_prefix: usize) {
        for (index, pending) in self.pending.iter_mut().enumerate() {
            if index < confirmed_prefix {
                pending.minimum_table_size = None;
                pending.possibly_applied_table_minimum = false;
            } else if pending
                .minimum_table_size
                .is_some_and(|bound| minimum <= bound)
            {
                // A voluntary shrink before receipt has identical wire bytes.
                // Retain the obligation and its uncertainty until causal proof.
                pending.possibly_applied_table_minimum = true;
            }
        }
    }

    pub(crate) fn acknowledge(&mut self) -> Option<PendingSettings> {
        let pending = self.pending.pop_front()?;
        self.acknowledged = pending.final_values;
        Some(pending)
    }
}

fn validate_setting(setting: Setting, server_sent: bool) -> Result<(), SettingIssue> {
    match setting.id {
        ENABLE_PUSH if setting.value > 1 => Err(SettingIssue {
            code: IssueCode::SettingsEnablePushValue,
            detail: "SETTINGS_ENABLE_PUSH value is not 0 or 1",
        }),
        ENABLE_PUSH if server_sent => Err(SettingIssue {
            code: IssueCode::SettingsEnablePushRole,
            detail: "a server must not send SETTINGS_ENABLE_PUSH",
        }),
        INITIAL_WINDOW_SIZE if setting.value > WINDOW_MAX as u32 => Err(SettingIssue {
            code: IssueCode::SettingsInitialWindowSize,
            detail: "SETTINGS_INITIAL_WINDOW_SIZE exceeds 2^31-1",
        }),
        MAX_FRAME_SIZE if !(MIN_FRAME_SIZE..=MAX_FRAME_SIZE_LIMIT).contains(&setting.value) => {
            Err(SettingIssue {
                code: IssueCode::SettingsMaxFrameSize,
                detail: "SETTINGS_MAX_FRAME_SIZE is outside 16384..=16777215",
            })
        }
        _ => Ok(()),
    }
}

fn apply_valid_setting(pending: &mut PendingSettings, setting: Setting) {
    match setting.id {
        HEADER_TABLE_SIZE => {
            pending.final_values.header_table_size = setting.value;
            pending.minimum_table_size = Some(
                pending
                    .minimum_table_size
                    .map_or(setting.value, |min| min.min(setting.value)),
            );
        }
        ENABLE_PUSH => {
            pending.final_values.enable_push = setting.value != 0;
        }
        MAX_CONCURRENT_STREAMS => {
            pending.final_values.max_concurrent_streams = Some(setting.value);
        }
        INITIAL_WINDOW_SIZE => {
            pending.window_delta +=
                i64::from(setting.value) - i64::from(pending.final_values.initial_window_size);
            // Preserve intermediate overflow checks without retaining
            // one update per duplicate setting for every open stream.
            pending.peak_window_delta = Some(
                pending
                    .peak_window_delta
                    .map_or(pending.window_delta, |peak| peak.max(pending.window_delta)),
            );
            pending.final_values.initial_window_size = setting.value;
        }
        MAX_FRAME_SIZE => {
            pending.final_values.max_frame_size = setting.value;
        }
        MAX_HEADER_LIST_SIZE => {
            pending.final_values.max_header_list_size = Some(setting.value);
        }
        _ => {}
    }
}
