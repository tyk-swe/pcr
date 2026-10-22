// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod settings;

/// The default NDJSON per-write wait, in milliseconds.
pub(crate) const OUTPUT_TIMEOUT_MS: u64 = 1000;

pub(crate) use settings::{
    Enabled, Field, Preset, PresetDefaults, SettingValue, Settings, Stage, Unit, collect_settings,
    declare, policy_value,
};

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};

use packetcraftr::runtime::Runtime;

use crate::output::resources::{Report, Setting, Worker};

pub(crate) struct Diagnostics {
    settings: Vec<(Setting, Enabled)>,
    stream_index: AtomicBool,
    runtimes: Mutex<Vec<(&'static str, Runtime)>>,
}
impl Diagnostics {
    pub(crate) fn new(settings: Vec<(Setting, Enabled)>) -> Self {
        Self {
            settings,
            stream_index: AtomicBool::new(true),
            runtimes: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn stream_index_needed(&self, needed: bool) {
        self.stream_index.store(needed, Ordering::Relaxed);
    }

    pub(crate) fn register_runtime(&self, name: &'static str, runtime: &Runtime) {
        {
            let mut runtimes = self.runtimes.lock().unwrap_or_else(PoisonError::into_inner);
            // A CLI invocation constructs at most one runtime per assembly owner.
            // Keep the diagnostic registry bounded even if future commands change.
            if runtimes.len() < 16 {
                runtimes.push((name, runtime.clone()));
            }
        }
    }

    pub(crate) fn snapshot(&self) -> Report {
        let mut workers = vec![
            Worker::from((
                "native_process",
                packetcraftr_netio::resources::native_snapshot(),
            )),
            Worker::from((
                "tcp_connect_process",
                packetcraftr_netio::resources::tcp_connect_snapshot(),
            )),
        ];
        workers.extend(
            self.runtimes
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .map(|(name, runtime)| Worker::from((*name, runtime.snapshot()))),
        );
        let stream_index = self.stream_index.load(Ordering::Relaxed);
        let settings = self
            .settings
            .iter()
            .map(|(setting, enabled)| Setting {
                enabled: match enabled {
                    Enabled::Fixed(enabled) => *enabled,
                    Enabled::StreamIndex => stream_index,
                },
                ..setting.clone()
            })
            .collect();
        Report {
            settings,
            workers,
            cooperative_deadlines: true,
            hard_rss_limit: false,
        }
    }
}
