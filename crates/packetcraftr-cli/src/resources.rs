// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Opt-in runtime observations, separate from setting declarations and presets.
//! Observations never govern admission, protocol mechanics, or runtime construction.

mod settings;
pub(crate) use settings::{
    Enabled, Field, Preset, PresetDefaults, SettingValue, Settings, Stage, Unit, collect_settings,
    declare, policy_value,
};

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};

use packetcraftr::runtime::Runtime;

use crate::output::{
    envelope::Envelope,
    resources::{Report, Setting, Worker},
};

struct Context {
    settings: Vec<(Setting, Enabled)>,
    stream_index: AtomicBool,
    runtimes: Mutex<Vec<(&'static str, Runtime)>>,
}
static CONTEXT: OnceLock<Context> = OnceLock::new();

/// Installs the selected command's declared settings for runtime diagnostics.
pub(crate) fn configure(settings: Vec<(Setting, Enabled)>) {
    let _ = CONTEXT.set(Context {
        settings,
        stream_index: AtomicBool::new(true),
        runtimes: Mutex::new(Vec::new()),
    });
}

/// Reports whether the comparison needs the capture stream index, which
/// enables or disables the [`Enabled::StreamIndex`] stages.
pub(crate) fn stream_index_needed(needed: bool) {
    if let Some(context) = CONTEXT.get() {
        context.stream_index.store(needed, Ordering::Relaxed);
    }
}

/// Registers an already-constructed runtime. Keeping a clone observes admission;
/// it neither holds permits nor keeps callback captures alive.
pub(crate) fn register_runtime(name: &'static str, runtime: &Runtime) {
    if let Some(context) = CONTEXT.get() {
        let mut runtimes = context
            .runtimes
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // A CLI invocation constructs at most one runtime per assembly owner.
        // Keep the diagnostic registry bounded even if future commands change.
        if runtimes.len() < 16 {
            runtimes.push((name, runtime.clone()));
        }
    }
}

pub(crate) fn snapshot() -> Option<Report> {
    let context = CONTEXT.get()?;
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
        context
            .runtimes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(name, runtime)| Worker::from((*name, runtime.snapshot()))),
    );
    let stream_index = context.stream_index.load(Ordering::Relaxed);
    let settings = context
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
    Some(Report {
        settings,
        workers,
        cooperative_deadlines: true,
        hard_rss_limit: false,
    })
}

pub(crate) fn decorate<T>(envelope: Envelope<T>) -> Envelope<T> {
    match snapshot() {
        Some(resources) => envelope.with_resources(resources),
        None => envelope,
    }
}
