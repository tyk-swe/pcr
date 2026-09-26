// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Invocation-local assembly of opt-in diagnostics. No protocol mechanics or
//! admission decisions depend on these observations.
//!
//! Each command declares its settings from its typed arguments through
//! [`Spec::resources`], naming each
//! setting's unit, stage, and whether the stage runs. The command-line
//! definition supplies only the flag name, help text, and value source.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};

use crate::output::{
    contract::Format,
    envelope::Envelope,
    resources::{Report, Setting, Value, Worker},
};
use clap::{ArgMatches, CommandFactory, ValueEnum, parser::ValueSource};
use packetcraftr::runtime::Runtime;

use crate::cli::Cli;
use crate::commands::Spec;
use crate::presets::Preset;
use crate::rendering::OUTPUT_TIMEOUT_MS;

struct Context {
    settings: Vec<(Setting, Enabled)>,
    stream_index: AtomicBool,
    runtimes: Mutex<Vec<(&'static str, Runtime)>>,
}
static CONTEXT: OnceLock<Context> = OnceLock::new();

/// What a setting's value measures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Unit {
    Count,
    Bytes,
    Milliseconds,
    /// A named policy choice rather than a quantity.
    Policy,
}

impl Unit {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Count => "count",
            Self::Bytes => "bytes",
            Self::Milliseconds => "milliseconds",
            Self::Policy => "policy",
        }
    }
}

/// The processing stage a setting bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stage {
    Output,
    CaptureStorage,
    Preparation,
    Comparison,
    ObservationCollection,
    ResultRetention,
    IndexedMetadata,
    NativeCapture,
    /// Capture-file reader bounds. A command that is not
    /// [`OFFLINE`](crate::commands::Spec::OFFLINE) reads its capture as part
    /// of a live operation, so there they are [`Stage::Operation`] settings.
    PhysicalInput,
    Operation,
    ActiveState,
}

impl Stage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Output => "output",
            Self::CaptureStorage => "capture_storage",
            Self::Preparation => "preparation",
            Self::Comparison => "comparison",
            Self::ObservationCollection => "observation_collection",
            Self::ResultRetention => "result_retention",
            Self::IndexedMetadata => "indexed_metadata",
            Self::NativeCapture => "native_capture",
            Self::PhysicalInput => "physical_input",
            Self::Operation => "operation",
            Self::ActiveState => "active_state",
        }
    }
}

/// Whether the command runs a setting's stage in this invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Enabled {
    /// Known from the arguments alone.
    Fixed(bool),
    /// Runs only when the comparison needs the capture stream index. The
    /// command reports that through [`stream_index_needed`] once its rules and
    /// filters compile; until then the stage counts as enabled.
    StreamIndex,
}

impl From<bool> for Enabled {
    fn from(enabled: bool) -> Self {
        Self::Fixed(enabled)
    }
}

/// A typed argument value as it is reported; `None` for an unset option.
pub(crate) trait SettingValue {
    fn setting_value(&self) -> Option<Value>;
}

macro_rules! numeric_setting_values {
    ($($number:ty),*) => {$(
        impl SettingValue for $number {
            fn setting_value(&self) -> Option<Value> {
                Some(Value::Number(u64::try_from(*self).unwrap_or(u64::MAX)))
            }
        }
    )*};
}

numeric_setting_values!(u8, u64, usize);

impl<T: SettingValue> SettingValue for Option<T> {
    fn setting_value(&self) -> Option<Value> {
        self.as_ref().and_then(SettingValue::setting_value)
    }
}

/// A policy choice reported under its command-line spelling.
pub(crate) fn policy_value<T: ValueEnum>(value: &T) -> Option<Value> {
    value
        .to_possible_value()
        .map(|value| Value::Policy(value.get_name().to_owned()))
}

/// Declares typed argument fields as resource settings:
/// `declare!(settings, group, [field: Unit @ Stage, field: Unit @ Stage if enabled])`.
/// Each field's name is its command-line argument id.
macro_rules! declare {
    (@enabled) => { $crate::resources::Enabled::Fixed(true) };
    (@enabled $enabled:expr) => { $crate::resources::Enabled::from($enabled) };
    (
        $settings:expr, $group:expr,
        [$($field:ident: $unit:ident @ $stage:ident $(if $enabled:expr)?),* $(,)?]
    ) => {{
        $(
            $settings.declare(
                stringify!($field),
                $crate::resources::SettingValue::setting_value(&$group.$field),
                $crate::resources::Unit::$unit,
                $crate::resources::Stage::$stage,
                $crate::resources::declare!(@enabled $($enabled)?),
            );
        )*
    }};
}
pub(crate) use declare;

/// The settings one invocation reports, collected from typed arguments.
pub(crate) struct Settings<'a> {
    root: (&'a clap::Command, &'a ArgMatches),
    selected: Option<(&'a clap::Command, &'a ArgMatches)>,
    preset: Option<Preset>,
    offline: bool,
    format: Format,
    declared: BTreeMap<String, (Setting, Enabled)>,
}

impl Settings<'_> {
    /// Declares one argument's effective value. `id` is the argument id; an
    /// unset optional argument (`value` is `None`) is not reported.
    ///
    /// # Panics
    ///
    /// If `id` names no argument of the selected command or the root command.
    pub(crate) fn declare(
        &mut self,
        id: &str,
        value: Option<Value>,
        unit: Unit,
        stage: Stage,
        enabled: Enabled,
    ) {
        let Some(value) = value else {
            return;
        };
        let (arg, matches) = self
            .selected
            .into_iter()
            .chain(std::iter::once(self.root))
            .find_map(|(definition, matches)| {
                definition
                    .get_arguments()
                    .find(|arg| arg.get_id() == id)
                    .map(|arg| (arg, matches))
            })
            .unwrap_or_else(|| panic!("resource setting {id} names no argument"));
        let stage = if stage == Stage::PhysicalInput && !self.offline {
            Stage::Operation
        } else {
            stage
        };
        let name = format!("--{}", arg.get_long().unwrap_or(id));
        let source = if matches.value_source(id) == Some(ValueSource::CommandLine) {
            "override".to_owned()
        } else if let Some(preset) = self.preset.filter(|preset| preset.value(id).is_some()) {
            format!("preset:{}", preset.name())
        } else {
            "default".to_owned()
        };
        let setting = Setting {
            name: name.clone(),
            value,
            unit: unit.as_str().to_owned(),
            stage: stage.as_str().to_owned(),
            scope: arg
                .get_long_help()
                .or_else(|| arg.get_help())
                .map(ToString::to_string)
                .unwrap_or_default(),
            source,
            enabled: true,
        };
        self.declared.insert(name, (setting, enabled));
    }

    /// Declares the aggregate JSON retention a command derives from its
    /// physical frame ceiling.
    pub(crate) fn retained_result_items(&mut self, max_frames: u64) {
        let name = "retained_result_items";
        self.declared.insert(
            name.to_owned(),
            (
                Setting {
                    name: name.to_owned(),
                    value: Value::Number(max_frames),
                    unit: Unit::Count.as_str().to_owned(),
                    stage: Stage::ResultRetention.as_str().to_owned(),
                    scope: "Aggregate JSON items; derived from the physical frame ceiling"
                        .to_owned(),
                    source: "derived".to_owned(),
                    enabled: true,
                },
                Enabled::Fixed(self.format == Format::Json),
            ),
        );
    }

    /// Adds the output settings every NDJSON stream runs under.
    fn stream_output(&mut self) {
        let fixed = |name: &str, value, unit: Unit, scope: &str, source: &str| {
            (
                Setting {
                    name: name.to_owned(),
                    value: Value::Number(value),
                    unit: unit.as_str().to_owned(),
                    stage: Stage::Output.as_str().to_owned(),
                    scope: scope.to_owned(),
                    source: source.to_owned(),
                    enabled: true,
                },
                Enabled::Fixed(true),
            )
        };
        self.declared
            .entry("--output-timeout-ms".to_owned())
            .or_insert_with(|| {
                fixed(
                    "--output-timeout-ms",
                    OUTPUT_TIMEOUT_MS,
                    Unit::Milliseconds,
                    "Per-write wait; clipped by the remaining operation deadline",
                    "default",
                )
            });
        for (name, value, unit, scope) in [
            (
                "output_record_bytes",
                crate::output::stream::MAX_RECORD_BYTES as u64,
                Unit::Bytes,
                "One prepared NDJSON line, including newline",
            ),
            (
                "terminal_error_timeout_ms",
                OUTPUT_TIMEOUT_MS,
                Unit::Milliseconds,
                "Separate terminal-error cleanup wait; cannot repair a failed write",
            ),
        ] {
            self.declared
                .insert(name.to_owned(), fixed(name, value, unit, scope, "fixed"));
        }
    }
}

/// Collects the selected command's settings for `--resource-diagnostics`.
pub(crate) fn configure<T: Spec>(
    matches: &ArgMatches,
    arguments: &T,
    preset: Option<Preset>,
    output_timeout_ms: Option<u64>,
    format: Format,
) {
    let settings = settings(matches, arguments, preset, output_timeout_ms, format);
    let _ = CONTEXT.set(Context {
        settings,
        stream_index: AtomicBool::new(true),
        runtimes: Mutex::new(Vec::new()),
    });
}

/// The settings `arguments` declare, with their stage enablement.
pub(crate) fn settings<T: Spec>(
    matches: &ArgMatches,
    arguments: &T,
    preset: Option<Preset>,
    output_timeout_ms: Option<u64>,
    format: Format,
) -> Vec<(Setting, Enabled)> {
    let mut definition = Cli::command();
    definition.build();
    let selected = matches.subcommand().and_then(|(name, values)| {
        definition
            .find_subcommand(name)
            .map(|definition| (definition, values))
    });
    let mut settings = Settings {
        root: (&definition, matches),
        selected,
        preset,
        offline: T::OFFLINE,
        format,
        declared: BTreeMap::new(),
    };
    settings.declare(
        "output_timeout_ms",
        output_timeout_ms.setting_value(),
        Unit::Milliseconds,
        Stage::Output,
        Enabled::Fixed(true),
    );
    arguments.resources(&mut settings);
    if format == Format::Ndjson {
        settings.stream_output();
    }
    settings.declared.into_values().collect()
}

/// Reports whether the comparison needs the capture stream index, which
/// enables or disables the [`Enabled::StreamIndex`] stages.
pub(crate) fn stream_index_needed(needed: bool) {
    if let Some(context) = CONTEXT.get() {
        context.stream_index.store(needed, Ordering::Relaxed);
    }
}

/// Constructors remain isolated. Keeping a runtime clone observes admission;
/// it neither holds permits nor keeps callback captures alive.
pub(crate) fn runtime(name: &'static str, capacity: usize) -> Runtime {
    let runtime = Runtime::new(capacity);
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
    runtime
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
