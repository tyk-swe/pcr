// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use clap::{ArgMatches, ValueEnum, parser::ValueSource};

use crate::output::{
    contract::Format,
    resources::{Setting, Value},
};
use crate::rendering::OUTPUT_TIMEOUT_MS;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum Preset {
    CiV1,
    WorkstationV1,
}

impl Preset {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::CiV1 => "ci-v1",
            Self::WorkstationV1 => "workstation-v1",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Unit {
    Count,
    Bytes,
    Milliseconds,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Enabled {
    Fixed(bool),
    /// Runs only when the comparison needs the capture stream index.
    StreamIndex,
}

impl From<bool> for Enabled {
    fn from(enabled: bool) -> Self {
        Self::Fixed(enabled)
    }
}

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

numeric_setting_values!(u8, u32, u64, usize);

impl<T: SettingValue> SettingValue for Option<T> {
    fn setting_value(&self) -> Option<Value> {
        self.as_ref().and_then(SettingValue::setting_value)
    }
}

pub(crate) fn policy_value<T: ValueEnum>(value: &T) -> Option<Value> {
    value
        .to_possible_value()
        .map(|value| Value::Policy(value.get_name().to_owned()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PresetDefaults {
    pub(crate) ci_v1: &'static str,
    pub(crate) workstation_v1: &'static str,
}

impl PresetDefaults {
    const fn value(self, preset: Preset) -> &'static str {
        match preset {
            Preset::CiV1 => self.ci_v1,
            Preset::WorkstationV1 => self.workstation_v1,
        }
    }
}

pub(crate) struct Field {
    pub(crate) id: &'static str,
    pub(crate) value: Option<Value>,
    pub(crate) unit: Unit,
    pub(crate) stage: Stage,
    pub(crate) enabled: Enabled,
    pub(crate) preset: Option<PresetDefaults>,
}

/// Declares typed argument fields as resource settings:
/// `declare!(settings, group, [field: Unit @ Stage, field: Unit @ Stage preset(ci, ws) if enabled])`.
macro_rules! declare {
    (@enabled) => { $crate::resources::Enabled::Fixed(true) };
    (@enabled $enabled:expr) => { $crate::resources::Enabled::from($enabled) };
    (@preset) => { None };
    (@preset $ci:literal, $workstation:literal) => {
        Some($crate::resources::PresetDefaults {
            ci_v1: stringify!($ci),
            workstation_v1: stringify!($workstation),
        })
    };
    (
        $settings:expr, $group:expr,
        [$(
            $field:ident: $unit:ident @ $stage:ident
            $(preset($ci:literal, $workstation:literal))?
            $(if $enabled:expr)?
        ),* $(,)?]
    ) => {{
        $(
            $settings.declare($crate::resources::Field {
                id: stringify!($field),
                value: $crate::resources::SettingValue::setting_value(&$group.$field),
                unit: $crate::resources::Unit::$unit,
                stage: $crate::resources::Stage::$stage,
                enabled: $crate::resources::declare!(@enabled $($enabled)?),
                preset: $crate::resources::declare!(@preset $($ci, $workstation)?),
            });
        )*
    }};
}
pub(crate) use declare;

enum Target<'a> {
    Diagnostics(Diagnostics<'a>),
    Presets {
        preset: Preset,
        defaults: BTreeMap<&'static str, &'static str>,
    },
}

struct Diagnostics<'a> {
    root: (&'a clap::Command, &'a ArgMatches),
    selected: Option<(&'a clap::Command, &'a ArgMatches)>,
    preset: Option<Preset>,
    offline: bool,
    format: Format,
    declared: BTreeMap<String, (Setting, Enabled)>,
}

pub(crate) struct Settings<'a> {
    target: Target<'a>,
}

impl Settings<'_> {
    pub(crate) fn preset_defaults(
        preset: Preset,
        declare: impl FnOnce(&mut Settings<'_>),
    ) -> BTreeMap<&'static str, &'static str> {
        let mut settings = Settings {
            target: Target::Presets {
                preset,
                defaults: BTreeMap::new(),
            },
        };
        declare(&mut settings);
        match settings.target {
            Target::Presets { defaults, .. } => defaults,
            Target::Diagnostics(_) => BTreeMap::new(),
        }
    }

    pub(crate) fn declare(&mut self, field: Field) {
        match &mut self.target {
            Target::Presets { preset, defaults } => {
                if let Some(values) = field.preset {
                    defaults.insert(field.id, values.value(*preset));
                }
            }
            Target::Diagnostics(report) => report.declare(field),
        }
    }

    pub(crate) fn retained_result_items(&mut self, max_frames: u64) {
        if let Target::Diagnostics(report) = &mut self.target {
            report.retained_result_items(max_frames);
        }
    }
}

impl Diagnostics<'_> {
    fn declare(&mut self, field: Field) {
        let Field {
            id,
            value,
            unit,
            stage,
            enabled,
            preset: defaults,
        } = field;
        let Some(value) = value else {
            return;
        };
        // `declare!` names a typed field, whose name clap uses as its id, so
        // every declared id is an argument; the test over every command's
        // declarations checks it.
        let Some((arg, matches)) = self
            .selected
            .into_iter()
            .chain(std::iter::once(self.root))
            .find_map(|(definition, matches)| {
                definition
                    .get_arguments()
                    .find(|arg| arg.get_id() == id)
                    .map(|arg| (arg, matches))
            })
        else {
            debug_assert!(false, "resource setting {id} names no argument");
            return;
        };
        let stage = if stage == Stage::PhysicalInput && !self.offline {
            Stage::Operation
        } else {
            stage
        };
        let name = format!("--{}", arg.get_long().unwrap_or(id));
        let source = if matches.value_source(id) == Some(ValueSource::CommandLine) {
            "override".to_owned()
        } else if let Some(preset) = self.preset.filter(|_| defaults.is_some()) {
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

    fn retained_result_items(&mut self, max_frames: u64) {
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

struct Root {
    output_timeout_ms: Option<u64>,
}

pub(crate) fn collect_settings(
    definition: &clap::Command,
    matches: &ArgMatches,
    offline: bool,
    preset: Option<Preset>,
    output_timeout_ms: Option<u64>,
    format: Format,
    declare: impl FnOnce(&mut Settings<'_>),
) -> Vec<(Setting, Enabled)> {
    let selected = matches.subcommand().and_then(|(name, values)| {
        definition
            .find_subcommand(name)
            .map(|definition| (definition, values))
    });
    let mut settings = Settings {
        target: Target::Diagnostics(Diagnostics {
            root: (definition, matches),
            selected,
            preset,
            offline,
            format,
            declared: BTreeMap::new(),
        }),
    };
    declare!(settings, Root { output_timeout_ms }, [output_timeout_ms: Milliseconds @ Output]);
    declare(&mut settings);
    let Target::Diagnostics(mut report) = settings.target else {
        return Vec::new();
    };
    if format == Format::Ndjson {
        report.stream_output();
    }
    report.declared.into_values().collect()
}
