// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod connect;
mod list;
mod payload;
mod profiles;
mod rendering;

use crate::output::contract::Format;

use crate::output;

use packetcraftr_core::error::{Classified, Kind};

use self::arguments::Args;
use super::execution;
use crate::errors::CliError;
use crate::input::manifest;
use crate::rendering::StreamEncoder;
use crate::system::{Runtime, prepare_workflow};

impl super::Spec for Args {
    const FORMATS: &'static [crate::output::contract::Format] = &[
        crate::output::contract::Format::Text,
        crate::output::contract::Format::Json,
        crate::output::contract::Format::Ndjson,
    ];
    const CANCELLATION: bool = true;

    fn run_time(&self) -> Option<&dyn crate::command_options::Bounded> {
        Some(&self.duration)
    }

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        crate::resources::declare!(settings, self, [
            max_in_flight: Count @ Operation,
            max_targets: Count @ Operation,
            max_ports: Count @ Operation,
            max_probes: Count @ Operation,
            max_undecoded: Count @ ResultRetention,
            max_prepared_bytes: Bytes @ Preparation,
        ]);
        self.timeout.resources(settings);
        self.duration.resources(settings);
        self.limits.resources(settings);
        self.policy.resources(settings);
    }

    fn run(
        self,
        format: Format,
        stream: &crate::rendering::StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        run(self, format, stream).map(|()| super::CommandExit::SUCCESS)
    }
}

pub(super) fn run(arguments: Args, format: Format, stream: &StreamEncoder) -> Result<(), CliError> {
    if arguments.connect && !matches!(arguments.transport, arguments::Transport::Tcp) {
        return Err(CliError::new(
            packetcraftr_core::error::Kind::Usage,
            "--connect requires TCP transport",
        ));
    }
    if arguments.connect && !arguments.route.supports_kernel_tcp() {
        return Err(CliError::classified(
            packetcraftr::scan::Error::UnsupportedTcpRoute,
        ));
    }
    let Args {
        connect,
        max_in_flight,
        max_prepared_bytes,
        list,
        targets,
        targets_file,
        exclude_file,
        max_manifest_bytes,
        max_manifest_lines,
        exclusions,
        max_targets,
        transport,
        udp_payload_hex,
        udp_payload_file,
        udp_profiles,
        family,
        ports,
        attempts,
        timeout,
        rate,
        max_ports,
        max_probes,
        duration,
        max_undecoded,
        route,
        limits,
        policy,
    } = arguments;
    let stdin_consumers = targets_file
        .iter()
        .chain(exclude_file.iter())
        .filter(|path| manifest::is_stdin(path))
        .count()
        + usize::from(udp_payload_file.as_deref().is_some_and(manifest::is_stdin))
        + usize::from(udp_profiles.as_deref().is_some_and(manifest::is_stdin));
    if stdin_consumers > 1 {
        return Err(CliError::new(
            Kind::Usage,
            "stdin (`-`) can supply at most one of --targets-file, --exclude-file, --udp-payload-file, or --udp-profiles",
        ));
    }
    let selection = ingest_targets(
        &targets,
        &targets_file,
        &exclusions,
        &exclude_file,
        max_manifest_bytes,
        max_manifest_lines,
    )?;
    selection.targets.validate().map_err(CliError::classified)?;
    let targets = selection.targets;
    if list {
        return list::run(
            targets,
            list::Options {
                origins: selection.origins,
                family,
                max_targets,
                max_duration: duration.max_duration(),
                policy,
            },
            format,
            stream,
        );
    }
    let udp_payload = payload::read(
        transport,
        udp_payload_hex.as_deref(),
        udp_payload_file.as_deref(),
    )?;
    let udp_profiles = profiles::load(udp_profiles.as_deref(), transport)?;
    let queue_limits = limits.into_limits();
    let scan_limits = packetcraftr::scan::Limits {
        max_prepared_bytes,
        max_targets,
        max_ports,
        max_probes,
        max_duration: duration.max_duration(),
        max_evidence_frames: queue_limits.max_frames,
        max_evidence_bytes: queue_limits.max_bytes,
        max_undecoded,
    };
    scan_limits.validate().map_err(CliError::classified)?;
    let ports = packetcraftr::scan::select_ports(ports.into_iter().map(|spec| spec.0), max_ports)
        .map_err(CliError::classified)?;
    let request = packetcraftr::scan::Request {
        max_in_flight,
        targets,
        target_sources: selection.origins.iter().map(ToString::to_string).collect(),
        transport: transport.into(),
        udp_payload,
        udp_profiles,
        address_family: family.into(),
        ports,
        attempts,
        timeout: timeout.timeout(),
        probes_per_second: rate,
        limits: scan_limits,
        route: packetcraftr::route::Options::default(),
        collection: packetcraftr::exchange::Collection::default(),
    };
    if connect {
        return connect::run(&request, policy, format, stream);
    }
    let workflow = prepare_workflow(&route, policy.into_policy(), request.timeout, queue_limits)?;
    let client = workflow.client(Runtime::Workflow);
    let request = packetcraftr::scan::Request {
        route: workflow.route,
        collection: workflow.collection,
        ..request
    };
    execution::run_workflow(
        format,
        stream,
        crate::cancellation::signal(),
        execution::Hooks {
            command: output::contract::Command::Scan,
            run: Box::new(|| {
                let collector = packetcraftr::scan::Collector::default();
                let report = client
                    .scan(request.clone(), collector.clone())
                    .map_err(rendering::scan_error)?;
                collector.finish(report).map_err(rendering::scan_error)
            }),
            run_with_events: Box::new(|emit| {
                client
                    .scan(request.clone(), emit)
                    .map_err(rendering::scan_error)
            }),
            on_event: rendering::emit_event,
            into_result: Box::new(|report| {
                output::envelope::Published::<output::scan::Report>::try_from(report)
                    .map_err(CliError::classified)
            }),
            render_text: Box::new(|report, _| {
                rendering::render_text(
                    output::envelope::Published::try_from(report).map_err(CliError::classified)?,
                )
            }),
            complete: rendering::emit_complete,
        },
    )
}

pub(super) struct Ingested {
    pub(crate) targets: packetcraftr::target::Selection,
    pub(crate) origins: Vec<manifest::Declaration>,
}

fn ingest_targets(
    positional: &[String],
    targets_file: &[std::path::PathBuf],
    exclusions: &[packetcraftr::target::Network],
    exclude_file: &[std::path::PathBuf],
    max_manifest_bytes: Option<usize>,
    max_manifest_lines: Option<usize>,
) -> Result<Ingested, CliError> {
    let bounds = manifest::ManifestBounds::new(
        max_manifest_bytes.unwrap_or(manifest::MAX_MANIFEST_BYTES),
        max_manifest_lines.unwrap_or(manifest::MAX_MANIFEST_LINES),
    )?;
    let mut budget = bounds.budget();
    let mut origins = positional
        .iter()
        .enumerate()
        .map(|(position, target)| manifest::Declaration {
            token: target.clone(),
            source: manifest::DeclarationSource::Argument {
                position: position + 1,
            },
            line: None,
        })
        .collect::<Vec<_>>();
    origins.extend(manifest::read_with_budget(
        &manifest_sources(targets_file),
        &mut budget,
    )?);
    let include = parse_declarations(&origins)?;
    if include.is_empty() {
        return Err(CliError::new(
            Kind::Usage,
            "at least one target is required: pass TARGET or --targets-file",
        ));
    }
    let mut exclude = exclusions.to_vec();
    exclude.extend(parse_declarations::<packetcraftr::target::Network>(
        &manifest::read_with_budget(&manifest_sources(exclude_file), &mut budget)?,
    )?);
    Ok(Ingested {
        targets: packetcraftr::target::Selection { include, exclude },
        origins,
    })
}

fn manifest_sources(paths: &[std::path::PathBuf]) -> Vec<manifest::ManifestSource> {
    paths
        .iter()
        .map(|path| manifest::ManifestSource::open(path))
        .collect()
}

fn parse_declarations<T>(declarations: &[manifest::Declaration]) -> Result<Vec<T>, CliError>
where
    T: std::str::FromStr,
    T::Err: Classified,
{
    declarations
        .iter()
        .map(|declaration| {
            declaration
                .token
                .parse()
                .map_err(|source| declaration_error(source, declaration))
        })
        .collect()
}

fn declaration_error(source: impl Classified, declaration: &manifest::Declaration) -> CliError {
    CliError::from_classification(
        source.classification(),
        format!("invalid declaration at {declaration}: {source}"),
        crate::errors::source_causes(&source),
    )
    .with_context(source.context())
}
