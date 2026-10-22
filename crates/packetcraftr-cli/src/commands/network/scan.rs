// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(in crate::commands) mod arguments;
mod connect;
mod inputs;
mod list;
mod preparation;
mod raw;
mod rendering;
mod selection;
mod streaming;
mod traceroute;

use packetcraftr::scan::followup;
use packetcraftr_core::error::Kind;

use crate::errors::CliError;

use self::arguments::Args;
use self::preparation::Planned;

impl crate::commands::Spec for Args {
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
            traceroute_max_hops: Count @ Operation if self.traceroute,
            traceroute_max_probes: Count @ Operation if self.traceroute,
        ]);
        self.timeout.resources(settings);
        self.duration.resources(settings);
        self.limits.resources(settings);
        self.policy.resources(settings);
    }

    fn run(
        self,
        invocation: &crate::invocation::Invocation,
    ) -> Result<crate::commands::CommandExit, CliError> {
        run(invocation, self).map(|()| crate::commands::CommandExit::SUCCESS)
    }
}

pub(super) fn run(
    invocation: &crate::invocation::Invocation,
    arguments: Args,
) -> Result<(), CliError> {
    let format = invocation.format;
    let stream = &invocation.output;
    match preparation::prepare(arguments)? {
        Planned::List(request) => list::run(invocation, request, format, stream),
        Planned::Connect(request) => connect::run(invocation, request, format, stream),
        Planned::Raw(request) => raw::run(invocation, request, format, stream),
    }
}

fn validated_reverse_dns(
    reverse: followup::ReverseDns,
    scan: &packetcraftr::scan::Request,
) -> Result<followup::ReverseDns, CliError> {
    reverse.validate(scan).map_err(followup_error)?;
    Ok(reverse)
}

/// A follow-up stage's failure, classified as the failing stage alone would
/// be; a scan failure keeps the partial evidence its pipeline retained.
pub(super) fn followup_error(error: followup::Error) -> CliError {
    match error {
        followup::Error::Scan(error) => scan_error(error),
        followup::Error::StatsOverflow(error) => CliError::caused(Kind::Internal, &error),
        error => CliError::classified(error),
    }
}

fn scan_error(error: packetcraftr::scan::Error) -> CliError {
    use packetcraftr_core::error::Classified;
    let mut cli =
        CliError::from_classification(error.classification(), error.to_string(), error.causes())
            .with_context(error.context());
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    while let Some(error) = source {
        if let Some(pipeline) = error.downcast_ref::<packetcraftr::scan::PipelineFailure>() {
            match crate::output::scan::Failure::try_from(pipeline) {
                Ok(partial) => cli = cli.with_scan(partial),
                Err(error) => cli
                    .causes
                    .push(format!("could not render pending scan evidence: {error}")),
            }
            break;
        }
        source = error.source();
    }
    cli
}

/// Each host's PTR lookup, by position; empty when no lookup was requested.
pub(super) fn reverse_dns_hosts(
    lookups: Option<followup::ReverseLookups>,
) -> Vec<Option<crate::output::scan::host::ReverseDns>> {
    lookups
        .map(|lookups| {
            lookups
                .lookups
                .into_iter()
                .map(|lookup| lookup.map(Into::into))
                .collect()
        })
        .unwrap_or_default()
}
