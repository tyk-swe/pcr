// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod files;
mod rendering;
mod writer;

use self::arguments::Args;
use crate::{
    errors::CliError,
    filtering::FrameSelector,
    rendering::StreamEncoder,
    system::{InterfaceSelector, resolve},
};
use packetcraftr_cli::output::{capture::Retention, contract::Format};
use packetcraftr_core::{analysis::pcap, error::Kind};
use packetcraftr_netio as net;
use std::{
    collections::HashSet,
    time::{Duration, Instant},
};

pub(super) fn run(args: Args, format: Format, stream: &StreamEncoder) -> Result<(), CliError> {
    let timeout = Duration::from_millis(args.timeout_ms);
    if timeout > net::capture::MAX_TIMEOUT || Instant::now().checked_add(timeout).is_none() {
        return Err(CliError::classified(net::Error::InvalidCaptureTimeout {
            timeout,
            maximum: net::capture::MAX_TIMEOUT,
        }));
    }
    if args.interface.len() > 256 {
        return Err(CliError::new(
            Kind::Cli,
            "capture accepts at most 256 interface selectors before deduplication",
        ));
    }
    if args.write.is_some() {
        if !matches!(format, Format::Text | Format::Json | Format::Ndjson) {
            return Err(CliError::new(
                Kind::Cli,
                "--write requires text, JSON, or NDJSON reporting",
            ));
        }
    } else {
        args.compression.validate(format)?;
        if args.rotate_bytes.is_some()
            || args.rotate_interval_ms.is_some()
            || args.rotate_files != 1
            || args.retention != Retention::Stop
        {
            return Err(CliError::new(
                Kind::Cli,
                "capture rotation requires --write",
            ));
        }
        if format == Format::Json {
            return Err(CliError::new(
                Kind::Cli,
                "JSON capture summaries require --write to retain packet data",
            ));
        }
    }
    let limits = args.limits.into_limits();
    limits.validate().map_err(CliError::classified)?;
    let registry = packetcraftr_core::protocol::builtin::registry();
    let selector =
        FrameSelector::compile_optional(args.filter.as_deref(), &registry, limits.snap_length)?;
    let policy = args.budgets.into_policy();
    let budget = packetcraftr::policy::CaptureBudget::new(&policy);
    let files = args
        .write
        .map(|path| {
            files::Files::new(
                files::Options {
                    path,
                    compression: args.compression,
                    rotate_bytes: args.rotate_bytes,
                    rotate_after: args.rotate_interval_ms.map(Duration::from_millis),
                    max_files: args.rotate_files,
                    retention: args.retention,
                },
                pcap::Limits {
                    max_frames: budget.max_frames(),
                    max_bytes: budget.max_bytes(),
                },
            )
        })
        .transpose()
        .map_err(CliError::classified)?;
    let mut seen = HashSet::new();
    let mut interfaces = Vec::new();
    for source in args.interface {
        let interface = resolve(
            InterfaceSelector::parse(&source)?,
            &net::interface::SystemProvider,
        )?;
        if seen.insert(interface.index) {
            interfaces.push(interface);
        }
    }
    if format == Format::Pcap && interfaces.len() != 1 {
        return Err(CliError::new(
            Kind::Cli,
            "multiple interfaces require PCAPNG capture output",
        ));
    }
    let request = net::capture::group::Request {
        interfaces,
        limits,
        filter: args.capture_filter,
        promiscuous: args.promiscuous,
    };
    rendering::run(
        &net::capture::SystemProvider,
        &request,
        packetcraftr::capture::Options {
            window: timeout,
            budget,
            cancellation: Some(crate::cancellation::signal().clone()),
        },
        rendering::Rendering {
            format,
            compression: args.compression,
            selector,
            files,
            stream,
        },
    )
}
