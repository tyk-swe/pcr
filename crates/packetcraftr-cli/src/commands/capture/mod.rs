// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Capture CLI command logic.

pub(super) mod arguments;
mod conversion;
mod execution;
mod rendering;

use std::sync::Arc;
use std::time::Duration;

use packetcraftr::{netio as net, netio::capture::Provider as _, output};

use self::arguments::Args;
use super::registry;
use crate::errors::CliError;
use crate::filtering::{self, Capabilities, FrameSelector};
use crate::rendering::NdjsonStream;
use crate::system::{client, prepare_route};

use conversion::validate_window;
use execution::Budget;

pub(super) fn run(
    arguments: Args,
    format: output::contract::Format,
    stream: &mut NdjsonStream,
) -> Result<(), CliError> {
    let Args {
        route,
        timeout_ms,
        capture_filter,
        filter,
        limits,
        policy,
    } = arguments;
    let timeout = Duration::from_millis(timeout_ms);
    validate_window(timeout)?;
    let limits = limits
        .into_limits()
        .validate()
        .map_err(CliError::classified)?;
    let registry = registry()?;
    let selector = prepare_selector(filter.as_deref(), &registry, limits.snap_length)?;
    let request = prepare_route(route, policy.into_policy(), &registry)?;
    let budget = Budget::from(&request.policy);
    let client = client(Arc::clone(&registry), request.policy);
    let route = client
        .plan(&request.packet, request.destination, &request.options)
        .map_err(CliError::classified)?;
    let arm_capture = || match capture_filter.as_deref() {
        Some(filter) => {
            net::capture::SystemProvider.arm_capture_with_filter(&route, limits, filter)
        }
        None => net::capture::SystemProvider.arm_capture(&route, limits),
    };

    match format {
        output::contract::Format::Text => rendering::render_text(
            arm_capture().map_err(CliError::classified)?,
            timeout,
            limits,
            budget,
            selector.as_ref(),
        ),
        output::contract::Format::Hex => rendering::render_hex(
            arm_capture().map_err(CliError::classified)?,
            timeout,
            limits,
            budget,
            selector.as_ref(),
        ),
        output::contract::Format::Ndjson => rendering::render_stream(
            arm_capture().map_err(CliError::classified)?,
            timeout,
            limits,
            budget,
            selector.as_ref(),
            stream,
        ),
        output::contract::Format::Pcap | output::contract::Format::PcapNg => {
            rendering::render_capture(
                arm_capture,
                format,
                route.decision.link_type,
                timeout,
                limits,
                budget,
                selector.as_ref(),
            )
        }
        _ => unreachable!("capture format is checked before command dispatch"),
    }
}

fn prepare_selector(
    source: Option<&str>,
    registry: &Arc<packetcraftr::core::registry::Registry>,
    max_frame_bytes: usize,
) -> Result<Option<FrameSelector>, CliError> {
    source
        .map(|source| {
            let filter = filtering::compile(source, registry, Capabilities::frames_only())?;
            Ok(FrameSelector::new(
                Arc::clone(registry),
                filter,
                max_frame_bytes,
            ))
        })
        .transpose()
}
