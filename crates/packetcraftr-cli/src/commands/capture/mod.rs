// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Capture CLI command logic.

pub(super) mod arguments;
mod execution;
mod rendering;

use std::time::{Duration, Instant};

use packetcraftr::{netio as net, netio::capture::Provider as _, output};

use self::arguments::Args;
use super::registry;
use crate::errors::CliError;
use crate::filtering::FrameSelector;
use crate::rendering::StreamEncoder;
use crate::system::{InterfaceSelector, resolve};

use packetcraftr::policy::CaptureBudget;

use super::format::CaptureFormat;

pub(super) fn run(
    arguments: Args,
    format: output::contract::Format,
    stream: &mut StreamEncoder,
) -> Result<(), CliError> {
    let format = CaptureFormat::narrow(output::contract::Command::Capture, format)?;
    let Args {
        interface,
        promiscuous,
        timeout_ms,
        capture_filter,
        filter,
        limits,
        budgets,
    } = arguments;
    let timeout = Duration::from_millis(timeout_ms);
    if timeout > net::capture::MAX_TIMEOUT || Instant::now().checked_add(timeout).is_none() {
        return Err(CliError::classified(net::Error::InvalidCaptureTimeout {
            timeout,
            maximum: net::capture::MAX_TIMEOUT,
        }));
    }
    let limits = limits
        .into_limits()
        .validate()
        .map_err(CliError::classified)?;
    let registry = registry()?;
    let selector =
        FrameSelector::compile_optional(filter.as_deref(), &registry, limits.snap_length)?;
    let interface = resolve(
        InterfaceSelector::parse(&interface)?,
        &net::interface::SystemProvider,
    )?;
    let policy = budgets.into_policy();
    let budget = CaptureBudget::new(&policy);
    let request = net::capture::Request {
        interface,
        limits,
        filter: capture_filter,
        promiscuous,
    };
    let capture = net::capture::SystemProvider
        .arm_capture(&request)
        .map_err(CliError::classified)?;

    match format {
        CaptureFormat::Text => {
            rendering::render_text(capture, timeout, limits, budget, selector.as_ref())
        }
        CaptureFormat::Hex => {
            rendering::render_hex(capture, timeout, limits, budget, selector.as_ref())
        }
        CaptureFormat::Ndjson => {
            rendering::render_stream(capture, timeout, limits, budget, selector.as_ref(), stream)
        }
        CaptureFormat::Pcap | CaptureFormat::PcapNg => rendering::render_capture(
            capture,
            format.format(),
            timeout,
            limits,
            budget,
            selector.as_ref(),
        ),
    }
}
