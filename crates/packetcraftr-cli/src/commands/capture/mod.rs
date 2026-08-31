// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Capture CLI command logic.

pub(super) mod arguments;
mod execution;
mod rendering;

use std::time::{Duration, Instant};

use packetcraftr::{analysis::pcap, netio as net, netio::capture::Provider as _, output};

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
    stream: &StreamEncoder,
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
    let limits = limits.into_limits();
    limits.validate().map_err(CliError::classified)?;
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

    let session = || execution::Session {
        capture,
        timeout,
        limits,
        budget,
        selector: selector.as_ref(),
    };
    match format {
        CaptureFormat::Text => rendering::render_text(session()),
        CaptureFormat::Hex => rendering::render_hex(session()),
        CaptureFormat::Ndjson => rendering::render_stream(session(), stream),
        CaptureFormat::Pcap => rendering::render_capture(session(), pcap::Format::Pcap),
        CaptureFormat::PcapNg => rendering::render_capture(session(), pcap::Format::PcapNg),
    }
}
