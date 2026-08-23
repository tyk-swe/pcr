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
use crate::filtering::FrameSelector;
use crate::rendering::NdjsonStream;
use crate::system::resolve;
use packetcraftr::BoundaryError;

pub(super) fn run(
    arguments: Args,
    format: output::contract::Format,
    stream: &mut NdjsonStream,
) -> Result<(), BoundaryError> {
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
        return Err(BoundaryError::from_error(
            net::Error::InvalidCaptureTimeout {
                timeout,
                maximum: net::capture::MAX_TIMEOUT,
            },
        ));
    }
    let limits = limits
        .into_limits()
        .validate()
        .map_err(BoundaryError::from_error)?;
    let registry = registry()?;
    let selector =
        FrameSelector::compile_optional(filter.as_deref(), &registry, limits.snap_length)?;
    let interface = resolve(Some(interface), &net::interface::SystemProvider)?
        .expect("required capture interface must resolve to an identity");
    let policy = budgets.into_policy();
    let request = net::capture::Request {
        interface,
        limits,
        filter: capture_filter,
        promiscuous,
    };
    let capture = net::capture::SystemProvider
        .arm_capture(&request)
        .map_err(BoundaryError::from_error)?;

    match format {
        output::contract::Format::Text => {
            rendering::render_text(capture, timeout, limits, &policy, selector.as_ref())
        }
        output::contract::Format::Hex => {
            rendering::render_hex(capture, timeout, limits, &policy, selector.as_ref())
        }
        output::contract::Format::Ndjson => {
            rendering::render_stream(capture, timeout, limits, &policy, selector.as_ref(), stream)
        }
        output::contract::Format::Pcap | output::contract::Format::PcapNg => {
            rendering::render_capture(capture, format, timeout, limits, &policy, selector.as_ref())
        }
        _ => unreachable!("capture format is checked before command dispatch"),
    }
}
