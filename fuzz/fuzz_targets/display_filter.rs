// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Input: UTF-8 filter text, then optionally a NUL byte and a `packet_decode`
//! input (link-type selector byte and frame) to evaluate the filter on. The
//! text also compiles as comma-separated projection columns.

#![no_main]

use std::time::{Duration, SystemTime};

use libfuzzer_sys::fuzz_target;
use packetcraftr_core::decode::{Dissector, Options};
use packetcraftr_core::filter::{Context, Filter, Limits, Projection};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_fuzz::registry;

const MAX_PROJECTION_BYTES: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    let (source, packet) = data
        .iter()
        .position(|&byte| byte == 0)
        .map_or((data, &[][..]), |nul| (&data[..nul], &data[nul + 1..]));
    let Ok(source) = std::str::from_utf8(source) else {
        return;
    };
    let registry = registry();
    let filter = Filter::compile(source, &registry, Limits::default());
    let projection = Projection::compile(source.split(','), &registry);
    let Some((selector, frame)) = packet.split_first() else {
        return;
    };
    let roots = LinkType::BUILTIN_ROOTS;
    let link_type = roots[usize::from(*selector) % roots.len()].0;
    let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let Ok(frame) = Frame::new(Some(timestamp), link_type, frame.to_vec()) else {
        return;
    };
    let Ok(decoded) = Dissector::new(registry).decode(frame, Options::default()) else {
        return;
    };
    let context = Context {
        decoded: &decoded,
        derived: &[],
        number: 1,
        tcp_stream: Some(0),
        udp_stream: Some(0),
    };
    if let Ok(filter) = filter {
        let _ = filter.matches(&context);
    }
    if let Ok(projection) = projection {
        let _ = projection.values(&context, MAX_PROJECTION_BYTES);
    }
});
