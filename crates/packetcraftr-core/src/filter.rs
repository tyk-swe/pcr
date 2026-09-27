// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded display filters over dissected packets.
//!
//! ```text
//! ipv4.source in 10.0.0.0/8 && udp.destination_port == 53
//! ipv4#2.destination == 192.168.1.5
//! ethernet.source[0:3] == 00:1b:21
//! frame.len > 1500 && !padding
//! ```
//!
//! Paths resolve reserved `frame.*`/`tcp.stream`/`udp.stream` names first,
//! registered paths second, and canonical schema paths last. A bare protocol
//! tests presence; a bare flag reads the flag, so `!tcp.flags.ack` means "ACK
//! clear". An unqualified path matches any occurrence in a tunnelled stack
//! (`ipv4#1`/`ipv4#2` select one), and either-field paths hold when either
//! side matches. There is no regex operator.

mod ast;
mod comparison;
mod error;
mod eval;
mod frames;
mod lexer;
mod literal;
mod model;
mod parser;
mod path;
mod plan;
mod projection;
pub use projection::Projection;

pub use error::Error;
pub use eval::{Context, DerivedPacket};
pub use frames::{FrameDecoder, FrameSelector};
pub use model::Filter;
pub use parser::{
    DEFAULT_MAX_FILTER_BYTES, Limits, MAX_FILTER_NESTING, MAX_FILTER_SET_MEMBERS, MAX_FILTER_TERMS,
    Requirements,
};
