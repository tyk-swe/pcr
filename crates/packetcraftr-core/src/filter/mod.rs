// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded display filters over dissected packets.
//!
//! A filter names packet fields and combines tests over them:
//!
//! ```text
//! ipv4.source in 10.0.0.0/8 && udp.destination_port == 53
//! ipv4#2.destination == 192.168.1.5
//! ethernet.source[0:3] == 00:1b:21
//! frame.len > 1500 && !padding
//! ```
//!
//! Canonical `<protocol-or-alias>.<field>` paths come from each protocol's
//! reflective schema. A registry can add conventional short names, paths that
//! read either of two fields, and per-flag paths through
//! [`crate::registry::Builder::bind_filter_field`]. Their availability depends
//! on the registry used to compile the filter.
//!
//! Paths resolve in this order: reserved synthetic names
//! (`frame.number`, `frame.time_epoch`, `frame.len`, `frame.cap_len`,
//! `frame.interface_id`, `frame.link_type`, and `tcp.stream` / `udp.stream`)
//! first, registered paths second, and canonical schema paths last. Reserved
//! names cannot be redefined, and every field listed by
//! `packetcraftr protocols <NAME>` is filterable without registration.
//!
//! A bare protocol name tests whether such a layer is present. A bare field
//! path tests whether the packet exposes a value. A single-bit or boolean flag
//! instead reads the flag itself, so `!tcp.flags.ack` means "the ACK bit is
//! clear", not "the packet has no ACK field".
//!
//! In a tunnelled stack, an unqualified path matches **any** occurrence;
//! `ipv4#1` and `ipv4#2` select the outer and inner layers. The same rule
//! applies to either-field paths: `tcp.port != 80` holds when *either* endpoint
//! is not port 80. Use `tcp.srcport` or `tcp.dstport` when direction matters.
//!
//! Filters have no regular-expression operator. Use `contains` for substrings
//! and byte-slice equality for prefixes. A `contains` needle must be a byte run
//! (`47:45`) or quoted text (`"GE"`), not an ambiguous bare number.
//!
//! Type-incompatible literals, slices, and `contains` operations are compile
//! errors rather than filters that quietly match nothing.
//!
//! Compilation is bounded in source length, parenthesis nesting, term count,
//! and set size. Both the parser and the evaluator use explicit stacks rather
//! than recursion, so filter text cannot drive stack depth.

mod ast;
mod comparison;
mod error;
mod eval;
mod lexer;
mod literal;
mod model;
mod parser;
mod path;

pub use error::FilterError as Error;
pub use eval::Context;
pub use model::Filter;
pub use parser::{
    DEFAULT_MAX_FILTER_BYTES, FilterOptions as Options, MAX_FILTER_NESTING, MAX_FILTER_SET_MEMBERS,
    MAX_FILTER_TERMS, Requirements,
};
