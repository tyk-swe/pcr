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
//! Those spellings are the canonical ones, taken from each protocol's
//! reflective schema. A protocol module may register further spellings — the
//! conventional short names and per-flag paths operators are used to — through
//! [`crate::registry::Builder::bind_filter_field`]; which of those exist
//! depends on the registry a filter is compiled against.
//!
//! Field paths resolve three ways, in this order. Reserved synthetic names
//! (`frame.number`, `frame.time_epoch`, `frame.len`, `frame.cap_len`,
//! `frame.interface_id`, `frame.link_type`, and `tcp.stream` / `udp.stream`)
//! come first, so no protocol can redefine them. Then spellings registered
//! through [`crate::registry::Builder::bind_filter_field`]. Then canonical
//! `<protocol-or-alias>.<field>` paths, which need no registration because
//! they come straight from the protocol's reflective schema — every name
//! listed by `packetcraftr protocols <NAME>` is filterable.
//!
//! A bare protocol name tests whether such a layer is present. A bare field
//! path tests whether the packet exposes a value for it — except for a flag,
//! meaning a single-bit selection or a boolean field, where it reads the flag
//! itself. That is what makes `!tcp.flags.ack` mean "the ACK bit is clear"
//! rather than "the packet has no ACK bit", which would be true of every TCP
//! segment ever captured.
//!
//! Where a protocol repeats, as in a tunnelled stack, an unqualified path
//! matches **any** occurrence; `ipv4#1` and `ipv4#2` select the outer and
//! inner layer explicitly. Equality, ordering, membership, and containment
//! match when any comparable candidate satisfies them. Inequality is the
//! complement of equality over the whole multivalued path: `tcp.port != 80`
//! holds only when neither endpoint is port 80. The same rule applies to list
//! fields and repeated layers. A missing, empty, or wholly uncomparable path
//! does not match either operator.
//!
//! A fixed byte-slice end must be available in full or the path contributes no
//! candidate. Only an omitted end, as in `raw.bytes[4:]`, extends to the actual
//! end of a shorter value.
//!
//! There is deliberately no regular-expression operator, which would mean
//! taking on a regex dependency. `contains` plus byte-slice equality covers
//! the substring and prefix cases it would otherwise serve. A `contains`
//! needle is written as a byte run (`47:45`) or quoted text (`"GE"`); a bare
//! number is refused because it reads as ambiguously decimal or hexadecimal.
//!
//! A comparison whose literal could never match the field it names is a
//! compile error rather than a filter that quietly matches nothing. That
//! covers a mistyped bareword on a numeric field, an address literal on a
//! port, slicing a number, and searching a field that holds no bytes.
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
