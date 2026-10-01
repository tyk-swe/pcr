// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded display filters over dissected packets.
//!
//! ```text
//! ipv4.source in 10.0.0.0/8 && udp.destination_port == 53
//! ipv4#2.destination == 192.168.1.5 || ipv4#last.destination == 192.168.1.5
//! ethernet.source[0:3] == 00:1b:21
//! frame.len > 1500 && !padding
//! tcp.flags & 0x12 == 0x12 && tcp.port in {53, 49152..65535}
//! raw.bytes contains b"\x16\x03\x01" || dns.qname endswith ".example.com."
//! dns.answers[*].type == 1 && dns.answers[-1].ttl > 60
//! len(raw.bytes) > 1400 || count(tcp.options) > 4
//! frame.truncated && frame.protocols == "tls"
//! ```
//!
//! Paths resolve reserved `frame.*`/`tcp.stream`/`udp.stream` names first,
//! registered paths second, and canonical schema paths last. A bare protocol
//! tests presence; a bare flag reads the flag, so `!tcp.flags.ack` means "ACK
//! clear". An unqualified path matches any occurrence in a tunnelled stack
//! (`ipv4#1`/`ipv4#2` select one; `ipv4#last` or `ipv4#-1` the innermost, in the
//! order occurrences are counted), and either-field paths hold when either
//! side matches. A list field takes `[N]` for one element, `[*]` for every
//! element, or `[-1]` for the last, as in `dns.answers[*].type`; a path holds
//! when any selected element satisfies the predicate, and a projection reports
//! `[*]` as a list. `len(path)` is the byte length of a bytes, text, MAC, or
//! address value (per element for a list) and `count(path)` the number of
//! elements in a list; either compares to an unsigned number.
//! `frame.time_nsec`, `frame.direction`, `frame.truncated`, `frame.layer_count`
//! and `frame.protocols` join the reserved frame facts. Byte fields take
//! separated bytes (`c0:00`) or quoted text; an unquoted run of hex digits such as `c000`, or a byte run with a malformed
//! group such as `c0:0`, is an error, not an ASCII needle. Quoted text takes
//! the escapes `\\ \" \r \n \t \0` and `\xNN` up to `\x7f`; `b"..."` holds
//! bytes, where `\xNN` covers `\x00` to `\xff`. `field & MASK` tests the
//! masked bits of an unsigned field, alone for "nonzero" or before a
//! comparison. `A..B` is an inclusive range of numbers or addresses for `==`,
//! `!=`, and `in`. `startswith`, `endswith`, `icontains`, and `iequals` search
//! like `contains`, and the `i` forms fold ASCII case only. There is no regex
//! operator.

mod ast;
mod comparison;
mod error;
mod eval;
mod frames;
mod lexer;
mod limits;
mod literal;
mod model;
mod parser;
mod path;
mod plan;
mod projection;
mod requirements;
pub use projection::Projection;

pub use error::Error;
pub use eval::{Context, DerivedPacket};
pub use frames::{FrameDecoder, FrameSelector};
pub use limits::{
    DEFAULT_MAX_FILTER_BYTES, Limits, MAX_FILTER_NESTING, MAX_FILTER_SET_MEMBERS, MAX_FILTER_TERMS,
};
pub use model::Filter;
pub use requirements::Requirements;
