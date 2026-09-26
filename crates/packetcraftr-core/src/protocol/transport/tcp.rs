// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! TCP segment model and codec, with standard options typed over the option
//! area.
//!
//! End-of-list and no-op markers, MSS, window scale, SACK-permitted/SACK, and
//! timestamps decode into variants; every other kind and every nonstandard
//! length stays byte-exact as [`TcpOption::Raw`]. A tail that cannot be a TLV
//! at all — a missing length byte, a length below two, or a length that runs
//! past the option area — becomes [`TcpOption::Trailing`] so decode never
//! loses wire bytes and re-encoding reproduces them exactly. EOL terminates
//! parsing; any remaining padding is preserved as `Trailing` too.

mod codec;
mod model;
mod reflection;

pub(crate) use codec::TcpCodec;
pub use model::{SackBlock, Tcp, TcpOption};
