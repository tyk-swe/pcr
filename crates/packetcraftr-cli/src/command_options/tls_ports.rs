// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::{ArgAction, Args};

/// The `--tls-port` remap, shared so `read`, `dissect`, `tls`, `stats`, and
/// `expert` bind the same ports from the same flag.
#[derive(Clone, Debug, Default, Args)]
pub(crate) struct TlsPortArgs {
    /// Dissect this TCP port as TLS in the per-frame layer, in addition to
    /// the well-known ports; repeatable.
    ///
    /// The per-frame layer is what `dissect`, `read --dissect`, and
    /// `read --filter` decode, and what `stats` and `expert` filter and
    /// count. `tls` assembles sessions from every TCP stream whatever ports
    /// are bound, so this flag never changes which sessions it assembles:
    /// there it only changes the port list printed when no session was
    /// assembled.
    #[arg(
        long = "tls-port",
        value_name = "PORT",
        action = ArgAction::Append,
        value_parser = clap::value_parser!(u16).range(1..)
    )]
    pub(crate) ports: Vec<u16>,
}
