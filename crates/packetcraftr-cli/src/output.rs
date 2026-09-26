// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! CLI machine output: hex, timestamps, reports, and versioned envelopes. The
//! stream encoder owns ordering/termination; each NDJSON envelope names its
//! `event`.
//!
//! The CLI owns every published field (ADR 0003). An output type embeds a
//! library type only when that type is itself a versioned contract: the
//! `packetcraftr.packet` document and its field values. Everything else is a
//! CLI-owned type with the same JSON shape, built with `From`/`TryFrom`, so a
//! serde change in a library cannot silently change a frozen output family.

/// Declares a CLI-owned unit enum that mirrors a library enum variant for
/// variant. Each published name is spelled here, so the serialized value, the
/// text rendering (`as_str`/`Display`), and the published vocabulary cannot
/// drift apart, and a library rename cannot reach the output.
macro_rules! published_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident from $source:ty {
            $($(#[$variant_meta:meta])* $variant:ident => $text:literal),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
        pub enum $name {
            $($(#[$variant_meta])* #[serde(rename = $text)] $variant,)+
        }

        impl $name {
            /// The published name, for text output that must agree with JSON.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $text,)+
                }
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl From<$source> for $name {
            fn from(value: $source) -> Self {
                type Source = $source;
                match value {
                    $(Source::$variant => Self::$variant,)+
                }
            }
        }
    };
}

pub mod analysis;
pub mod build;
pub mod capture;
pub mod contract;
pub mod diagnostic;
pub mod dissect;
pub mod dns;
pub mod dns_read;
pub mod envelope;
pub mod exchange;
pub mod expert;
pub mod export;
pub mod follow;
pub mod fragment;
pub mod frame;
pub mod fuzz;
pub mod hex;
pub mod http;
pub mod interfaces;
pub mod merge;
pub mod network;
pub mod plan;
pub mod probe;
pub mod projection;
pub mod protocols;
pub mod provenance;
pub mod read;
pub mod reassembly;
pub mod replay;
pub mod resources;
pub mod rewrite;
pub mod routes;
pub mod scan;
pub mod send;
pub mod stats;
pub mod stream;
pub mod tls;
pub mod traceroute;
pub mod verify_forwarding;
