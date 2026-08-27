// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Declaration of output enums that mirror an upstream enum one variant at a
//! time.

/// Declares an output enum and its `From<Source>` conversion from a single
/// variant list.
///
/// Each entry reads `OutputVariant = SourceVariant`, so the output name is free
/// to differ from the source name. The enum carries the derives every output
/// enum needs (`Clone, Copy, Debug, PartialEq, Eq, Serialize`); doc comments,
/// `#[serde(rename_all = ...)]`, and per-variant attributes pass through as
/// written.
///
/// A `#[non_exhaustive]` source needs a trailing `unmatched <binding> => <expr>`
/// clause, which becomes the catch-all match arm.
///
/// ```ignore
/// mirror_enum! {
///     /// Who sent a chunk.
///     #[serde(rename_all = "snake_case")]
///     pub enum Direction from AnalysisDirection {
///         Client = ClientToServer,
///         Server = ServerToClient,
///     }
/// }
/// ```
macro_rules! mirror_enum {
    (
        $(#[$enum_attribute:meta])*
        $visibility:vis enum $name:ident from $source:path {
            $(
                $(#[$variant_attribute:meta])*
                $variant:ident = $source_variant:ident,
            )*
        }
        $( unmatched $binding:ident => $fallback:expr $(,)? )?
    ) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, ::serde::Serialize)]
        $(#[$enum_attribute])*
        $visibility enum $name {
            $(
                $(#[$variant_attribute])*
                $variant,
            )*
        }

        impl From<$source> for $name {
            fn from(value: $source) -> Self {
                match value {
                    $( <$source>::$source_variant => Self::$variant, )*
                    $( $binding => $fallback, )?
                }
            }
        }
    };
}
