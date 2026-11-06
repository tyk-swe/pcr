// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The CLI owns every published field, so a library serde change cannot
//! silently change a frozen output family.

macro_rules! published_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident from $source:ty {
            $($(#[$variant_meta:meta])* $variant:ident => $text:literal),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
        $vis enum $name {
            $($(#[$variant_meta])* #[serde(rename = $text)] $variant,)+
        }

        impl $name {
            #[must_use]
            $vis const fn as_str(self) -> &'static str {
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
pub(crate) use published_enum;

pub mod capture;
pub mod contract;
pub mod envelope;
pub mod frame;
pub mod hex;
pub mod network;
pub mod projection;
pub mod resources;
pub mod scan_failure;
pub mod stream;
