// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Layer2,
    Layer3,
    #[serde(rename = "layer2_and3")]
    Layer2AndLayer3,
}

impl Capability {
    /// Unresolved [`Mode::Auto`] is never supported.
    pub const fn supports(self, mode: Mode) -> bool {
        match mode {
            Mode::Layer2 => matches!(self, Self::Layer2 | Self::Layer2AndLayer3),
            Mode::Layer3 => matches!(self, Self::Layer3 | Self::Layer2AndLayer3),
            Mode::Auto => false,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Layer2 => "layer2",
            Self::Layer3 => "layer3",
            Self::Layer2AndLayer3 => "layer2_and3",
        }
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Auto,
    Layer2,
    Layer3,
}

impl Mode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Layer2 => "layer2",
            Self::Layer3 => "layer3",
        }
    }
}

impl std::fmt::Display for Mode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}
