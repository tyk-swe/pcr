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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supports_matches_each_concrete_mode_and_never_auto() {
        let cases = [
            (Capability::Layer2, Mode::Layer2, true),
            (Capability::Layer2, Mode::Layer3, false),
            (Capability::Layer3, Mode::Layer2, false),
            (Capability::Layer3, Mode::Layer3, true),
            (Capability::Layer2AndLayer3, Mode::Layer2, true),
            (Capability::Layer2AndLayer3, Mode::Layer3, true),
            (Capability::Layer2, Mode::Auto, false),
            (Capability::Layer3, Mode::Auto, false),
            (Capability::Layer2AndLayer3, Mode::Auto, false),
        ];
        for (capability, mode, expected) in cases {
            assert_eq!(
                capability.supports(mode),
                expected,
                "{capability:?} {mode:?}"
            );
        }
    }

    #[test]
    fn rendered_names_match_the_serialized_vocabulary() {
        assert_eq!(Capability::Layer2.as_str(), "layer2");
        assert_eq!(Capability::Layer3.as_str(), "layer3");
        assert_eq!(Capability::Layer2AndLayer3.as_str(), "layer2_and3");
        assert_eq!(Capability::Layer2AndLayer3.to_string(), "layer2_and3");
        assert_eq!(Mode::Auto.as_str(), "auto");
        assert_eq!(Mode::Layer2.as_str(), "layer2");
        assert_eq!(Mode::Layer3.as_str(), "layer3");
        assert_eq!(Mode::Auto.to_string(), "auto");
        assert_eq!(
            serde_json::to_string(&Capability::Layer2AndLayer3).unwrap(),
            "\"layer2_and3\""
        );
        assert_eq!(
            serde_json::to_string(&Capability::Layer2).unwrap(),
            "\"layer2\""
        );
        assert_eq!(serde_json::to_string(&Mode::Auto).unwrap(), "\"auto\"");
    }
}
