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
    fn as_str_names_are_nonempty_and_distinct_per_variant() {
        let capabilities = [
            Capability::Layer2.as_str(),
            Capability::Layer3.as_str(),
            Capability::Layer2AndLayer3.as_str(),
        ];
        let modes = [
            Mode::Auto.as_str(),
            Mode::Layer2.as_str(),
            Mode::Layer3.as_str(),
        ];
        for names in [capabilities, modes] {
            assert!(names.iter().all(|name| !name.is_empty()));
            assert_ne!(names[0], names[1]);
            assert_ne!(names[1], names[2]);
            assert_ne!(names[0], names[2]);
        }
    }

    #[test]
    fn display_agrees_with_as_str() {
        for capability in [
            Capability::Layer2,
            Capability::Layer3,
            Capability::Layer2AndLayer3,
        ] {
            assert_eq!(capability.to_string(), capability.as_str());
        }
        for mode in [Mode::Auto, Mode::Layer2, Mode::Layer3] {
            assert_eq!(mode.to_string(), mode.as_str());
        }
    }
}
