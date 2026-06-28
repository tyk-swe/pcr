// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use crate::engine::request::{FragmentProfile, FragmentRequest};

#[derive(Debug, Clone, Default)]
pub struct FragmentSpec {
    pub mtu: Option<u16>,
    pub offset: Option<u16>,
    pub more_fragments: bool,
    pub dont_fragment: bool,
    pub overlap: bool,
    pub teardrop: bool,
    pub profile: Option<FragmentProfile>,
    pub fragment_id: Option<u32>,
}

impl FragmentSpec {
    pub(crate) fn from_request(request: &FragmentRequest) -> Self {
        let mut spec = Self {
            mtu: request.mtu,
            offset: request.offset,
            more_fragments: request.more_fragments.unwrap_or(false),
            dont_fragment: request.dont_fragment.unwrap_or(false),
            overlap: request.overlap.unwrap_or(false),
            teardrop: request.teardrop.unwrap_or(false),
            profile: request.profile,
            fragment_id: request.fragment_id,
        };

        if let Some(profile) = spec.profile {
            spec.apply_profile(profile);
        }

        spec
    }

    pub fn is_default(&self) -> bool {
        self.mtu.is_none()
            && self.offset.is_none()
            && !self.more_fragments
            && !self.dont_fragment
            && !self.overlap
            && !self.teardrop
            && self.profile.is_none()
            && self.fragment_id.is_none()
    }

    pub fn apply_profile(&mut self, profile: FragmentProfile) {
        self.dont_fragment = false;
        match profile {
            FragmentProfile::Overlap => {
                self.overlap = true;
                self.more_fragments = true;
                self.mtu = self.mtu.or(Some(68));
            }
            FragmentProfile::Teardrop => {
                self.teardrop = true;
                self.more_fragments = true;
            }
            FragmentProfile::TinyOverlap => {
                self.mtu = Some(self.mtu.unwrap_or(40));
                self.more_fragments = true;
                self.overlap = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragment_spec_default_is_default() {
        let spec = FragmentSpec::default();
        assert!(spec.is_default());
    }

    #[test]
    fn is_default_returns_false_for_any_fragment_knob() {
        let cases = [
            FragmentSpec {
                mtu: Some(1500),
                ..Default::default()
            },
            FragmentSpec {
                offset: Some(100),
                ..Default::default()
            },
            FragmentSpec {
                more_fragments: true,
                ..Default::default()
            },
            FragmentSpec {
                dont_fragment: true,
                ..Default::default()
            },
            FragmentSpec {
                overlap: true,
                ..Default::default()
            },
            FragmentSpec {
                teardrop: true,
                ..Default::default()
            },
            FragmentSpec {
                profile: Some(FragmentProfile::Overlap),
                ..Default::default()
            },
            FragmentSpec {
                fragment_id: Some(12345),
                ..Default::default()
            },
        ];

        for spec in cases {
            assert!(!spec.is_default(), "{spec:?}");
        }
    }

    #[test]
    fn profiles_apply_expected_fragment_defaults() {
        let mut overlap = FragmentSpec::default();
        overlap.apply_profile(FragmentProfile::Overlap);
        assert!(overlap.overlap);
        assert!(overlap.more_fragments);
        assert_eq!(overlap.mtu, Some(68));

        let mut teardrop = FragmentSpec::default();
        teardrop.apply_profile(FragmentProfile::Teardrop);
        assert!(teardrop.teardrop);
        assert!(teardrop.more_fragments);
        assert!(teardrop.mtu.is_none());

        let mut tiny = FragmentSpec::default();
        tiny.apply_profile(FragmentProfile::TinyOverlap);
        assert!(tiny.overlap);
        assert!(tiny.more_fragments);
        assert_eq!(tiny.mtu, Some(40));
    }

    #[test]
    fn profiles_preserve_explicit_mtu_and_clear_dont_fragment() {
        let mut request = FragmentRequest {
            profile: Some(FragmentProfile::TinyOverlap),
            mtu: Some(96),
            dont_fragment: Some(true),
            fragment_id: Some(0xfeed_face),
            ..Default::default()
        };

        let spec = FragmentSpec::from_request(&request);
        assert_eq!(spec.mtu, Some(96));
        assert!(spec.overlap);
        assert!(!spec.dont_fragment);
        assert_eq!(spec.fragment_id, Some(0xfeed_face));

        request.profile = Some(FragmentProfile::Overlap);
        let spec = FragmentSpec::from_request(&request);
        assert_eq!(spec.mtu, Some(96));
    }
}
