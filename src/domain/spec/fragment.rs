// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use crate::domain::request::{FragmentProfile, FragmentRequest};

#[derive(Debug, Clone, Default)]
pub(crate) struct FragmentSpec {
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

    pub(crate) fn is_default(&self) -> bool {
        self.mtu.is_none()
            && self.offset.is_none()
            && !self.more_fragments
            && !self.dont_fragment
            && !self.overlap
            && !self.teardrop
            && self.profile.is_none()
            && self.fragment_id.is_none()
    }

    pub(crate) fn apply_profile(&mut self, profile: FragmentProfile) {
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
    fn default_fragment_spec_is_effectively_empty() {
        assert!(FragmentSpec::from_request(&FragmentRequest::default()).is_default());
    }

    #[test]
    fn fragment_spec_preserves_explicit_flags() {
        let spec = FragmentSpec::from_request(&FragmentRequest {
            mtu: Some(1280),
            offset: Some(8),
            more_fragments: Some(true),
            dont_fragment: Some(true),
            fragment_id: Some(42),
            ..Default::default()
        });

        assert_eq!(spec.mtu, Some(1280));
        assert_eq!(spec.offset, Some(8));
        assert!(spec.more_fragments);
        assert!(spec.dont_fragment);
        assert_eq!(spec.fragment_id, Some(42));
    }

    #[test]
    fn overlap_profile_sets_overlap_more_fragments_and_default_mtu() {
        let spec = FragmentSpec::from_request(&FragmentRequest {
            profile: Some(FragmentProfile::Overlap),
            dont_fragment: Some(true),
            ..Default::default()
        });

        assert!(spec.overlap);
        assert!(spec.more_fragments);
        assert_eq!(spec.mtu, Some(68));
        assert!(!spec.dont_fragment);
    }

    #[test]
    fn tiny_overlap_profile_keeps_explicit_mtu() {
        let spec = FragmentSpec::from_request(&FragmentRequest {
            mtu: Some(96),
            profile: Some(FragmentProfile::TinyOverlap),
            ..Default::default()
        });

        assert_eq!(spec.mtu, Some(96));
        assert!(spec.overlap);
        assert!(spec.more_fragments);
    }

    #[test]
    fn teardrop_profile_sets_teardrop_without_forcing_mtu() {
        let spec = FragmentSpec::from_request(&FragmentRequest {
            profile: Some(FragmentProfile::Teardrop),
            ..Default::default()
        });

        assert!(spec.teardrop);
        assert!(spec.more_fragments);
        assert_eq!(spec.mtu, None);
    }
}
