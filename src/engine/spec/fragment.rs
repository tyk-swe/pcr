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
