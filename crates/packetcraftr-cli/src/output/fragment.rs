// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{frame::Captured, stream::StreamRecord};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct Fragment {
    pub fragment_index: u64,
    pub frame: Captured,
}
impl StreamRecord for Fragment {
    fn event_name(&self) -> &'static str {
        "fragment"
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Complete {
    pub mtu: usize,
    pub fragments: u64,
    pub bytes: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub summary: Complete,
    pub fragments: Vec<Fragment>,
}
