// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::frame::Frame;
use serde::Serialize;

use super::{contract::Error, frame::Captured, stream::StreamRecord};

#[derive(Clone, Debug, Serialize)]
pub struct Fragment {
    pub fragment_index: u64,
    pub frame: Captured,
}
impl TryFrom<(u64, Frame)> for Fragment {
    type Error = Error;

    fn try_from((fragment_index, frame): (u64, Frame)) -> Result<Self, Error> {
        Ok(Self {
            fragment_index,
            frame: frame.try_into()?,
        })
    }
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
impl From<(usize, &[Frame])> for Complete {
    fn from((mtu, frames): (usize, &[Frame])) -> Self {
        Self {
            mtu,
            fragments: frames.len() as u64,
            bytes: frames.iter().map(|frame| frame.bytes().len() as u64).sum(),
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub summary: Complete,
    pub fragments: Vec<Fragment>,
}
impl From<(Complete, Vec<Fragment>)> for Report {
    fn from((summary, fragments): (Complete, Vec<Fragment>)) -> Self {
        Self { summary, fragments }
    }
}
