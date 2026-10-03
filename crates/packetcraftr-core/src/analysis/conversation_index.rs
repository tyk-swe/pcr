// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::net::IpAddr;

use super::Error;
use super::reassembly::tcp::ScopedFlowKey;
use crate::analysis::scope::ScopeId;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct CanonicalFlow {
    pub(super) scope: ScopeId,
    pub(super) first: (IpAddr, u16),
    pub(super) second: (IpAddr, u16),
}

impl CanonicalFlow {
    pub(super) fn from_flow(flow: &ScopedFlowKey) -> Self {
        let near = (flow.flow.source, flow.flow.source_port);
        let far = (flow.flow.destination, flow.flow.destination_port);
        if near <= far {
            Self {
                scope: flow.scope,
                first: near,
                second: far,
            }
        } else {
            Self {
                scope: flow.scope,
                first: far,
                second: near,
            }
        }
    }
}

/// First-seen conversation indices assigned before filtering, so indices remain
/// stable across commands on the same capture.
#[derive(Debug, Default)]
pub(super) struct StreamIndex {
    assignments: HashMap<CanonicalFlow, u64>,
}

impl StreamIndex {
    pub(super) fn assign(
        &mut self,
        flow: &ScopedFlowKey,
        number: u64,
        max_flows: usize,
    ) -> Result<u64, Error> {
        let canonical = CanonicalFlow::from_flow(flow);
        if let Some(index) = self.assignments.get(&canonical) {
            return Ok(*index);
        }
        if self.assignments.len() >= max_flows {
            return Err(Error::StreamLimit {
                number,
                limit: max_flows,
            });
        }
        let index = self.assignments.len() as u64;
        self.assignments.insert(canonical, index);
        Ok(index)
    }
}
