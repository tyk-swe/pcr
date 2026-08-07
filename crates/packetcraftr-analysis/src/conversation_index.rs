// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Conversation indexing for packet flows.

use std::collections::HashMap;
use std::net::IpAddr;

use super::{AnalysisError, FlowKey};

/// One conversation, with its two endpoints in a direction-neutral order.
///
/// Both directions of a flow map onto the same canonical value, which is what
/// lets one index describe the conversation an operator follows rather than
/// the two one-way flows the wire carries.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct CanonicalFlow {
    pub(super) first: (IpAddr, u16),
    pub(super) second: (IpAddr, u16),
}

impl CanonicalFlow {
    pub(super) fn from_flow(flow: &FlowKey) -> Self {
        let near = (flow.source, flow.source_port);
        let far = (flow.destination, flow.destination_port);
        if near <= far {
            Self {
                first: near,
                second: far,
            }
        } else {
            Self {
                first: far,
                second: near,
            }
        }
    }
}

/// First-seen conversation numbering, stable for a given input.
///
/// Indices are assigned in the order conversations first appear in the
/// capture, before any display filter is applied, so `tcp.stream 7` names the
/// same conversation whether or not the run was filtered — which is what lets
/// one command report an index and another extract it.
#[derive(Debug, Default)]
pub(super) struct StreamIndex {
    assignments: HashMap<CanonicalFlow, u64>,
}

impl StreamIndex {
    /// Returns the conversation index for `flow`, assigning the next index
    /// on first sight. `number` is the capture frame being processed and
    /// `max_flows` the table bound; exceeding it is an error rather than a
    /// silent misattribution.
    pub(super) fn assign(
        &mut self,
        flow: &FlowKey,
        number: u64,
        max_flows: usize,
    ) -> Result<u64, AnalysisError> {
        let canonical = CanonicalFlow::from_flow(flow);
        if let Some(index) = self.assignments.get(&canonical) {
            return Ok(*index);
        }
        if self.assignments.len() >= max_flows {
            return Err(AnalysisError::StreamLimit {
                number,
                limit: max_flows,
            });
        }
        let index = self.assignments.len() as u64;
        self.assignments.insert(canonical, index);
        Ok(index)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn flow(source_port: u16, destination_port: u16) -> FlowKey {
        FlowKey {
            source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            source_port,
            destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            destination_port,
        }
    }

    #[test]
    fn reverse_directions_share_an_index_and_new_flows_obey_the_limit() {
        let first = flow(10_000, 443);
        let mut index = StreamIndex::default();

        assert_eq!(index.assign(&first, 1, 1).expect("first flow must fit"), 0);
        assert_eq!(
            index
                .assign(&first.reverse(), 2, 1)
                .expect("reverse direction must reuse the conversation"),
            0
        );
        assert!(matches!(
            index.assign(&flow(10_001, 443), 3, 1),
            Err(AnalysisError::StreamLimit {
                number: 3,
                limit: 1
            })
        ));
    }
}
