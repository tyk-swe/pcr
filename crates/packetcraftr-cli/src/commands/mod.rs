// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Command-specific CLI adapters.

mod capture;
mod dns;
mod expert;
mod follow;
mod fuzz;
mod interfaces;
mod network;
mod offline;
mod offline_analysis;
mod protocols;
mod replay;
mod scan;
mod stats;
mod traceroute;

pub(super) use capture::{run_capture, run_exchange};
pub(super) use dns::run_dns;
pub(super) use expert::run_expert;
pub(super) use follow::run_follow;
pub(super) use fuzz::run_fuzz;
pub(super) use interfaces::run_interfaces;
pub(super) use network::{run_plan, run_routes, run_send};
pub(super) use offline::{run_build, run_dissect, run_read};
pub(super) use protocols::run_protocols;
pub(super) use replay::run_replay;
pub(super) use scan::run_scan;
pub(super) use stats::run_stats;
pub(super) use traceroute::run_traceroute;

#[cfg(test)]
mod tests {
    use packetcraftr::workflow;

    use super::{
        dns::dns_cli_error, fuzz::fuzz_cli_error, replay::replay_cli_error, scan::scan_cli_error,
        traceroute::traceroute_cli_error,
    };

    #[test]
    fn per_item_tool_errors_retain_their_input_sequence() {
        let scan = scan_cli_error(workflow::scan::Error::InvalidEvidence {
            sequence: 7,
            message: "invalid scan evidence".to_owned(),
        });
        assert_eq!(scan.sequence, Some(7));

        let traceroute = traceroute_cli_error(workflow::traceroute::Error::InvalidEvidence {
            sequence: 8,
            message: "invalid traceroute evidence".to_owned(),
        });
        assert_eq!(traceroute.sequence, Some(8));

        let dns = dns_cli_error(workflow::dns::Error::InvalidEvidence {
            attempt: 3,
            message: "invalid DNS evidence".to_owned(),
        });
        assert_eq!(dns.sequence, Some(2));

        let fuzz = fuzz_cli_error(workflow::fuzz::Error::InvalidEvidence {
            case_index: 9,
            message: "invalid fuzz evidence".to_owned(),
        });
        assert_eq!(fuzz.sequence, Some(9));

        let replay = replay_cli_error(workflow::replay::Error::output(10, "replay output failed"));
        assert_eq!(replay.sequence, Some(10));
    }
}
