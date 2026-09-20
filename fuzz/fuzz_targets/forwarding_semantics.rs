// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]
mod composed_support;

use libfuzzer_sys::fuzz_target;
use packetcraftr_core::{
    analysis::forwarding::{self, Side, Verdict, VerifyLimits},
    protocol::builtin,
};

fuzz_target!(|data: &[u8]| {
    let mut payload = data[..data.len().min(512)].to_vec();
    payload.push(0); // Raw is always present, even for an empty fuzz input.
    let ingress = [composed_support::udp(40000, &payload)];
    payload[0] ^= 1;
    let changed = [composed_support::udp(40000, &payload)];
    let identity = vec!["udp.source_port".to_owned()];
    let preserve = vec!["raw.bytes".to_owned()];
    let rules =
        forwarding::Rules::compile(&identity, &preserve, &[], &builtin::registry(), 8192).unwrap();
    for (egress, expected) in [(&ingress, Verdict::Pass), (&changed, Verdict::Fail)] {
        let mut first = None;
        for (max_details, max_detail_bytes) in [(16, 65536), (0, 0), (1, 1)] {
            let (Ok(before), Ok(after)) = (
                composed_support::collect(&rules, Side::Ingress, &ingress),
                composed_support::collect(&rules, Side::Egress, egress),
            ) else {
                return;
            };
            let report = forwarding::verify_with_limits(
                &rules,
                before,
                after,
                VerifyLimits {
                    max_details,
                    max_detail_bytes,
                    ..VerifyLimits::default()
                },
                None,
                None,
            )
            .unwrap();
            assert_eq!(report.verdict, expected);
            let counters = serde_json::to_value(&report.summary).unwrap();
            if let Some(ref first) = first {
                assert_eq!(first, &counters);
            }
            first = Some(counters);
        }
    }
    let missing = forwarding::Rules::compile(
        &identity,
        &["tcp.sequence".to_owned()],
        &[],
        &builtin::registry(),
        8192,
    )
    .unwrap();
    let (Ok(before), Ok(after)) = (
        composed_support::collect(&missing, Side::Ingress, &ingress),
        composed_support::collect(&missing, Side::Egress, &ingress),
    ) else {
        return;
    };
    let report = forwarding::verify(&missing, before, after, 16, None).unwrap();
    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert_eq!(report.summary.checks_satisfied, 0);
});
