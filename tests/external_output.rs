// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::UNIX_EPOCH;

use packetcraftr::{
    AggregateOutput, CapturedFrame, CommandName, LinkType, ReadFrameCommandResult,
    RoutesCommandResult, StreamRecord,
};

#[test]
fn external_commands_can_reuse_typed_aggregate_and_stream_contracts() {
    let aggregate = AggregateOutput::success(
        CommandName::Routes,
        RoutesCommandResult { routes: Vec::new() },
        Vec::new(),
    );
    let aggregate = serde_json::to_value(aggregate).unwrap();
    assert_eq!(aggregate["mode"], "aggregate");
    assert!(aggregate.get("sequence").is_none());

    let frame = CapturedFrame::new(UNIX_EPOCH, LinkType::ETHERNET, vec![0xde, 0xad]).unwrap();
    let result = ReadFrameCommandResult::try_from_frame(frame).unwrap();
    let stream = StreamRecord::success(CommandName::Read, 0, result, Vec::new());
    let stream = serde_json::to_value(stream).unwrap();
    assert_eq!(stream["mode"], "stream");
    assert_eq!(stream["sequence"], 0);
    assert_eq!(stream["result"]["frame"]["bytes_hex"], "dead");
}
