// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;
use common::{CLIENT, SERVER, reader, registry, udp_frame};
use packetcraftr_core::{
    analysis::{
        self, StreamRef, StreamTransport,
        export::{self, Selection},
    },
    capture_file,
    filter::Filter,
    frame::Frame,
    transform::{FragmentOptions, fragment},
};
use std::{io::Cursor, time::UNIX_EPOCH};
fn frames() -> (Vec<Frame>, usize) {
    let registry = registry();
    let whole = udp_frame(
        &registry,
        UNIX_EPOCH,
        CLIENT,
        SERVER,
        40000,
        40001,
        &[0x55; 300],
    );
    let fragments = fragment(
        &whole,
        FragmentOptions {
            mtu: 76,
            ..Default::default()
        },
    )
    .unwrap();
    let count = fragments.len();
    let mut frames = vec![udp_frame(
        &registry,
        UNIX_EPOCH,
        CLIENT,
        SERVER,
        41000,
        41001,
        b"unrelated",
    )];
    frames.extend(fragments.into_iter().rev());
    frames.push(udp_frame(
        &registry,
        UNIX_EPOCH,
        SERVER,
        CLIENT,
        40001,
        40000,
        b"response",
    ));
    (frames, count)
}
#[test]
fn conversation_export_keeps_fragments_control_direction_and_exact_source_records() {
    let (frames, count) = frames();
    let selected = StreamRef {
        transport: StreamTransport::Udp,
        index: 1,
    };
    let mut input = reader(&frames);
    let plan = export::plan(
        &mut input,
        registry(),
        &Default::default(),
        &Selection {
            streams: vec![selected],
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        plan.source_frames.iter().copied().collect::<Vec<_>>(),
        (2..=count as u64 + 2).collect::<Vec<_>>()
    );
    assert_eq!(plan.matched_streams, [selected]);
    assert_eq!(plan.selected_complete_datagrams, 1);
    input.rewind().unwrap();
    let (wire, report) =
        capture_file::select(&mut input, Vec::new(), Default::default(), |number, _| {
            Ok(plan.source_frames.contains(&number))
        })
        .unwrap();
    assert_eq!(report.frames_selected, count as u64 + 1);
    let mut copied = capture_file::Reader::new(Cursor::new(wire)).unwrap();
    for source in &frames[1..] {
        assert_eq!(
            copied.next_frame().unwrap().unwrap().bytes(),
            source.bytes()
        );
    }
    assert!(copied.next_frame().unwrap().is_none());
}
#[test]
fn a_fragment_selector_and_derived_filter_expand_to_physical_dependencies() {
    let (frames, count) = frames();
    let plan = export::plan(
        &mut reader(&frames),
        registry(),
        &Default::default(),
        &Selection {
            datagram_frames: vec![2],
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(plan.source_frames.len(), count);
    assert!(plan.unmatched_datagram_frames.is_empty());
    let registry = registry();
    let filter = Filter::compile("udp.port == 40001", &registry, Default::default()).unwrap();
    let plan = export::plan(
        &mut reader(&frames),
        registry.clone(),
        &Default::default(),
        &Selection {
            filter: Some(&filter),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(plan.source_frames.len(), count + 1);
    assert!(
        export::plan(
            &mut reader(&frames),
            registry,
            &Default::default(),
            &Selection {
                datagram_frames: vec![2],
                max_selected_frames: 1,
                ..Default::default()
            }
        )
        .is_err()
    );
}
/// An incomplete group's key names a capture scope, so the plan defines it
/// even when no frame of the group reached the selection within time bounds.
#[test]
fn every_selected_incomplete_group_scope_is_defined() {
    let (frames, _) = frames();
    let options = analysis::Options {
        time_bounds: Some(
            packetcraftr_core::frame::TimeBounds::new(
                Some(UNIX_EPOCH + std::time::Duration::from_secs(1)),
                None,
            )
            .expect("ordered bounds"),
        ),
        ..analysis::Options::default()
    };
    let plan = export::plan(
        &mut reader(&frames[1..2]),
        registry(),
        &options,
        &Selection {
            datagram_frames: vec![1],
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(plan.selected_incomplete_datagrams.len(), 1);
    for group in &plan.selected_incomplete_datagrams {
        let scope = match &group.key {
            analysis::reassembly::ip::DatagramKey::Ipv4(key) => key.scope,
            analysis::reassembly::ip::DatagramKey::Ipv6(key) => key.scope,
        };
        assert!(
            plan.scopes.iter().any(|definition| definition.id == scope),
            "{scope:?} is undefined in {:?}",
            plan.scopes
        );
    }
}

#[test]
fn incomplete_dependencies_and_unmatched_streams_are_explicit() {
    let (mut frames, count) = frames();
    frames.remove(3);
    frames.pop();
    let plan = export::plan(
        &mut reader(&frames),
        registry(),
        &Default::default(),
        &Selection {
            datagram_frames: vec![2, 999],
            streams: vec![StreamRef {
                transport: StreamTransport::Tcp,
                index: 88,
            }],
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(plan.selected_incomplete_datagrams.len(), 1);
    assert_eq!(plan.source_frames.len(), count - 1);
    assert_eq!(plan.unmatched_datagram_frames, [999]);
    assert_eq!(plan.unmatched_streams.len(), 1);
    assert_eq!(plan.selected_complete_datagrams, 0);
    let mut limited = analysis::Options::default();
    limited.limits.max_provenance_bytes = 1;
    assert!(
        export::plan(
            &mut reader(&frames),
            registry(),
            &limited,
            &Selection {
                datagram_frames: vec![2],
                ..Default::default()
            }
        )
        .is_err()
    );
}
