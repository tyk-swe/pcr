#![no_main]

use libfuzzer_sys::fuzz_target;
use packetcraftr_core::{
    analysis::{
        self,
        pcap::{Reader, Writer},
        tls,
    },
    frame::{Frame, LinkType},
    protocol::builtin,
};
use std::{
    collections::HashSet,
    io::Cursor,
    sync::OnceLock,
    time::{Duration, SystemTime},
};

fn frames() -> &'static [Frame] {
    static FRAMES: OnceLock<Vec<Frame>> = OnceLock::new();
    FRAMES.get_or_init(|| {
        let mut reader = Reader::new(Cursor::new(include_bytes!(
            "../../examples/captures/tls-handshake.pcapng"
        )))
        .unwrap();
        let mut frames = Vec::new();
        while let Some(frame) = reader.next_frame().unwrap() {
            frames.push(frame);
        }
        frames
    })
}

fuzz_target!(|data: &[u8]| {
    let frames = frames();
    let mut writer = Writer::pcapng(Vec::new()).unwrap();
    for _ in 0..2 {
        writer.add_interface(LinkType::IPV4).unwrap();
    }
    // Valid captured SYN/hello/close records are reordered, repeated, split
    // across scopes, and spread over discontinuous capture time. Most inputs
    // reach collector transitions immediately instead of failing a file header.
    for action in data.chunks_exact(4).take(64) {
        let source = &frames[usize::from(action[0]) % frames.len()];
        let mut bytes = source.bytes().to_vec();
        let port = (40_000 + u16::from(action[1] % 4)).to_be_bytes();
        let offset = if bytes[20..22] == 443u16.to_be_bytes() {
            22
        } else {
            20
        };
        bytes[offset..offset + 2].copy_from_slice(&port);
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(u64::from(action[2]));
        let mut frame = Frame::new(timestamp, LinkType::IPV4, bytes).unwrap();
        frame.interface = Some(u32::from(action[3] % 2));
        writer.write_frame(&frame).unwrap();
    }
    let mut reader = Reader::new(Cursor::new(writer.into_inner())).unwrap();
    let mut collector = tls::Collector::new(tls::Limits {
        max_sessions: 4,
        max_buffered_bytes: tls::MAX_DIRECTION_BUFFER,
    })
    .unwrap();
    let mut seen = HashSet::new();
    let mut observe = |events: Vec<tls::SessionEvent>| {
        for event in events {
            assert!(
                seen.insert(event.session.session),
                "duplicate terminal session"
            );
            assert!(event.session.first_frame <= event.session.last_frame);
            serde_json::to_vec(&event.session).unwrap();
        }
    };
    let options = analysis::Options {
        tcp_events: true,
        limits: analysis::Limits {
            max_frames: 64,
            max_flows: 8,
            ..analysis::Limits::default()
        },
        ..analysis::Options::default()
    };
    if let Ok(summary) = analysis::run(&mut reader, builtin::registry(), &options, |record| {
        observe(collector.observe(&record));
        Ok(())
    }) {
        let (events, summary) = collector.finish(&summary);
        observe(events);
        assert_eq!(summary.sessions as usize, seen.len());
        assert!(summary.tcp_streams <= 8);
        assert!(summary.evicted_sessions <= summary.sessions);
    }
});
