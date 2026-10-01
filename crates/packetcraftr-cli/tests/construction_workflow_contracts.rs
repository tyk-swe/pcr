// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;
use common::{parse_json, parse_ndjson, path_text, run, run_success};

#[test]
fn cli_builds_named_dns_and_tls_fixtures_and_nested_axes() {
    let dns = r#"dns(questions=[{name="example.test",type=1}],answers=[{owner="example.test",ttl=60,value={kind=a,address=192.0.2.8}}])"#;
    let result = parse_json(&run_success(&[
        "--output", "json", "build", "--packet", dns,
    ]));
    assert_eq!(
        result["result"]["packet"]["layers"][0]["fields"]["answer_count"]["value"],
        1
    );
    let tls = r#"tls(hello={extensions=[{server_name="example.test"}]})"#;
    let records = parse_ndjson(&run_success(&[
        "--output",
        "ndjson",
        "build",
        "--packet",
        tls,
        "--axis",
        "0.hello.cipher_suites[0]=[49199,49200]",
    ]));
    assert_eq!(records.len(), 3);
    let first = &records[0]["result"]["packet"]["layers"][0]["fields"];
    assert_eq!(first["sni"]["value"], "example.test");
    assert_ne!(
        first["ja3"],
        records[1]["result"]["packet"]["layers"][0]["fields"]["ja3"]
    );
}

#[test]
fn fragment_capture_and_structured_outputs_have_matching_bounded_frames() {
    let packet = format!(
        "ipv4(src=192.0.2.1,dst=192.0.2.2)/udp(sport=40000,dport=40001)/raw(text={})",
        "x".repeat(600)
    );
    let records = parse_ndjson(&run_success(&[
        "--output", "ndjson", "fragment", "--packet", &packet, "--mtu", "128",
    ]));
    let capture = run_success(&[
        "--output", "pcapng", "fragment", "--packet", &packet, "--mtu", "128",
    ]);
    let mut reader =
        packetcraftr_core::capture_file::Reader::new(std::io::Cursor::new(capture.stdout)).unwrap();
    let mut count = 0;
    while let Some(frame) = reader.next_frame().unwrap() {
        assert!(frame.bytes().len() <= 128);
        count += 1;
    }
    assert_eq!(records.last().unwrap()["result"]["fragments"], count);
    assert_eq!(records.last().unwrap()["event"], "complete");
}

const TCP_SESSION_RECIPE: &str = "ethernet(src=02:00:00:00:00:01,dst=02:00:00:00:00:02)/ipv4(src=192.0.2.1,dst=198.51.100.2)/tcp(sport=40000,dport=80)/raw()";

fn session_frames(capture: &[u8]) -> Vec<packetcraftr_core::frame::Frame> {
    let mut reader =
        packetcraftr_core::capture_file::Reader::new(std::io::Cursor::new(capture)).unwrap();
    let mut frames = Vec::new();
    while let Some(frame) = reader.next_frame().unwrap() {
        frames.push(frame);
    }
    frames
}

fn tcp_flags(frame: &packetcraftr_core::frame::Frame) -> u8 {
    // Ethernet 14 + IPv4 20 + TCP flags at offset 13.
    frame.bytes()[14 + 20 + 13]
}

#[test]
fn build_session_tcp_writes_an_analyzable_deterministic_conversation() {
    let directory = tempfile::tempdir().expect("scratch directory");
    let request = directory.path().join("request.bin");
    let response = directory.path().join("response.bin");
    let request_bytes = (0..3000_u32).map(|value| value as u8).collect::<Vec<_>>();
    let response_bytes = vec![b'r'; 100];
    std::fs::write(&request, &request_bytes).unwrap();
    std::fs::write(&response, &response_bytes).unwrap();
    let payload = format!("raw.bytes={}", path_text(&request));
    let arguments = [
        "--output",
        "pcap",
        "build",
        "--session",
        "tcp",
        "--packet",
        TCP_SESSION_RECIPE,
        "--payload-file",
        &payload,
        "--link-type",
        "ethernet",
        "--timestamp",
        "1700000000.5",
        "--session-step-ns",
        "250000000",
        "--session-response-file",
        path_text(&response),
    ];
    let first = run_success(&arguments);
    assert_eq!(first.stdout, run_success(&arguments).stdout);

    let frames = session_frames(&first.stdout);
    // Handshake, three request segments and an ACK, response and ACK, FIN exchange.
    assert_eq!(frames.len(), 13);
    for (index, frame) in frames.iter().enumerate() {
        let elapsed = frame
            .timestamp
            .expect("captured timestamp")
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        assert_eq!(
            elapsed,
            std::time::Duration::new(1_700_000_000, 500_000_000)
                + std::time::Duration::from_millis(250 * index as u64),
            "frame {index}"
        );
    }
    assert_eq!(tcp_flags(&frames[0]), 0x02);
    assert_eq!(tcp_flags(&frames[1]), 0x12);
    assert_eq!(tcp_flags(&frames[9]), 0x11);

    let capture = directory.path().join("conversation.pcap");
    std::fs::write(&capture, &first.stdout).unwrap();
    let expert = parse_json(&run_success(&[
        "--output",
        "json",
        "expert",
        path_text(&capture),
    ]));
    assert_eq!(expert["result"]["codes"], serde_json::json!([]));
    let out = directory.path().join("followed");
    std::fs::create_dir(&out).unwrap();
    run_success(&[
        "follow",
        path_text(&capture),
        "--stream",
        "tcp:0",
        "--write",
        path_text(&out),
    ]);
    assert_eq!(
        std::fs::read(out.join("tcp-0-client.bin")).unwrap(),
        request_bytes
    );
    assert_eq!(
        std::fs::read(out.join("tcp-0-server.bin")).unwrap(),
        response_bytes
    );
}

#[test]
fn build_session_close_modes_and_ndjson_output() {
    let build = |close: &str| {
        let output = run_success(&[
            "--output",
            "pcap",
            "build",
            "--session",
            "tcp",
            "--packet",
            TCP_SESSION_RECIPE,
            "--link-type",
            "ethernet",
            "--session-close",
            close,
        ]);
        session_frames(&output.stdout)
    };
    let rst = build("rst");
    assert_eq!(rst.len(), 4);
    assert_eq!(tcp_flags(rst.last().unwrap()), 0x14);
    let open = build("none");
    assert_eq!(open.len(), 3);
    assert_eq!(tcp_flags(open.last().unwrap()), 0x10);
    // The default step spaces frames one millisecond apart.
    assert_eq!(
        open[2]
            .timestamp
            .expect("captured timestamp")
            .duration_since(open[1].timestamp.expect("captured timestamp"))
            .unwrap(),
        std::time::Duration::from_millis(1)
    );

    let records = parse_ndjson(&run_success(&[
        "--output",
        "ndjson",
        "build",
        "--session",
        "tcp",
        "--packet",
        TCP_SESSION_RECIPE,
        "--session-close",
        "none",
    ]));
    assert_eq!(records.len(), 4);
    assert_eq!(records[3]["event"], "complete");
    assert_eq!(records[3]["result"]["packets_built"], 3);
}

#[test]
fn build_session_udp_replies_with_swapped_endpoints() {
    let directory = tempfile::tempdir().expect("scratch directory");
    let response = directory.path().join("response.bin");
    std::fs::write(&response, b"answer").unwrap();
    let output = run_success(&[
        "--output",
        "pcap",
        "build",
        "--session",
        "udp",
        "--packet",
        "ethernet(src=02:00:00:00:00:01,dst=02:00:00:00:00:02)/ipv4(src=192.0.2.1,dst=198.51.100.2)/udp(sport=41000,dport=5300)/raw(text=query)",
        "--link-type",
        "ethernet",
        "--session-response-file",
        path_text(&response),
    ]);
    let frames = session_frames(&output.stdout);
    assert_eq!(frames.len(), 2);
    let (request, reply) = (frames[0].bytes(), frames[1].bytes());
    assert_eq!(request[0..6], reply[6..12]);
    assert_eq!(request[6..12], reply[0..6]);
    assert_eq!(request[26..30], reply[30..34]);
    assert_eq!(request[30..34], reply[26..30]);
    assert_eq!(request[34..36], reply[36..38]);
    assert_eq!(request[36..38], reply[34..36]);
    assert!(reply.ends_with(b"answer"));
    // The builder resolves the checksum, so it is never left at zero.
    assert_ne!(reply[40..42], [0, 0]);
}

#[test]
fn build_session_udp_keeps_a_typed_request_on_a_registered_port() {
    let directory = tempfile::tempdir().expect("scratch directory");
    let response = directory.path().join("response.bin");
    std::fs::write(&response, b"answer").unwrap();
    let recipe =
        "ethernet()/ipv4(src=192.0.2.1,dst=198.51.100.2)/udp(sport=4000,dport=53)/dns(id=1)";
    // Strict mode builds the typed query exactly as it does without a session.
    let query = run_success(&[
        "--output",
        "pcap",
        "build",
        "--session",
        "udp",
        "--packet",
        recipe,
        "--link-type",
        "ethernet",
    ]);
    let plain = run_success(&[
        "--output",
        "pcap",
        "build",
        "--packet",
        recipe,
        "--link-type",
        "ethernet",
    ]);
    assert_eq!(query.stdout, plain.stdout);
    assert_eq!(session_frames(&query.stdout).len(), 1);

    // A reply is raw bytes, so strict mode refuses it before any output while
    // permissive mode keeps it and warns.
    let reply = [
        "build",
        "--session",
        "udp",
        "--packet",
        recipe,
        "--link-type",
        "ethernet",
        "--session-response-file",
        path_text(&response),
    ];
    let strict = run(&[&["--output", "pcap"][..], &reply[..]].concat());
    assert_eq!(strict.status.code(), Some(3));
    assert!(strict.stdout.is_empty());
    assert!(String::from_utf8_lossy(&strict.stderr).contains("move it off the registered port"));
    let permissive = run(&[
        &["--output", "pcap"][..],
        &reply[..],
        &["--mode", "permissive"],
    ]
    .concat());
    assert_eq!(permissive.status.code(), Some(0));
    assert_eq!(session_frames(&permissive.stdout).len(), 2);
    assert!(String::from_utf8_lossy(&permissive.stderr).contains("build.udp_encapsulation_port"));
}

#[test]
fn build_session_applies_segment_size_and_both_initial_sequence_numbers() {
    let output = run_success(&[
        "--output",
        "pcap",
        "build",
        "--session",
        "tcp",
        "--packet",
        &TCP_SESSION_RECIPE.replace("raw()", "raw(text=hello)"),
        "--link-type",
        "ethernet",
        "--session-mss",
        "2",
        "--session-client-isn",
        "4294967295",
        "--session-server-isn",
        "7",
        "--session-close",
        "none",
    ]);
    let frames = session_frames(&output.stdout);
    // Handshake, three segments of two, two, and one byte, then one ACK.
    assert_eq!(frames.len(), 7);
    let word = |frame: usize, offset: usize| {
        let bytes = frames[frame].bytes();
        u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
    };
    let sequence = |frame: usize| word(frame, 14 + 20 + 4);
    let acknowledgment = |frame: usize| word(frame, 14 + 20 + 8);
    // The SYN advertises the chosen segment size as its only option.
    assert_eq!(frames[0].bytes()[54..58], [2, 4, 0, 2]);
    assert_eq!((sequence(0), sequence(1)), (u32::MAX, 7));
    assert_eq!(acknowledgment(1), 0);
    // The client sequence wraps past the maximum after the SYN.
    assert_eq!(
        [sequence(3), sequence(4), sequence(5)],
        [0, 2, 4],
        "segments advance by the segment size"
    );
    let payload_lengths = (3..6)
        .map(|frame| frames[frame].bytes().len() - (14 + 20 + 20))
        .collect::<Vec<_>>();
    assert_eq!(payload_lengths, [2, 2, 1]);
    assert_eq!((sequence(6), acknowledgment(6)), (8, 5));
}

#[test]
fn build_session_runs_over_vlan_tagged_ipv6() {
    let directory = tempfile::tempdir().expect("scratch directory");
    let output = run_success(&[
        "--output",
        "pcap",
        "build",
        "--session",
        "tcp",
        "--packet",
        "ethernet(src=02:00:00:00:00:01,dst=02:00:00:00:00:02)/vlan(vlan_id=7)/ipv6(src=2001:db8::1,dst=2001:db8::2)/tcp(sport=40000,dport=80)/raw(text=hello)",
        "--link-type",
        "ethernet",
    ]);
    let frames = session_frames(&output.stdout);
    // Handshake, request and its ACK, FIN exchange.
    assert_eq!(frames.len(), 9);
    let (request, reply) = (frames[0].bytes(), frames[1].bytes());
    // The reply keeps the VLAN tag and IPv6 header and swaps the endpoints.
    assert_eq!(request[12..18], reply[12..18]);
    assert_eq!(request[0..6], reply[6..12]);
    assert_eq!(request[6..12], reply[0..6]);
    assert_eq!(request[26..42], reply[42..58]);
    assert_eq!(request[42..58], reply[26..42]);
    assert_eq!(request[58..60], reply[60..62]);
    assert_eq!(request[60..62], reply[58..60]);

    let capture = directory.path().join("vlan.pcap");
    std::fs::write(&capture, &output.stdout).unwrap();
    let expert = parse_json(&run_success(&[
        "--output",
        "json",
        "expert",
        path_text(&capture),
    ]));
    assert_eq!(expert["result"]["codes"], serde_json::json!([]));
}

#[test]
fn build_session_checks_every_capture_timestamp_before_output() {
    let recipe = "ipv4(src=192.0.2.1,dst=198.51.100.2)/tcp(sport=40000,dport=80)/raw(text=hello)";
    for format in ["pcap", "pcapng"] {
        // The last frame lies beyond the capture format's range, though
        // earlier frames fit and would otherwise be written first.
        let output = run(&[
            "--output",
            format,
            "build",
            "--session",
            "tcp",
            "--packet",
            recipe,
            "--link-type",
            "ipv4",
            "--timestamp",
            "1.5",
            "--session-step-ns",
            "18446744073709551615",
        ]);
        assert_eq!(output.status.code(), Some(3), "{format}");
        assert!(
            output.stdout.is_empty(),
            "{format}: partial capture written"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("cannot be represented"),
            "{format}"
        );
    }
}

#[test]
fn build_session_reports_the_frame_limit_and_empty_responses_as_typed_errors() {
    let output = run(&[
        "--output",
        "pcap",
        "build",
        "--session",
        "tcp",
        "--packet",
        "ipv4(src=192.0.2.1,dst=198.51.100.2)/tcp(sport=40000,dport=80)/raw(text=hello)",
        "--link-type",
        "ipv4",
        "--session-mss",
        "1",
        "--max-template-packets",
        "10",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cli.conversation_limit"));

    let directory = tempfile::tempdir().expect("scratch directory");
    let empty = directory.path().join("empty.bin");
    std::fs::write(&empty, b"").unwrap();
    let output = run(&[
        "--output",
        "pcap",
        "build",
        "--session",
        "tcp",
        "--packet",
        TCP_SESSION_RECIPE,
        "--link-type",
        "ethernet",
        "--session-response-file",
        path_text(&empty),
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("response file"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("is empty"));
}

#[test]
fn build_session_refuses_oversized_or_conflicting_requests_before_output() {
    let directory = tempfile::tempdir().expect("scratch directory");
    let response = directory.path().join("response.bin");
    std::fs::write(&response, vec![0_u8; 1460 * 5000]).unwrap();
    for extra in [
        &["--session-response-file", path_text(&response)][..],
        &["--max-template-packets", "5"][..],
        &["--axis", "1.dport=[80,81]"][..],
        &["--session-mss", "0"][..],
    ] {
        let mut arguments = vec![
            "--output",
            "pcap",
            "build",
            "--session",
            "tcp",
            "--packet",
            TCP_SESSION_RECIPE,
            "--link-type",
            "ethernet",
        ];
        arguments.extend_from_slice(extra);
        let output = run(&arguments);
        assert_eq!(output.status.code(), Some(2), "{extra:?}");
        assert!(output.stdout.is_empty(), "{extra:?}");
    }
    // Session options without --session, and the step without capture output.
    for arguments in [
        &[
            "--output",
            "ndjson",
            "build",
            "--packet",
            TCP_SESSION_RECIPE,
            "--session-mss",
            "100",
        ][..],
        &[
            "--output",
            "ndjson",
            "build",
            "--session",
            "tcp",
            "--packet",
            TCP_SESSION_RECIPE,
            "--session-step-ns",
            "5",
        ][..],
    ] {
        let output = run(arguments);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        // NDJSON reports the error as its one record, never as a packet event.
        assert!(!String::from_utf8_lossy(&output.stdout).contains("\"event\":\"packet\""));
    }
    let output = run(&[
        "--output",
        "pcap",
        "build",
        "--session",
        "udp",
        "--packet",
        "ethernet()/ipv4()/udp()",
        "--link-type",
        "ethernet",
        "--session-mss",
        "100",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--session tcp"));
}
