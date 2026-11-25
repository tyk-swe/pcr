// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::fmt::Debug;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn run(args: &[impl AsRef<OsStr> + Debug]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to run packetcraftr {args:?}: {error}"))
}

fn capture_path(name: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures")
        .join(name);
    assert!(
        path.is_file(),
        "example capture missing: {}",
        path.display()
    );
    path
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn assert_success(output: &Output, args: &[impl Debug]) -> String {
    let text = stdout(output);
    assert!(
        output.status.success(),
        "packetcraftr {args:?} should exit 0, got {:?}\nstdout:\n{text}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !text.trim().is_empty(),
        "packetcraftr {args:?} should write non-empty stdout"
    );
    text
}

fn assert_error(output: &Output, expected_code: &str) {
    assert!(
        !output.status.success(),
        "expected {expected_code}, got success:\n{}",
        stdout(output)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "expected JSON error: {error}\nstdout:\n{}\nstderr:\n{}",
                stdout(output),
                String::from_utf8_lossy(&output.stderr)
            )
        });
    assert_eq!(report["error"]["code"], expected_code, "{report}");
}

fn capture_frames(path: &Path) -> Vec<Vec<u8>> {
    let source = std::fs::File::open(path).expect("open capture");
    packetcraftr_core::capture_file::Reader::with_limits(source, Default::default())
        .expect("read capture header")
        .map(|frame| frame.expect("read capture frame").bytes().to_vec())
        .collect()
}

#[test]
fn help_succeeds_with_tool_name() {
    let args = ["--help"];
    let output = run(&args);
    let text = assert_success(&output, &args);
    assert!(
        text.contains("packetcraftr"),
        "--help should name the tool, got:\n{text}"
    );
}

#[test]
fn offline_help_explains_when_machine_output_requires_fields() {
    for (args, expected) in [
        (
            ["files", "read", "--help"],
            [
                "JSON requires at least one --field",
                "streams frame records without --field",
                "rows_written: 0",
            ],
        ),
        (
            ["packet", "dissect", "--help"],
            [
                "NDJSON requires at least one --field",
                "matched: false, dissection: null",
                "rows_written: 0",
            ],
        ),
        (
            ["reference", "topics", "formats"],
            [
                "files read: JSON requires at least one --field",
                "packet dissect: NDJSON requires at least one --field",
                "field projection with --field",
            ],
        ),
    ] {
        let help = assert_success(&run(&args), &args);
        let help = help.split_whitespace().collect::<Vec<_>>().join(" ");
        for detail in expected {
            assert!(help.contains(detail), "{args:?} should explain {detail}");
        }
    }
}

#[test]
fn reference_topics_rejects_machine_output_flags_with_text_output() {
    for (args, expected) in [
        (
            ["reference", "topics", "--resource-diagnostics"].as_slice(),
            "--resource-diagnostics requires --output json or ndjson",
        ),
        (
            ["reference", "topics", "--output-timeout-ms", "20"].as_slice(),
            "--output-timeout-ms requires --output ndjson",
        ),
    ] {
        let output = run(args);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(output.stdout.is_empty(), "{args:?}: {}", stdout(&output));
        assert!(stderr.contains(expected), "{args:?}: {stderr}");
    }
}

#[test]
fn pcapng_output_can_be_read_back() {
    let args = [
        "--output",
        "pcapng",
        "packet",
        "build",
        "--packet",
        "ipv4()/icmpv4(identifier=1)",
        "--link-type",
        "ipv4",
    ];
    let output = run(&args);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let reader = packetcraftr_core::capture_file::Reader::with_limits(
        output.stdout.as_slice(),
        Default::default(),
    )
    .expect("read generated capture header");
    assert_eq!(
        reader.format(),
        packetcraftr_core::capture_file::Format::PcapNg
    );
    let capture = tempfile::NamedTempFile::new().expect("create capture file");
    std::fs::write(capture.path(), &output.stdout).expect("write capture");
    let capture_path = capture.path().to_string_lossy();
    let args = ["--output", "ndjson", "files", "read", capture_path.as_ref()];
    let output = run(&args);
    let text = assert_success(&output, &args);
    let events = text
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("valid NDJSON"))
        .collect::<Vec<_>>();
    assert_eq!(
        events
            .iter()
            .filter(|event| event["event"] == "frame")
            .count(),
        1
    );
}

#[test]
fn invalid_output_format_is_rejected() {
    let args = [
        "--output",
        "pcap-ng",
        "packet",
        "build",
        "--packet",
        "raw(text=hello)",
    ];
    let output = run(&args);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(
        error.contains("pcap-ng") && error.contains("pcapng"),
        "{error}"
    );
}

#[test]
fn raw_build_outputs_packet_bytes() {
    let args = ["packet", "build", "--packet", "raw(text=hello)"];
    let output = run(&args);
    let text = assert_success(&output, &args);
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(
        compact.contains("68656c6c6f"),
        "built bytes should encode \"hello\" (68 65 6c 6c 6f), got:\n{text}"
    );
}

#[test]
fn dns_capture_dissects_successfully() {
    let capture = capture_path("dns-response.pcap");
    let capture = capture.to_string_lossy().into_owned();
    let args = ["files", "read", capture.as_str(), "--dissect"];
    let output = run(&args);
    let text = assert_success(&output, &args);
    assert!(
        text.to_lowercase().contains("dns"),
        "dissected output should identify the DNS layer, got:\n{text}"
    );
}

#[test]
fn hunt_reports_each_indicator_matching_capture_addresses_and_names() {
    let indicators = tempfile::NamedTempFile::new().expect("create indicator file");
    std::fs::write(
        indicators.path(),
        r#"{"schema":"packetcraftr.indicators/v1","indicators":[
            {"id":"server","kind":"ip","value":"192.0.2.53"},
            {"id":"client-net","kind":"cidr","value":"198.51.100.0/24"},
            {"id":"zone","kind":"domain_suffix","value":"Test."},
            {"id":"absent-host","kind":"ip","value":"203.0.113.1"},
            {"id":"absent-name","kind":"domain","value":"other.test"}
        ]}"#,
    )
    .expect("write indicators");
    let capture = capture_path("dns-response.pcap");
    let args = [
        "--output",
        "json",
        "analyze",
        "hunt",
        capture.to_str().unwrap(),
        "--indicators",
        indicators.path().to_str().unwrap(),
    ];
    let output = run(&args);
    assert_success(&output, &args);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON report");
    let matches: std::collections::BTreeSet<_> = report["result"]["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .map(|finding| {
            assert_eq!(finding["rule_id"], "ioc.match");
            (
                finding["indicator_id"].as_str().unwrap().to_owned(),
                finding["subject"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let expected = [
        ("client-net", "198.51.100.8"),
        ("server", "192.0.2.53"),
        ("zone", "example.test."),
        ("zone", "ns.example.test."),
    ]
    .map(|(id, subject)| (id.to_owned(), subject.to_owned()));
    assert_eq!(matches, expected.into());
}

#[test]
fn frame_text_shows_bytes_only_when_verbose_or_as_a_field_tree() {
    let path = capture_path("dns-response.pcap");
    let capture = path.to_string_lossy().into_owned();
    let bytes = capture_frames(&path)
        .first()
        .expect("one captured frame")
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    let read = |extra: &[&str]| {
        let args = [&["files", "read", capture.as_str()], extra].concat();
        assert_success(&run(&args), &args)
    };

    let summary = read(&[]);
    assert!(!summary.contains(&bytes), "{summary}");
    let verbose = read(&["-v"]);
    assert_eq!(
        verbose.trim_end(),
        format!("{} {bytes}", summary.trim_end())
    );

    let decoded = read(&["--dissect"]);
    assert!(decoded.contains("  dns answer: "), "{decoded}");
    assert!(!decoded.contains(&bytes), "{decoded}");
    assert!(!decoded.contains("Decoded fields:"), "{decoded}");

    let decoded_verbose = read(&["--dissect", "-v"]);
    assert!(decoded_verbose.contains(&bytes), "{decoded_verbose}");
    assert!(
        decoded_verbose.contains("  dns answer: "),
        "{decoded_verbose}"
    );
    assert!(
        decoded_verbose.contains("Decoded fields:"),
        "{decoded_verbose}"
    );

    let tree = read(&["--dissect", "--tree"]);
    assert!(tree.contains(&bytes), "{tree}");
    assert!(!tree.contains("  dns answer: "), "{tree}");
    assert!(!tree.contains("Decoded fields:"), "{tree}");
}

#[test]
fn fragment_capture_output_holds_exactly_the_published_fragments() {
    let packet = format!(
        "ipv4(dst=192.0.2.1)/udp(sport=40000,dport=40001)/raw(text={})",
        "a".repeat(200)
    );
    let fragment = |format: &'static str| {
        let args = [
            "--output",
            format,
            "packet",
            "fragment",
            "--packet",
            packet.as_str(),
            "--mtu",
            "68",
        ];
        let output = run(&args);
        assert!(
            output.status.success(),
            "{format}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    };
    let published: serde_json::Value =
        serde_json::from_slice(&fragment("json")).expect("valid JSON");
    let expected = published["result"]["fragments"]
        .as_array()
        .expect("published fragments")
        .iter()
        .map(|fragment| {
            fragment["frame"]["bytes_hex"]
                .as_str()
                .expect("frame bytes")
        })
        .collect::<Vec<_>>();
    assert!(expected.len() > 1, "{published}");

    for format in ["pcap", "pcapng"] {
        let capture = tempfile::NamedTempFile::new().expect("create capture file");
        std::fs::write(capture.path(), fragment(format)).expect("write capture");
        let written = capture_frames(capture.path())
            .iter()
            .map(|frame| frame.iter().map(|byte| format!("{byte:02x}")).collect())
            .collect::<Vec<String>>();
        assert_eq!(written, expected, "{format}");
    }
}

#[test]
fn text_diagnostics_repeat_the_published_severity_code_and_message() {
    let frame = "4500001c0000000040018eaac0000201c63364020800f7ff00000000";
    let dissect = |format: &'static str| {
        let args = [
            "--output",
            format,
            "packet",
            "dissect",
            "--link-type",
            "1",
            "--hex",
            frame,
        ];
        assert_success(&run(&args), &args)
    };
    let published: serde_json::Value = serde_json::from_str(&dissect("json")).expect("valid JSON");
    let diagnostics = published["diagnostics"].as_array().expect("diagnostics");
    assert!(!diagnostics.is_empty(), "{published}");
    let text = dissect("text");
    for diagnostic in diagnostics {
        let line = format!(
            "{} {}: {}",
            diagnostic["severity"].as_str().expect("severity"),
            diagnostic["code"].as_str().expect("code"),
            diagnostic["message"].as_str().expect("message")
        );
        assert!(text.lines().any(|printed| printed == line), "{text}");
    }
}

#[test]
fn forwarding_rule_warnings_are_printed_as_coded_warning_lines() {
    let path = capture_path("http-stream.pcap");
    let capture = path.to_string_lossy().into_owned();
    let verify = |format: &'static str| {
        let args = [
            "--output",
            format,
            "analyze",
            "verify-forwarding",
            capture.as_str(),
            capture.as_str(),
            "--identity",
            "ipv4.identification",
        ];
        assert_success(&run(&args), &args)
    };
    let published: serde_json::Value = serde_json::from_str(&verify("json")).expect("valid JSON");
    let warnings = published["result"]["rules"]["warnings"]
        .as_array()
        .expect("rule warnings");
    assert!(!warnings.is_empty(), "{published}");
    let text = verify("text");
    for warning in warnings {
        let line = format!(
            "warning {}: {}",
            warning["code"].as_str().expect("code"),
            warning["message"].as_str().expect("message")
        );
        assert!(text.lines().any(|printed| printed == line), "{text}");
    }
}

#[test]
fn http_text_prints_the_published_start_line_and_headers() {
    let path = capture_path("http-stream.pcap");
    let capture = path.to_string_lossy().into_owned();
    let json = ["--output", "json", "analyze", "http", capture.as_str()];
    let published: serde_json::Value =
        serde_json::from_str(&assert_success(&run(&json), &json)).expect("valid JSON");
    let request = &published["result"]["messages"][0];
    let verbose = ["-v", "analyze", "http", capture.as_str()];
    let text = assert_success(&run(&verbose), &verbose);
    let start = format!(
        " {} {} ",
        request["start"]["method"].as_str().expect("method"),
        request["start"]["target"].as_str().expect("target")
    );
    assert!(
        text.lines().next().expect("first line").contains(&start),
        "{text}"
    );
    let headers = request["headers"].as_array().expect("headers");
    assert!(!headers.is_empty(), "{published}");
    for header in headers {
        let line = format!(
            "  {}: {}",
            header["name"].as_str().expect("name"),
            header["value"].as_str().expect("value")
        );
        assert!(text.lines().any(|printed| printed == line), "{text}");
    }
}

#[test]
fn dns_capture_text_summary_counts_orphan_responses() {
    let capture = capture_path("dns-response.pcap");
    let capture = capture.to_string_lossy().into_owned();
    let args = ["analyze", "dns", capture.as_str()];
    let output = run(&args);
    let text = assert_success(&output, &args);
    let summary = text
        .lines()
        .find(|line| line.contains(" DNS messages;"))
        .unwrap_or_else(|| panic!("missing DNS analysis summary:\n{text}"));
    assert!(
        summary
            .split("; ")
            .any(|field| field == "orphan responses: 1"),
        "{summary}"
    );
}

#[test]
fn dns_analysis_preserves_mdns_cache_flush_record_values() {
    use packetcraftr_core::build::Builder;
    use packetcraftr_core::capture_file::{Format, Writer};
    use packetcraftr_core::frame::{Frame, LinkType};
    use packetcraftr_core::layer::Raw;
    use packetcraftr_core::packet::Packet;
    use packetcraftr_core::protocol::application::dns::Dns;
    use packetcraftr_core::protocol::{
        builtin,
        link::Ethernet,
        network::Ipv4,
        transport::{Tcp, Udp},
    };
    use std::time::UNIX_EPOCH;

    // RFC 6762 section 10.2, checked 2026-11-12, defines the mDNS cache-flush class bit.
    let wire = [
        0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 4, b'h', b'o', b's', b't', 5, b'l', b'o', b'c',
        b'a', b'l', 0, 0, 1, 0x80, 1, 0, 0, 0, 120, 0, 4, 192, 0, 2, 9,
    ];
    let directory = tempfile::tempdir().unwrap();
    for (source, destination, tcp, kind) in [
        (5353, 5353, false, "a"),
        (5353, 40000, false, "a"),
        (40000, 5353, false, "a"),
        (53, 40000, false, "unknown"),
        (5355, 40000, false, "unknown"),
        (53, 5353, false, "unknown"),
        (5353, 53, false, "unknown"),
        (5353, 5355, false, "unknown"),
        (5353, 8053, false, "unknown"),
        (8053, 5353, false, "a"),
        (5353, 40000, true, "unknown"),
    ] {
        let mut packet = Packet::default();
        packet.push(Ethernet::default());
        packet.push(Ipv4 {
            source: "192.0.2.1".parse().unwrap(),
            destination: "224.0.0.251".parse().unwrap(),
            ..Default::default()
        });
        if tcp {
            packet.push(Tcp {
                source_port: source,
                destination_port: destination,
                flags: Tcp::ACK,
                ..Default::default()
            });
            let mut framed = (wire.len() as u16).to_be_bytes().to_vec();
            framed.extend_from_slice(&wire);
            packet.push(Raw::new(framed));
        } else {
            packet.push(Udp {
                source_port: source,
                destination_port: destination,
                ..Default::default()
            });
            packet.push(Dns::try_from(wire.to_vec()).unwrap());
        }
        let built = Builder::new(builtin::registry())
            .build(packet, Default::default(), Default::default())
            .unwrap();
        let path = directory
            .path()
            .join(format!("dns-{source}-{destination}-{tcp}.pcap"));
        let mut writer = Writer::new(
            std::fs::File::create(&path).unwrap(),
            Format::Pcap,
            LinkType::ETHERNET,
        )
        .unwrap();
        writer
            .write_frame(&Frame::new(Some(UNIX_EPOCH), LinkType::ETHERNET, built.bytes).unwrap())
            .unwrap();
        writer.flush().unwrap();
        let path = path.to_str().unwrap();
        let args = [
            "--output",
            "json",
            "analyze",
            "dns",
            path,
            "--dns-port",
            "5353",
            "--dns-port",
            "5355",
            "--dns-port",
            "8053",
            "--decode-as",
            "udp.port=8053:dns",
        ];
        let report: serde_json::Value =
            serde_json::from_str(&assert_success(&run(&args), &args)).unwrap();
        let message = &report["result"]["messages"][0];
        assert_eq!(message["status"], "complete", "{report}");
        let record = &message["fields"]["answers"]["value"][0]["value"];
        assert_eq!(record["class"]["value"], 0x8001, "{report}");
        let value = &record["value"]["value"];
        assert_eq!(
            value["kind"]["value"], kind,
            "ports {source}/{destination}: {report}"
        );
        if kind == "a" {
            assert_eq!(value["address"]["value"], "192.0.2.9", "{report}");
        }
    }
}

#[test]
fn capture_field_projection_preserves_rows_across_output_formats() {
    let path = capture_path("protocol-mqtt.pcap");
    let frames = capture_frames(&path);
    let capture = path.to_string_lossy().into_owned();
    let mut args = [
        "--output",
        "json",
        "files",
        "read",
        capture.as_str(),
        "--field",
        "frame.number",
        "--field",
        "frame.len",
    ];
    let output = run(&args);
    let text = assert_success(&output, &args);
    let aggregate: serde_json::Value = serde_json::from_str(&text).unwrap();
    let expected_rows: Vec<_> = frames.iter().enumerate().map(|(index, bytes)| {
        serde_json::json!({"source_frame": index + 1, "values": [index + 1, bytes.len()]})
    }).collect();
    assert_eq!(
        aggregate["schema"],
        packetcraftr_cli::output::contract::OUTPUT_SCHEMA
    );
    assert_eq!(aggregate["status"], "success");
    assert_eq!(
        aggregate["result"]["rows"],
        serde_json::json!(expected_rows)
    );
    assert_eq!(
        aggregate["result"]["columns"],
        serde_json::json!(["frame.number", "frame.len"])
    );
    assert_eq!(aggregate["result"]["rows_written"], frames.len());
    assert_eq!(aggregate["result"]["frames_read"], frames.len());
    assert_eq!(
        aggregate["result"]["captured_bytes_read"],
        frames.iter().map(Vec::len).sum::<usize>()
    );

    args[1] = "ndjson";
    let output = run(&args);
    let text = assert_success(&output, &args);
    let records: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), expected_rows.len() + 1);
    for (record, row) in records.iter().zip(&expected_rows) {
        assert_eq!(record["event"], "fields");
        assert_eq!(record["result"]["columns"], aggregate["result"]["columns"]);
        assert_eq!(record["result"]["source_frame"], row["source_frame"]);
        assert_eq!(record["result"]["values"], row["values"]);
    }
    let terminal = records.last().unwrap();
    assert_eq!(terminal["event"], "complete");
    for key in [
        "columns",
        "rows_written",
        "frames_read",
        "captured_bytes_read",
    ] {
        assert_eq!(terminal["result"][key], aggregate["result"][key]);
    }

    args[1] = "text";
    let output = run(&args);
    let text = assert_success(&output, &args);
    let expected = std::iter::once("frame.number\tframe.len\n".to_owned())
        .chain(
            frames
                .iter()
                .enumerate()
                .map(|(index, bytes)| format!("{}\t{}\n", index + 1, bytes.len())),
        )
        .collect::<String>();
    assert_eq!(text, expected);
}

#[test]
fn read_and_dissect_resource_diagnostics_report_active_rendering_limits() {
    let path = capture_path("dns-response.pcap");
    let capture = path.to_string_lossy();
    let read = ["files", "read", capture.as_ref()];
    let dissect = [
        "packet",
        "dissect",
        "--link-type",
        "ipv4",
        "--hex",
        "4500001c0000000040018eaac0000201c63364020800f7ff00000000",
    ];
    let selections = [["--field", "frame.number"].as_slice(), &[]];
    for (format, command) in [("ndjson", read.as_slice()), ("json", dissect.as_slice())] {
        for fields in selections {
            let args = ["--output", format, "--resource-diagnostics"]
                .into_iter()
                .chain(command.iter().copied())
                .chain(fields.iter().copied())
                .collect::<Vec<_>>();
            let text = assert_success(&run(&args), &args);
            let result: serde_json::Value = if format == "ndjson" {
                serde_json::from_str(text.lines().last().unwrap()).unwrap()
            } else {
                serde_json::from_str(&text).unwrap()
            };
            assert_eq!(result["status"], "success", "{result}");
            let selected = !fields.is_empty();
            assert_eq!(
                result["result"].get("columns").is_some(),
                selected,
                "{result}"
            );
            let settings = result["resources"]["settings"].as_array().unwrap();
            for (name, enabled) in [
                ("--max-projection-bytes", selected),
                ("--max-tree-bytes", false),
            ] {
                let setting = settings
                    .iter()
                    .find(|setting| setting["name"] == name)
                    .unwrap_or_else(|| panic!("missing resource setting {name} in {result}"));
                assert_eq!(setting["enabled"], enabled, "{args:?}: {setting}");
            }
        }
    }
}

#[test]
fn projection_ndjson_budget_counts_row_payload_and_rejects_unpublished_rows() {
    let path = capture_path("protocol-mqtt.pcap");
    let capture = path.to_string_lossy().into_owned();
    let base = [
        "--output",
        "ndjson",
        "files",
        "read",
        capture.as_str(),
        "--field",
        "frame.number",
        "--filter",
        "frame.number == 1",
    ];
    let output = run(&base);
    let text = assert_success(&output, &base);
    let first: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    assert_eq!(first["event"], "fields");
    let row_bytes = serde_json::to_vec(&first["result"]).unwrap().len();
    for (maximum, succeeds) in [(row_bytes, true), (row_bytes - 1, false)] {
        let maximum = maximum.to_string();
        let args = base
            .iter()
            .copied()
            .chain(["--max-projection-bytes", maximum.as_str()])
            .collect::<Vec<_>>();
        let output = run(&args);
        let text = stdout(&output);
        let records: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(output.status.success(), succeeds, "{text}");
        if succeeds {
            assert_eq!(records.len(), 2);
            assert_eq!(records[0]["result"], first["result"]);
            assert_eq!(records[1]["event"], "complete");
            continue;
        }
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["event"], "error");
        assert_eq!(records[0]["error"]["code"], "policy.projection_limit");
    }
}

#[test]
fn projection_json_budget_is_the_sum_of_every_retained_row() {
    let path = capture_path("http-stream.pcap");
    let capture = path.to_string_lossy().into_owned();
    let base = [
        "--output",
        "json",
        "files",
        "read",
        capture.as_str(),
        "--field",
        "frame.number",
        "--filter",
        "frame.number <= 2",
    ];
    let output = run(&base);
    let document: serde_json::Value =
        serde_json::from_str(&assert_success(&output, &base)).expect("valid JSON");
    let rows = document["result"]["rows"].as_array().expect("rows");
    assert_eq!(rows.len(), 2);
    let row_bytes = rows
        .iter()
        .map(|row| serde_json::to_vec(row).unwrap().len())
        .sum::<usize>();
    for (maximum, succeeds) in [(row_bytes, true), (row_bytes - 1, false)] {
        let maximum = maximum.to_string();
        let args = base
            .iter()
            .copied()
            .chain(["--max-projection-bytes", maximum.as_str()])
            .collect::<Vec<_>>();
        let output = run(&args);
        let limited: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("valid JSON");
        assert_eq!(output.status.success(), succeeds, "{limited}");
        if succeeds {
            assert_eq!(limited["result"]["rows"], document["result"]["rows"]);
            continue;
        }
        assert_eq!(limited["error"]["code"], "policy.projection_limit");
    }
}

#[test]
fn files_read_floors_fractional_pcapng_timestamps_only_for_display() {
    use packetcraftr_core::capture_file::{Interface, TimestampResolution, Writer};
    use packetcraftr_core::frame::{Frame, LinkType};
    use std::time::{Duration, UNIX_EPOCH};

    let packet = capture_frames(&capture_path("dns-response.pcap")).remove(0);
    let file = tempfile::NamedTempFile::new().unwrap();
    let path = file.path().to_str().unwrap();
    for (resolution, offset, ticks, expected_nanos, exact) in [
        (TimestampResolution::Binary(10), 123, 1_u64, 976_562, false),
        (TimestampResolution::Binary(10), 123, 128, 125_000_000, true),
        (TimestampResolution::Binary(10), -1, 1, 976_562, false),
        (TimestampResolution::Decimal(10), 123, 19, 1, false),
        (TimestampResolution::Decimal(127), 123, u64::MAX, 0, false),
        (TimestampResolution::Decimal(127), 123, 0, 0, true),
    ] {
        let mut writer = Writer::pcapng_with_options(Vec::new(), Default::default()).unwrap();
        let interface = writer
            .add_interface_description_with_options(
                Interface {
                    link_type: LinkType::IPV4,
                    snap_len: 65_535,
                    timestamp_resolution: resolution,
                    timestamp_offset: offset,
                },
                &[],
            )
            .unwrap();
        let seconds = Duration::from_secs(offset.unsigned_abs());
        let time_at_zero_ticks = if offset < 0 {
            UNIX_EPOCH - seconds
        } else {
            UNIX_EPOCH + seconds
        };
        let mut frame =
            Frame::new(Some(time_at_zero_ticks), LinkType::IPV4, packet.clone()).unwrap();
        frame.interface = Some(interface);
        let enhanced = writer.get_ref().len();
        writer.write_frame(&frame).unwrap();
        let mut capture = writer.into_inner();
        let mut wire_ticks = ticks.to_le_bytes();
        wire_ticks.rotate_left(4);
        capture[enhanced + 12..enhanced + 20].copy_from_slice(&wire_ticks);
        std::fs::write(path, &capture).unwrap();

        let args = ["--output", "ndjson", "files", "read", path];
        let output = run(&args);
        let text = assert_success(&output, &args);
        let record: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(record["event"], "frame");
        let fraction = Duration::from_nanos(expected_nanos);
        let expected_nanos = if offset < 0 {
            let before_epoch = (UNIX_EPOCH - (seconds - fraction))
                .duration_since(UNIX_EPOCH)
                .unwrap_err()
                .duration();
            (1_000_000_000 - before_epoch.subsec_nanos()) % 1_000_000_000
        } else {
            (UNIX_EPOCH + (seconds + fraction))
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        };
        assert_eq!(
            record["result"]["frame"]["timestamp"]["unix_seconds"],
            offset,
        );
        assert_eq!(
            record["result"]["frame"]["timestamp"]["nanoseconds"],
            expected_nanos
        );
        assert_eq!(record["result"]["frame"]["captured_length"], packet.len());

        for flags in [&[][..], &["--normalize"][..]] {
            let args = ["--output", "pcapng", "files", "read", path]
                .into_iter()
                .chain(flags.iter().copied())
                .collect::<Vec<_>>();
            let output = run(&args);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.success(), exact, "{args:?}: {stderr}");
            if exact && flags.is_empty() {
                assert_eq!(output.stdout, capture);
            } else if !exact {
                assert!(stderr.contains("sub-nanosecond timestamp"), "{stderr}");
            }
        }
    }
}

#[test]
fn files_read_missing_capture_exits_nonzero() {
    let missing = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/missing-offline-corpus.pcap");
    assert!(
        !missing.exists(),
        "failure-case path must not exist: {}",
        missing.display()
    );
    let missing = missing.to_string_lossy().into_owned();
    let args = ["files", "read", missing.as_str(), "--dissect"];
    let output = run(&args);
    assert!(
        !output.status.success(),
        "packetcraftr {args:?} should exit non-zero for a missing input file, got {:?}\nstdout:\n{}",
        output.status.code(),
        stdout(&output)
    );
    assert!(
        !output.stderr.is_empty(),
        "packetcraftr {args:?} should explain the failure on stderr"
    );
}

#[test]
fn files_merge_honors_capture_limits() {
    let source = capture_path("dns-response.pcap");
    let source_frames = capture_frames(&source);
    assert!(!source_frames.is_empty());
    let source_size = std::fs::metadata(&source).unwrap().len().to_string();
    let source = source.to_str().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let merged = dir.path().join("merged.pcapng");
    let command = [
        "--output", "json", "files", "merge", source, source, "--order", "append",
    ];
    let args = [
        &command[..],
        &[
            "--write",
            merged.to_str().unwrap(),
            "--max-frame-bytes",
            "65536",
            "--max-bytes",
            "65536",
            "--max-encoded-bytes",
            &source_size,
            "--max-decoded-bytes",
            &source_size,
            "--max-interfaces",
            "1",
        ],
    ]
    .concat();
    assert_success(&run(&args), &args);
    let expected: Vec<_> = source_frames
        .iter()
        .chain(&source_frames)
        .cloned()
        .collect();
    assert_eq!(capture_frames(&merged), expected);

    let failures: [(&[&str], &str); 2] = [
        (
            &["--max-encoded-bytes", "0"],
            "packet.capture_compression_limit",
        ),
        (
            &["--max-frame-bytes", "2", "--max-bytes", "1"],
            "cli.capture_limit",
        ),
    ];
    for (index, (limits, code)) in failures.iter().enumerate() {
        let destination = dir.path().join(format!("rejected-merge-{index}.pcapng"));
        let args = [
            &command[..],
            &["--write", destination.to_str().unwrap()],
            limits,
        ]
        .concat();
        assert_error(&run(&args), code);
        assert!(!destination.exists());
    }
}

fn write_merge_source(
    path: &Path,
    source: usize,
    times: &[u64],
    format: packetcraftr_core::capture_file::Format,
) {
    use packetcraftr_core::capture_file::Writer;
    use packetcraftr_core::frame::{Frame, LinkType};
    use std::time::{Duration, UNIX_EPOCH};

    let mut writer = Writer::new(
        std::fs::File::create(path).unwrap(),
        format,
        LinkType::ETHERNET,
    )
    .unwrap();
    for (number, &time) in times.iter().enumerate() {
        let frame = Frame::new(
            Some(UNIX_EPOCH + Duration::from_micros(time)),
            LinkType::ETHERNET,
            vec![u8::try_from(source).unwrap(), u8::try_from(number).unwrap()],
        )
        .unwrap();
        writer.write_frame(&frame).unwrap();
    }
    writer.flush().unwrap();
}

#[test]
fn files_merge_preserves_order_and_provenance() {
    use packetcraftr_core::capture_file::{Format, MAX_MERGE_SOURCES, Reader};
    use std::time::{Duration, UNIX_EPOCH};

    let cases = [
        (
            "chronological",
            0,
            vec![
                vec![],
                vec![1, 2, 2, 7],
                vec![],
                vec![1, 2, 3],
                vec![2],
                vec![],
            ],
        ),
        ("chronological", 0, vec![vec![1, 1]; MAX_MERGE_SOURCES]),
        ("chronological", 0, vec![vec![], vec![]]),
        ("chronological", 2, vec![vec![2, 1, 2, 4, 3], vec![1, 3, 3]]),
        ("append", 0, vec![vec![], vec![3, 1, 1], vec![2, 1], vec![]]),
    ];
    for (order, window, sources) in cases {
        let dir = tempfile::tempdir().unwrap();
        let paths: Vec<_> = sources
            .iter()
            .enumerate()
            .map(|(source, times)| {
                let path = dir.path().join(format!("source-{source}"));
                let format = if source % 2 == 0 {
                    Format::Pcap
                } else {
                    Format::PcapNg
                };
                write_merge_source(&path, source, times, format);
                path
            })
            .collect();
        let destination = dir.path().join("merged.pcapng");
        let window = window.to_string();
        let args: Vec<_> = ["--output", "json", "files", "merge"]
            .into_iter()
            .chain(paths.iter().map(|path| path.to_str().unwrap()))
            .chain([
                "--write",
                destination.to_str().unwrap(),
                "--order",
                order,
                "--max-reorder-frames",
                &window,
            ])
            .collect();
        let report: serde_json::Value =
            serde_json::from_str(&assert_success(&run(&args), &args)).unwrap();
        let result = &report["result"];
        let mut expected: Vec<_> = sources
            .iter()
            .enumerate()
            .flat_map(|(source, times)| {
                times
                    .iter()
                    .enumerate()
                    .map(move |(number, &time)| (time, source, number))
            })
            .collect();
        if order == "chronological" {
            expected.sort_unstable();
        }
        let frames: Vec<_> = Reader::with_limits(
            std::fs::File::open(&destination).unwrap(),
            Default::default(),
        )
        .unwrap()
        .map(Result::unwrap)
        .collect();
        assert_eq!(frames.len(), expected.len());
        assert_eq!(result["frames"], frames.len());
        assert_eq!(
            result["captured_bytes"],
            frames
                .iter()
                .map(|frame| u64::from(frame.captured_length()))
                .sum::<u64>()
        );
        assert_eq!(
            result["source_frames"],
            serde_json::json!(sources.iter().map(Vec::len).collect::<Vec<_>>())
        );
        let interfaces = result["interfaces"].as_array().unwrap();
        assert_eq!(
            interfaces.len(),
            sources.iter().filter(|times| !times.is_empty()).count()
        );
        for (frame, (time, source, number)) in frames.iter().zip(expected) {
            assert_eq!(
                frame.timestamp,
                Some(UNIX_EPOCH + Duration::from_micros(time))
            );
            assert_eq!(
                frame.bytes().as_ref(),
                &[u8::try_from(source).unwrap(), u8::try_from(number).unwrap()]
            );
            let interface = interfaces
                .iter()
                .find(|interface| interface["output_interface"] == frame.interface.unwrap())
                .unwrap();
            assert_eq!(interface["source"], source);
            assert_eq!(interface["source_name"], paths[source].to_str().unwrap());
            assert_eq!(interface["global_interface"], 0);
        }
    }
}

#[test]
fn merge_rejects_clock_regression_before_publication() {
    use packetcraftr_core::capture_file::Format;

    for (times, window) in [(vec![2, 1], "0"), (vec![2, 3, 1], "2")] {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first.pcap");
        let second = dir.path().join("second.pcapng");
        let destination = dir.path().join("rejected.pcapng");
        write_merge_source(&first, 0, &times, Format::Pcap);
        write_merge_source(&second, 1, &[1, 4], Format::PcapNg);
        let args = [
            "--output",
            "json",
            "files",
            "merge",
            first.to_str().unwrap(),
            second.to_str().unwrap(),
            "--write",
            destination.to_str().unwrap(),
            "--max-reorder-frames",
            window,
        ];
        assert_error(&run(&args), "packet.capture_merge_order");
        assert!(!destination.exists());
    }
}

fn merge_source<'a>(
    name: &str,
    capture: &'a [u8],
) -> packetcraftr_core::capture_file::MergeSource<&'a [u8]> {
    use packetcraftr_core::capture_file::{MergeSource, Reader};

    MergeSource {
        name: name.to_owned(),
        reader: Reader::with_limits(capture, Default::default()).unwrap(),
    }
}

#[test]
fn merge_honors_source_count_and_name_limits() {
    use packetcraftr_core::capture_file::{Error, MAX_MERGE_SOURCES, MergeLimits, Writer, merge};

    let capture = Writer::pcapng_with_options(Vec::new(), Default::default())
        .unwrap()
        .into_inner();
    let longest_name = "é".repeat(2048);
    let long_name = format!("{longest_name}x");
    let limits = MergeLimits {
        max_sources: 1,
        ..Default::default()
    };
    let mut output = Writer::pcapng_with_options(Vec::new(), Default::default()).unwrap();
    let report = merge(
        &mut [merge_source(&longest_name, &capture)],
        &mut output,
        limits,
    )
    .unwrap();
    assert_eq!(report.source_frames, [0]);

    for mut sources in [
        vec![],
        vec![
            merge_source("first", &capture),
            merge_source("second", &capture),
        ],
        vec![merge_source(&long_name, &capture)],
    ] {
        assert!(matches!(
            merge(&mut sources, &mut output, limits),
            Err(Error::MergeSources { maximum: 1 })
        ));
    }
    for max_sources in [0, MAX_MERGE_SOURCES + 1] {
        assert!(matches!(
            merge(
                &mut [merge_source("source", &capture)],
                &mut output,
                MergeLimits {
                    max_sources,
                    ..limits
                },
            ),
            Err(Error::MergeSources {
                maximum: MAX_MERGE_SOURCES
            })
        ));
    }
}

#[test]
fn merge_validates_order_options_and_requires_pcapng_output() {
    use packetcraftr_core::capture_file::{
        Error, Format, MAX_REORDER_FRAMES, MergeLimits, MergeOrder, Writer, merge,
    };
    use packetcraftr_core::frame::LinkType;

    let capture = Writer::pcapng_with_options(Vec::new(), Default::default())
        .unwrap()
        .into_inner();
    let mut output = Writer::pcapng_with_options(Vec::new(), Default::default()).unwrap();
    let merge_with_order = |output: &mut Writer<Vec<u8>>, order, max_reorder_frames| {
        merge(
            &mut [merge_source("source", &capture)],
            output,
            MergeLimits {
                order,
                max_reorder_frames,
                ..Default::default()
            },
        )
    };
    merge_with_order(&mut output, MergeOrder::Chronological, MAX_REORDER_FRAMES).unwrap();
    for (order, window) in [
        (MergeOrder::Chronological, MAX_REORDER_FRAMES + 1),
        (MergeOrder::Append, 1),
    ] {
        assert!(matches!(
            merge_with_order(&mut output, order, window),
            Err(Error::MergeOption(_))
        ));
    }
    let mut classic = Writer::new(Vec::new(), Format::Pcap, LinkType::ETHERNET).unwrap();
    assert!(matches!(
        merge_with_order(&mut classic, MergeOrder::Chronological, 0),
        Err(Error::WrongWriterFormat {
            expected: Format::PcapNg,
            actual: Format::Pcap
        })
    ));
}

#[test]
fn merge_counts_interfaces_across_capture_formats() {
    use packetcraftr_core::capture_file::{Error, Format, MergeLimits, Writer, merge};
    use packetcraftr_core::frame::LinkType;

    let classic = Writer::new(Vec::new(), Format::Pcap, LinkType::ETHERNET)
        .unwrap()
        .into_inner();
    let pcapng = Writer::new(Vec::new(), Format::PcapNg, LinkType::ETHERNET)
        .unwrap()
        .into_inner();
    for second in [&classic, &pcapng] {
        let merge_with_limit = |max_interfaces| {
            let mut output = Writer::pcapng_with_options(Vec::new(), Default::default()).unwrap();
            merge(
                &mut [
                    merge_source("first", &classic),
                    merge_source("second", second),
                ],
                &mut output,
                MergeLimits {
                    max_interfaces,
                    ..Default::default()
                },
            )
        };
        assert_eq!(merge_with_limit(2).unwrap().source_frames, [0, 0]);
        assert!(matches!(
            merge_with_limit(1),
            Err(Error::TotalInterfaceLimit { limit: 1 })
        ));
    }
}

fn merge_pcapng_section(
    endianness: packetcraftr_core::capture_file::Endianness,
    frame: &packetcraftr_core::frame::Frame,
    fcs_bits: u8,
) -> Vec<u8> {
    use packetcraftr_core::capture_file::{
        Interface, PcapNgOption, PcapNgOptions, TimestampResolution, Writer,
    };

    const IF_FCS_LENGTH_OPTION: u16 = 13;

    let mut writer = Writer::pcapng_with_options(
        Vec::new(),
        PcapNgOptions {
            endianness,
            ..Default::default()
        },
    )
    .unwrap();
    writer
        .add_interface_description_with_options(
            Interface {
                link_type: frame.link_type,
                snap_len: 128,
                timestamp_resolution: TimestampResolution::Decimal(9),
                timestamp_offset: 0,
            },
            &[PcapNgOption {
                code: IF_FCS_LENGTH_OPTION,
                value: vec![fcs_bits].into(),
            }],
        )
        .unwrap();
    writer.write_frame(frame).unwrap();
    writer.into_inner()
}

#[test]
fn merge_preserves_frames_and_interface_provenance_across_sections() {
    use packetcraftr_core::capture_file::{
        Endianness, MetadataBlockKind, Reader, RecordKind, Writer, merge,
    };
    use packetcraftr_core::frame::{Direction, Frame, LinkType};
    use std::time::{Duration, UNIX_EPOCH};

    const COMMENT_OPTION: u16 = 1;

    let cases = [
        (
            Endianness::Little,
            Direction::Inbound,
            LinkType::ETHERNET,
            1,
        ),
        (Endianness::Big, Direction::Outbound, LinkType::RAW, 2),
    ];
    let frames = cases.map(|(_, direction, link_type, marker)| {
        let mut frame = Frame::new(
            Some(UNIX_EPOCH + Duration::from_secs(u64::from(marker))),
            link_type,
            vec![marker],
        )
        .unwrap();
        frame.direction = Some(direction);
        frame
    });
    let capture = cases
        .into_iter()
        .zip(&frames)
        .flat_map(|((endianness, ..), frame)| merge_pcapng_section(endianness, frame, 0))
        .collect::<Vec<_>>();
    let mut output = Writer::pcapng_with_options(Vec::new(), Default::default()).unwrap();
    let report = merge(
        &mut [merge_source("mixed", &capture)],
        &mut output,
        Default::default(),
    )
    .unwrap();
    assert_eq!(report.source_metadata_records, 3);
    assert_eq!(report.interfaces.len(), frames.len());

    let bytes = output.into_inner();
    let mut reader = Reader::with_limits(bytes.as_slice(), Default::default()).unwrap();
    let records: Vec<_> = std::iter::from_fn(|| reader.next_record().unwrap()).collect();
    let interfaces: Vec<_> = records
        .iter()
        .filter_map(|record| match &record.kind {
            RecordKind::Metadata(MetadataBlockKind::InterfaceDescription {
                global_id,
                options,
                ..
            }) => Some((*global_id, options)),
            _ => None,
        })
        .collect();
    assert_eq!(interfaces.len(), frames.len());
    let actual_frames: Vec<_> = records
        .iter()
        .filter_map(|record| record.frame.as_ref())
        .collect();
    assert_eq!(actual_frames.len(), frames.len());
    for (section, (actual, mut expected)) in actual_frames.into_iter().zip(frames).enumerate() {
        let output_id = actual.interface.unwrap();
        let mapping = report
            .interfaces
            .iter()
            .find(|mapping| mapping.output_interface == output_id)
            .unwrap();
        let (_, options) = interfaces.iter().find(|(id, _)| *id == output_id).unwrap();
        assert_eq!(mapping.source, 0);
        assert_eq!(mapping.source_name, "mixed");
        assert_eq!(mapping.section, Some(u64::try_from(section).unwrap()));
        assert_eq!(mapping.local_interface, Some(0));
        assert_eq!(mapping.global_interface, u32::try_from(section).unwrap());
        let comment = options
            .iter()
            .find(|option| option.code == COMMENT_OPTION)
            .unwrap();
        let provenance: serde_json::Value = serde_json::from_slice(&comment.value).unwrap();
        assert_eq!(
            provenance,
            serde_json::json!({
                "schema": "packetcraftr.capture-source/v1",
                "source": mapping.source,
                "source_name": mapping.source_name,
                "section": mapping.section,
                "local_interface": mapping.local_interface,
                "global_interface": mapping.global_interface,
            })
        );

        expected.interface = Some(mapping.output_interface);
        assert_eq!(actual, &expected);
    }
}

#[test]
fn merge_rejects_fcs_declared_in_a_later_section() {
    use packetcraftr_core::capture_file::{Endianness, Error, Writer, merge};
    use packetcraftr_core::frame::{Frame, LinkType};
    use std::time::UNIX_EPOCH;

    let frame = Frame::new(Some(UNIX_EPOCH), LinkType::ETHERNET, vec![1]).unwrap();
    let capture = [
        merge_pcapng_section(Endianness::Little, &frame, 0),
        merge_pcapng_section(Endianness::Little, &frame, 32),
    ]
    .concat();
    let mut output = Writer::pcapng_with_options(Vec::new(), Default::default()).unwrap();
    assert!(matches!(
        merge(
            &mut [merge_source("source", &capture)],
            &mut output,
            Default::default(),
        ),
        Err(Error::MergeMetadata {
            input: 0,
            field: "declared frame check sequence"
        })
    ));
}

#[test]
fn files_export_honors_capture_limits() {
    let source = capture_path("dns-response.pcap");
    let source_frames = capture_frames(&source);
    assert!(!source_frames.is_empty());
    let source_size = std::fs::metadata(&source).unwrap().len().to_string();
    let source = source.to_str().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let exported = dir.path().join("exported.pcap");
    let command = [
        "--output", "json", "files", "export", source, "--filter", "dns",
    ];
    let args = [
        &command[..],
        &[
            "--write",
            exported.to_str().unwrap(),
            "--max-frame-bytes",
            "65536",
            "--max-bytes",
            "65536",
            "--max-encoded-bytes",
            &source_size,
            "--max-decoded-bytes",
            &source_size,
            "--max-interfaces",
            "1",
        ],
    ]
    .concat();
    assert_success(&run(&args), &args);
    assert_eq!(capture_frames(&exported), source_frames);

    let failures: [(&[&str], &str); 2] = [
        (
            &["--max-decoded-bytes", "0"],
            "packet.capture_compression_limit",
        ),
        (&["--max-interfaces", "0"], "cli.capture_limit"),
    ];
    for (index, (limits, code)) in failures.iter().enumerate() {
        let destination = dir.path().join(format!("rejected-export-{index}.pcap"));
        let args = [
            &command[..],
            &["--write", destination.to_str().unwrap()],
            limits,
        ]
        .concat();
        assert_error(&run(&args), code);
        assert!(!destination.exists());
    }
}

#[test]
fn files_export_keeps_dependencies_of_earlier_fragment_matches() {
    use packetcraftr_core::build::Builder;
    use packetcraftr_core::capture_file::{Format, Writer};
    use packetcraftr_core::frame::{Frame, LinkType};
    use packetcraftr_core::layer::Raw;
    use packetcraftr_core::packet::Packet;
    use packetcraftr_core::protocol::{
        builtin,
        link::Ethernet,
        network::{Ipv4, Ipv6},
        transport::Udp,
    };
    use packetcraftr_core::transform::{FragmentOptions, fragment};
    use std::time::UNIX_EPOCH;

    for ipv6 in [false, true] {
        let mut packet = Packet::default();
        packet.push(Ethernet::default());
        if ipv6 {
            packet.push(Ipv6 {
                source: "2001:db8::1".parse().unwrap(),
                destination: "2001:db8::2".parse().unwrap(),
                ..Default::default()
            });
        } else {
            packet.push(Ipv4 {
                source: "192.0.2.1".parse().unwrap(),
                destination: "192.0.2.2".parse().unwrap(),
                ..Default::default()
            });
        }
        packet.push(Udp {
            source_port: 40000,
            destination_port: 40001,
            ..Default::default()
        });
        packet.push(Raw::new(vec![0xa5; 32]));
        let built = Builder::new(builtin::registry())
            .build(packet, Default::default(), Default::default())
            .unwrap();
        let original = Frame::new(Some(UNIX_EPOCH), LinkType::ETHERNET, built.bytes).unwrap();
        let fragments = fragment(
            &original,
            FragmentOptions {
                mtu: if ipv6 { 64 } else { 36 },
                identification: Some(1),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(fragments.len() > 2);

        for format in [Format::Pcap, Format::PcapNg] {
            for reverse in [false, true] {
                for incomplete in [false, true] {
                    let directory = tempfile::tempdir().unwrap();
                    let source = directory.path().join("fragments.pcap");
                    let destination = directory.path().join("exported.pcap");
                    let mut selected = fragments.clone();
                    if incomplete {
                        selected.pop();
                    }
                    if reverse {
                        selected.reverse();
                    }
                    let expected: Vec<_> = selected
                        .iter()
                        .map(|frame| frame.bytes().to_vec())
                        .collect();
                    let numbers: Vec<_> = (0..selected.len())
                        .map(|index| if index == 0 { 1 } else { index + 2 })
                        .collect();
                    selected.insert(1, original.clone());
                    let mut writer = Writer::new(
                        std::fs::File::create(&source).unwrap(),
                        format,
                        LinkType::ETHERNET,
                    )
                    .unwrap();
                    for frame in selected {
                        writer.write_frame(&frame).unwrap();
                    }
                    writer.flush().unwrap();
                    let args = [
                        "--output",
                        "json",
                        "files",
                        "export",
                        source.to_str().unwrap(),
                        "--filter",
                        "frame.number == 1",
                        "--write",
                        destination.to_str().unwrap(),
                    ];
                    let report: serde_json::Value =
                        serde_json::from_str(&assert_success(&run(&args), &args)).unwrap();
                    assert_eq!(
                        report["result"]["source_frames"],
                        serde_json::json!(numbers),
                        "ipv6={ipv6}, format={format}, reverse={reverse}, incomplete={incomplete}"
                    );
                    assert_eq!(capture_frames(&destination), expected);
                    assert_eq!(
                        report["result"]["selected_complete_datagrams"],
                        u64::from(!incomplete)
                    );
                    assert_eq!(
                        report["result"]["selected_incomplete_datagrams"]
                            .as_array()
                            .unwrap()
                            .len(),
                        usize::from(incomplete)
                    );

                    let refused = directory.path().join("refused.pcap");
                    let limit = (expected.len() - 1).to_string();
                    let args = [
                        &args[..7],
                        &[
                            "--write",
                            refused.to_str().unwrap(),
                            "--max-selected-frames",
                            &limit,
                        ],
                    ]
                    .concat();
                    assert_error(&run(&args), "policy.export_limit");
                    assert!(!refused.exists());
                }
            }
        }
    }
}

#[test]
fn forwarding_limits_apply_to_both_inputs() {
    let ingress = capture_path("dns-response.pcap");
    let egress = capture_path("http-stream.pcap");
    let ingress_size = std::fs::metadata(&ingress).unwrap().len();
    assert!(std::fs::metadata(&egress).unwrap().len() > ingress_size);
    let limit = ingress_size.to_string();
    let ingress = ingress.to_str().unwrap();
    let egress = egress.to_str().unwrap();
    let args = [
        "--output",
        "json",
        "analyze",
        "verify-forwarding",
        ingress,
        ingress,
        "--identity",
        "ipv4.identification",
        "--max-encoded-bytes",
        &limit,
    ];
    assert_success(&run(&args), &args);
    let args = [
        "--output",
        "json",
        "analyze",
        "verify-forwarding",
        ingress,
        egress,
        "--identity",
        "ipv4.identification",
        "--max-encoded-bytes",
        &limit,
    ];
    assert_error(&run(&args), "packet.capture_compression_limit");
}

fn analyze_http2_json(capture_name: &str) -> serde_json::Value {
    let capture = capture_path(capture_name);
    let capture = capture.to_string_lossy().into_owned();
    let args = ["--output", "json", "analyze", "http2", capture.as_str()];
    let output = run(&args);
    let text = assert_success(&output, &args);
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("analyze http2 should emit valid JSON: {error}\n{text}"))
}

#[test]
fn http2_analysis_reports_streams_and_push() {
    let json = analyze_http2_json("http2-multiplexed.pcapng");
    let result = &json["result"];
    let connections = result["connections"].as_array().unwrap();
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0]["startup"], "prior_knowledge");
    assert_eq!(connections[0]["status"], "complete");
    let messages = result["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 7);
    let kinds: Vec<_> = messages
        .iter()
        .map(|message| message["kind"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
        [
            "request",
            "request",
            "push_promise",
            "response",
            "response",
            "response",
            "request"
        ]
    );
    assert!(
        messages
            .iter()
            .all(|message| message["status"] == "complete")
    );
    assert!(result["issues"].as_array().unwrap().is_empty());
    let summary = &result["summary"];
    assert_eq!(summary["connections"], 1);
    assert_eq!(summary["prior_knowledge_connections"], 1);
    assert_eq!(summary["upgraded_connections"], 0);
    assert_eq!(summary["unsupported_connections"], 0);
    assert_eq!(summary["frames"], 22);
    assert_eq!(summary["streams"], 4);
    assert_eq!(summary["messages"], 7);
    assert_eq!(summary["complete_messages"], 7);
    assert_eq!(summary["issues"], 0);
}

#[test]
fn http2_analysis_reports_h2c_startup() {
    let json = analyze_http2_json("http2-upgrade.pcapng");
    let result = &json["result"];
    let connections = result["connections"].as_array().unwrap();
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0]["startup"], "h2c");
    assert_eq!(connections[0]["status"], "complete");
    let messages = result["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0]["kind"], "request");
    assert_eq!(messages[0]["status"], "complete");
    assert_eq!(messages[0]["http2_stream_id"], 1);
    assert_eq!(messages[1]["kind"], "response");
    assert_eq!(messages[1]["status"], "complete");
    assert_eq!(messages[1]["http2_stream_id"], 1);
    assert_eq!(messages[1]["request"], 1);
    assert!(result["issues"].as_array().unwrap().is_empty());
    let summary = &result["summary"];
    assert_eq!(summary["connections"], 1);
    assert_eq!(summary["prior_knowledge_connections"], 0);
    assert_eq!(summary["upgraded_connections"], 1);
    assert_eq!(summary["unsupported_connections"], 0);
    assert_eq!(summary["frames"], 6);
    assert_eq!(summary["streams"], 1);
    assert_eq!(summary["messages"], 2);
    assert_eq!(summary["complete_messages"], 2);
    assert_eq!(summary["issues"], 0);
}

#[test]
fn scan_diff_reports_changes_and_provenance() {
    use serde_json::json;
    use sha2::{Digest, Sha256};

    let dir = tempfile::tempdir().unwrap();
    let before_path = dir.path().join("before.json");
    let after_path = dir.path().join("after.json");
    let before = json!({
        "schema": packetcraftr_cli::output::contract::OUTPUT_SCHEMA,
        "payload_schema": "packetcraftr.output.scan/v1",
        "command":"scan", "mode":"aggregate", "status":"success",
        "result":{"method":"tcp_connect", "endpoints":[
            {"address":"192.0.2.1", "port":443, "inference":{"state":"closed", "supporting":[1]}},
            {"address":"192.0.2.2", "port":443, "inference":{"state":"open", "supporting":[2]}}
        ]}
    });
    let after = json!({
        "schema": packetcraftr_cli::output::contract::OUTPUT_SCHEMA,
        "payload_schema": "packetcraftr.output.scan/v1",
        "command":"scan", "mode":"aggregate", "status":"success",
        "result":{"method":"tcp_connect", "endpoints":[
            {"address":"192.0.2.1", "port":443, "inference":{"state":"open", "supporting":[3]}}
        ]}
    });
    let before_bytes = serde_json::to_vec(&before).unwrap();
    let after_bytes = serde_json::to_vec(&after).unwrap();
    std::fs::write(&before_path, &before_bytes).unwrap();
    std::fs::write(&after_path, &after_bytes).unwrap();
    let before_path = before_path.to_str().unwrap();
    let after_path = after_path.to_str().unwrap();
    let args = [
        "--output",
        "json",
        "analyze",
        "scan-diff",
        before_path,
        after_path,
    ];
    let output = run(&args);
    let report: serde_json::Value = serde_json::from_str(&assert_success(&output, &args)).unwrap();
    let result = &report["result"];
    assert_eq!(report["command"], "scan-diff");
    assert_eq!(result["kind"], "scan-diff");
    let findings = result["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 2);
    let changed = findings
        .iter()
        .find(|f| f["rule_id"] == "scan.state_changed")
        .unwrap();
    assert_eq!(changed["severity"], "medium");
    assert_eq!(
        changed["evidence"]["before"],
        before["result"]["endpoints"][0]
    );
    assert_eq!(
        changed["evidence"]["after"],
        after["result"]["endpoints"][0]
    );
    let coverage = findings
        .iter()
        .find(|f| f["rule_id"] == "scan.coverage_changed")
        .unwrap();
    assert_eq!(
        coverage["evidence"]["before"],
        before["result"]["endpoints"][1]
    );
    assert!(coverage["evidence"]["after"].is_null());
    assert_eq!(result["measurements"]["before_endpoints"], 2);
    assert_eq!(result["measurements"]["after_endpoints"], 1);
    let hash = |bytes: &[u8]| {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    assert_eq!(
        result["sources"],
        json!([
            {"path": before_path, "sha256": hash(&before_bytes)},
            {"path": after_path, "sha256": hash(&after_bytes)}
        ])
    );
}

#[test]
fn scan_diff_rejects_invalid_input() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invalid.json");
    std::fs::write(
        &path,
        format!(
            r#"{{"schema":"{}","command":"scan","mode":"aggregate","status":"failure"}}"#,
            packetcraftr_cli::output::contract::OUTPUT_SCHEMA
        ),
    )
    .unwrap();
    let path = path.to_str().unwrap();
    let args = ["--output", "json", "analyze", "scan-diff", path, path];
    let output = run(&args);
    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "error");
    assert_eq!(report["error"]["code"], "cli.security_input");
}

mod differential {
    use packetcraftr::differential as lib;
    use serde_json::{Value, json};
    use std::process::Output;

    pub(super) fn campaign() -> Vec<u8> {
        let attempt = |attempt_seq: u32| {
            json!({
                "variant": "baseline",
                "attempt_seq": attempt_seq,
                "answered": false,
                "packets_sent": 1,
                "payload_sha256": "11".repeat(32),
            })
        };
        serde_json::to_vec(&json!({
            "schema": packetcraftr_cli::output::contract::OUTPUT_SCHEMA,
            "payload_schema": "packetcraftr.output.differential/v1",
            "command": "differential",
            "mode": "aggregate",
            "status": "success",
            "result": {
                "provisional": true,
                "plan_digest": "fixture",
                "source_port": 40000,
                "spoof_source": "192.0.2.1",
                "attempts": [attempt(u32::MAX), attempt(7)],
            },
        }))
        .unwrap()
    }

    fn reception(attempt_seq: u32) -> Vec<u8> {
        serde_json::to_vec(&lib::ReceptionRecord {
            variant_index: 0,
            attempt_seq,
            source: "192.0.2.1:40000".parse().unwrap(),
            payload_sha256: lib::hex(&[0x11; 32]),
        })
        .unwrap()
    }

    fn join(campaign: &[u8], log: &[u8]) -> Output {
        let dir = tempfile::tempdir().unwrap();
        let campaign_path = dir.path().join("campaign.json");
        let log_path = dir.path().join("receptions.jsonl");
        std::fs::write(&campaign_path, campaign).unwrap();
        std::fs::write(&log_path, log).unwrap();
        super::run(&[
            "--output",
            "json",
            "network",
            "differential-join",
            campaign_path.to_str().unwrap(),
            "--responder-log",
            log_path.to_str().unwrap(),
        ])
    }

    fn result(output: &Output) -> Value {
        serde_json::from_str(&super::assert_success(
            output,
            &["network", "differential-join"],
        ))
        .unwrap()
    }

    #[test]
    fn differential_join_preserves_existing_answers() {
        let first = join(&campaign(), &reception(u32::MAX));
        let report = result(&first);
        assert_eq!(report["result"]["rows"][0]["verdict"], "flaky");
        assert_eq!(report["result"]["attempts"][0]["attempt_seq"], u32::MAX);
        assert_eq!(report["result"]["attempts"][0]["answered"], true);
        assert_eq!(report["result"]["attempts"][1]["answered"], false);
        let second = join(
            &first.stdout,
            &[b"\n\n", reception(7).as_slice(), b"\n"].concat(),
        );
        let report = result(&second);
        assert_eq!(report["result"]["valid"], true);
        assert_eq!(report["result"]["provisional"], false);
        assert_eq!(report["result"]["rows"][0]["verdict"], "accepted");
        assert_eq!(report["result"]["rows"][0]["answered"], 2);
        assert_eq!(
            result(&join(&second.stdout, b""))["result"],
            report["result"]
        );
    }

    #[test]
    fn differential_join_rejects_reception_aliasing() {
        let mut value: Value = serde_json::from_slice(&campaign()).unwrap();
        value["result"]["attempts"][0]["attempt_seq"] = json!(u64::from(u32::MAX) + 1);
        let output = join(&serde_json::to_vec(&value).unwrap(), &reception(u32::MAX));
        super::assert_error(&output, "cli.error");
    }

    #[test]
    fn differential_join_validates_campaign_and_source() {
        let original: Value = serde_json::from_slice(&campaign()).unwrap();
        for (field, replacement) in [
            (
                "schema",
                json!(packetcraftr_cli::output::contract::AMBIGUOUS_OUTPUT_SCHEMA),
            ),
            ("schema", json!("unsupported-schema")),
            ("command", json!("scan")),
            ("mode", json!("stream")),
            ("status", json!("error")),
            ("payload_schema", json!("packetcraftr.output.scan/v1")),
        ] {
            let mut value = original.clone();
            value[field] = replacement;
            let output = join(&serde_json::to_vec(&value).unwrap(), b"");
            super::assert_error(&output, "cli.error");
            if value[field] == packetcraftr_cli::output::contract::AMBIGUOUS_OUTPUT_SCHEMA {
                assert!(super::stdout(&output).contains("regenerate"));
            }
        }
        for field in ["schema", "payload_schema", "command", "mode", "status"] {
            let mut value = original.clone();
            value.as_object_mut().unwrap().remove(field);
            super::assert_error(
                &join(&serde_json::to_vec(&value).unwrap(), b""),
                "cli.error",
            );
        }
        for field in ["source_port", "spoof_source", "attempts"] {
            let mut value = original.clone();
            value["result"].as_object_mut().unwrap().remove(field);
            super::assert_error(
                &join(&serde_json::to_vec(&value).unwrap(), b""),
                "cli.error",
            );
        }
        let mut unspoofed = original;
        unspoofed["result"]["spoof_source"] = Value::Null;
        assert_eq!(
            result(&join(&serde_json::to_vec(&unspoofed).unwrap(), b""))["result"]["spoof_source"],
            Value::Null
        );
    }

    #[test]
    fn differential_join_bounds_inputs_before_parsing() {
        let mut oversized = campaign();
        oversized.resize(16 * 1024 * 1024 + 1, b' ');
        for output in [join(&oversized, b""), join(&campaign(), &oversized)] {
            super::assert_error(&output, "cli.error");
            assert!(super::stdout(&output).contains("byte limit"));
        }
    }
}

#[cfg(unix)]
mod stalled_inputs {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Child, ChildStdin, Command, Output, Stdio};
    use std::time::{Duration, Instant};

    const DEADLINE_MS: &str = "1500";
    const EXIT_WITHIN: Duration = Duration::from_secs(10);

    fn spawn(args: &[&str], stdin: Stdio) -> Child {
        Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
            .args(args)
            .stdin(stdin)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("failed to spawn packetcraftr {args:?}: {error}"))
    }

    fn spawn_with_open_stdin(args: &[&str]) -> (Child, ChildStdin) {
        let mut child = spawn(args, Stdio::piped());
        let stdin = child.stdin.take().expect("piped stdin");
        (child, stdin)
    }

    fn kill_after_timeout(mut child: Child, args: &[&str], waiting_for: &str) -> ! {
        let _ = child.kill();
        let output = child.wait_with_output().expect("reap killed child");
        panic!(
            "packetcraftr {args:?} was still running after {EXIT_WITHIN:?} waiting for {waiting_for}; killed it\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn wait_bounded(mut child: Child, args: &[&str]) -> Output {
        let started = Instant::now();
        while child.try_wait().expect("poll child status").is_none() {
            if started.elapsed() > EXIT_WITHIN {
                kill_after_timeout(child, args, "exit");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        child.wait_with_output().expect("collect child output")
    }

    fn assert_interrupted(output: &Output, exit_code: i32, error_code: &str, message: &str) {
        assert_eq!(
            output.status.code(),
            Some(exit_code),
            "stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        super::assert_error(output, error_code);
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(
            report["error"]["message"]
                .as_str()
                .is_some_and(|text| text.contains(message)),
            "{report}"
        );
    }

    fn assert_deadline(output: &Output) {
        assert_interrupted(output, 6, "policy.duration_limit", "budget");
    }

    #[test]
    fn empty_capture_stdin_reaches_deadline() {
        let args = [
            "--output",
            "json",
            "analyze",
            "stats",
            "-",
            "--max-duration-ms",
            DEADLINE_MS,
        ];
        let (child, stdin) = spawn_with_open_stdin(&args);
        let output = wait_bounded(child, &args);
        drop(stdin);
        assert_deadline(&output);
    }

    #[test]
    fn empty_document_stdin_reaches_deadline() {
        let capture = super::capture_path("dns-response.pcap");
        let capture = capture.to_str().unwrap();
        let args = [
            "--output",
            "json",
            "analyze",
            "hunt",
            capture,
            "--indicators",
            "-",
            "--max-duration-ms",
            DEADLINE_MS,
        ];
        let (child, stdin) = spawn_with_open_stdin(&args);
        let output = wait_bounded(child, &args);
        drop(stdin);
        assert_deadline(&output);
    }

    #[test]
    fn partial_capture_header_reaches_deadline() {
        let args = [
            "--output",
            "json",
            "analyze",
            "stats",
            "-",
            "--max-duration-ms",
            DEADLINE_MS,
        ];
        let (child, mut stdin) = spawn_with_open_stdin(&args);
        stdin
            .write_all(&[0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0, 0])
            .expect("write partial PCAP header");
        stdin.flush().expect("flush partial header");
        let output = wait_bounded(child, &args);
        drop(stdin);
        assert_deadline(&output);
    }

    #[test]
    fn stalled_capture_record_reaches_deadline() {
        let args = [
            "--output",
            "json",
            "analyze",
            "stats",
            "-",
            "--max-duration-ms",
            DEADLINE_MS,
        ];
        let (child, mut stdin) = spawn_with_open_stdin(&args);
        let header = [
            [0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00],
            [0; 8],
            [0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00],
        ]
        .concat();
        stdin
            .write_all(&[header.as_slice(), &[0; 4]].concat())
            .expect("write PCAP header and a partial record");
        stdin.flush().expect("flush capture prefix");
        let output = wait_bounded(child, &args);
        drop(stdin);
        assert_eq!(output.status.code(), Some(6));
        super::assert_error(&output, "policy.duration_limit");
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            report["error"]["causes"][0]
                .as_str()
                .and_then(|cause| cause.split(':').next()),
            Some("capture operation exceeded its duration budget"),
            "{report}"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn fifo_without_writer_honors_the_deadline() {
        let directory = tempfile::tempdir().unwrap();
        let fifo = directory.path().join("capture.fifo");
        let status = Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("run mkfifo");
        assert!(status.success(), "mkfifo failed: {status:?}");
        let fifo = fifo.to_str().unwrap();
        let args = [
            "--output",
            "json",
            "analyze",
            "stats",
            fifo,
            "--max-duration-ms",
            DEADLINE_MS,
        ];
        let output = wait_bounded(spawn(&args, Stdio::null()), &args);
        assert_deadline(&output);
    }

    fn sigint_handler_installed(pid: u32) -> bool {
        const SIGINT: u32 = 2;
        std::fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find_map(|line| line.strip_prefix("SigCgt:"))
                    .and_then(|mask| u64::from_str_radix(mask.trim(), 16).ok())
            })
            .is_some_and(|mask| mask & (1 << (SIGINT - 1)) != 0)
    }

    fn open_fds() -> usize {
        std::fs::read_dir("/proc/self/fd")
            .expect("list /proc/self/fd")
            .count()
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn differential_join_cancels_stalled_inputs() {
        let directory = tempfile::tempdir().unwrap();
        let campaign = directory.path().join("campaign.json");
        let log = directory.path().join("receptions.jsonl");
        std::fs::write(&campaign, super::differential::campaign()).unwrap();
        std::fs::write(&log, b"").unwrap();
        let fifo = directory.path().join("input.fifo");
        assert!(
            Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let _writer = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fifo)
            .unwrap();
        for (campaign, log) in [(&fifo, &log), (&campaign, &fifo)] {
            let args = [
                "--output",
                "json",
                "network",
                "differential-join",
                campaign.to_str().unwrap(),
                "--responder-log",
                log.to_str().unwrap(),
            ];
            let mut child = spawn(&args, Stdio::null());
            let started = Instant::now();
            loop {
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "command exited before reading input"
                );
                let reading = std::fs::read_dir(format!("/proc/{}/fd", child.id()))
                    .unwrap()
                    .filter_map(Result::ok)
                    .filter_map(|entry| std::fs::read_link(entry.path()).ok())
                    .any(|path| path == fifo);
                if reading && sigint_handler_installed(child.id()) {
                    break;
                }
                if started.elapsed() > EXIT_WITHIN {
                    kill_after_timeout(child, &args, "the stalled input");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(
                Command::new("kill")
                    .args(["-INT", &child.id().to_string()])
                    .status()
                    .unwrap()
                    .success()
            );
            assert_interrupted(
                &wait_bounded(child, &args),
                130,
                "io.cancelled",
                "cancelled",
            );
        }
    }

    #[test]
    fn piped_capture_publishes_each_frame_before_its_input_ends() {
        let capture =
            std::fs::read(super::capture_path("dns-response.pcap")).expect("read capture");
        for format in ["ndjson", "text"] {
            let args = ["--output", format, "files", "read", "-"];
            let (mut child, mut stdin) = spawn_with_open_stdin(&args);
            let stdout = child.stdout.take().expect("piped stdout");
            let (lines, first) = std::sync::mpsc::channel();
            let reader = std::thread::spawn(move || {
                let mut stdout = BufReader::new(stdout);
                let mut line = String::new();
                stdout.read_line(&mut line).expect("read first record");
                lines.send(line).expect("receive first record");
                std::io::copy(&mut stdout, &mut std::io::sink()).expect("drain stdout");
            });
            stdin.write_all(&capture).expect("write capture");
            stdin.flush().expect("flush capture");
            let line = first
                .recv_timeout(EXIT_WITHIN)
                .expect("a frame record while stdin stays open");
            assert!(!line.is_empty(), "{format}");
            drop(stdin);
            let output = wait_bounded(child, &args);
            reader.join().expect("join stdout reader");
            assert!(output.status.success(), "{output:?}");
        }
    }

    /// Enough frames to overflow an output batch, and optionally a record cut short.
    fn synthetic_pcap(truncated: bool) -> Vec<u8> {
        let frame = [0x45_u8; 20];
        let header = [
            0xa1b2_c3d4_u32.to_le_bytes().as_slice(),
            &2_u16.to_le_bytes(),
            &4_u16.to_le_bytes(),
            &[0; 8],
            &65_535_u32.to_le_bytes(),
            &228_u32.to_le_bytes(),
        ]
        .concat();
        let record = [
            [0_u8; 8].as_slice(),
            &20_u32.to_le_bytes(),
            &20_u32.to_le_bytes(),
            &frame,
        ]
        .concat();
        let frames = record.repeat(2000);
        let tail: &[u8] = if truncated { &record[..30] } else { &[] };
        [header.as_slice(), &frames, tail].concat()
    }

    fn read_piped(args: &[&str], capture: Vec<u8>) -> Output {
        let (child, mut stdin) = spawn_with_open_stdin(args);
        let writer = std::thread::spawn(move || {
            stdin.write_all(&capture).expect("write capture");
        });
        let output = child.wait_with_output().expect("wait for child");
        writer.join().expect("join stdin writer");
        output
    }

    /// A datagram socket keeps write boundaries, so each received message is one write.
    #[cfg(target_os = "linux")]
    fn count_stdout_writes(args: &[&str]) -> usize {
        use std::os::unix::net::UnixDatagram;
        let (received, sent) = UnixDatagram::pair().expect("create socket pair");
        received.set_nonblocking(true).expect("set nonblocking");
        let mut child = Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
            .args(args)
            .stdin(Stdio::null())
            .stdout(std::os::fd::OwnedFd::from(sent))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn packetcraftr");
        let started = Instant::now();
        let mut message = vec![0_u8; 1 << 20];
        let mut writes = 0;
        loop {
            match received.recv(&mut message) {
                Ok(_) => writes += 1,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if let Some(status) = child.try_wait().expect("poll child status") {
                        assert!(status.success(), "{args:?}: {status:?}");
                        return writes;
                    }
                    assert!(started.elapsed() < EXIT_WITHIN, "{args:?} did not exit");
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("receive stdout: {error}"),
            }
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn regular_file_input_coalesces_stdout_writes() {
        let file = tempfile::NamedTempFile::new().expect("create capture");
        std::fs::write(file.path(), synthetic_pcap(false)).expect("write capture");
        let path = file.path().to_string_lossy();
        for format in ["text", "ndjson"] {
            let writes = count_stdout_writes(&["--output", format, "files", "read", path.as_ref()]);
            assert!((1..200).contains(&writes), "{format} took {writes} writes");
        }
    }

    #[test]
    fn regular_file_output_matches_piped_output_through_success_and_failure() {
        for truncated in [false, true] {
            let capture = synthetic_pcap(truncated);
            let file = tempfile::NamedTempFile::new().expect("create capture");
            std::fs::write(file.path(), &capture).expect("write capture");
            let path = file.path().to_string_lossy();
            for format in ["text", "ndjson"] {
                let piped =
                    read_piped(&["--output", format, "files", "read", "-"], capture.clone());
                let regular = super::run(&["--output", format, "files", "read", path.as_ref()]);
                assert_eq!(
                    String::from_utf8_lossy(&regular.stdout),
                    String::from_utf8_lossy(&piped.stdout),
                    "{format} truncated={truncated}"
                );
                assert_eq!(
                    regular.status, piped.status,
                    "{format} truncated={truncated}"
                );
                assert_eq!(regular.status.success(), !truncated, "{format}");
                assert!(piped.stdout.len() > 16 * 1024, "{format}");
            }
        }
    }

    #[test]
    #[cfg_attr(
        not(target_os = "linux"),
        ignore = "needs /proc/<pid>/status SigCgt to know when the child's SIGINT handler is installed"
    )]
    fn first_sigint_cancels_a_stalled_stdin_capture_gracefully() {
        let args = ["--output", "ndjson", "files", "read", "-"];
        let fds_before = open_fds();
        for _ in 0..5 {
            let (mut child, stdin) = spawn_with_open_stdin(&args);
            let started = Instant::now();
            while !sigint_handler_installed(child.id()) {
                assert!(
                    child.try_wait().expect("poll child status").is_none(),
                    "packetcraftr {args:?} exited before installing its SIGINT handler"
                );
                if started.elapsed() > EXIT_WITHIN {
                    kill_after_timeout(child, &args, "its SIGINT handler");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let status = Command::new("kill")
                .args(["-INT", &child.id().to_string()])
                .status()
                .expect("run kill");
            assert!(status.success(), "kill -INT failed: {status:?}");
            let output = wait_bounded(child, &args);
            drop(stdin);
            assert_interrupted(&output, 130, "io.cancelled", "cancelled");
        }
        let settled = Instant::now();
        while open_fds() > fds_before {
            assert!(
                settled.elapsed() < EXIT_WITHIN,
                "test process holds {} descriptors, {fds_before} before the children ran",
                open_fds()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

#[test]
fn quic_decryption_exposes_metadata_by_default_and_payloads_only_when_requested() {
    let keys = capture_path("quic-demo.keys");
    for name in ["quic-demo-v1.pcap", "quic-demo-v2.pcapng"] {
        let capture = capture_path(name);
        let args = [
            "--output",
            "json",
            "analyze",
            "quic",
            capture.to_str().unwrap(),
            "--keylog",
            keys.to_str().unwrap(),
        ];
        let value: serde_json::Value =
            serde_json::from_str(&assert_success(&run(&args), &args)).unwrap();
        let connection = &value["result"]["connections"][0];
        assert_eq!(connection["sni"], "quic.example.test");
        assert_eq!(connection["negotiated_alpn"], "quic-test");
        assert_eq!(connection["metrics"]["key_updates"], 1);
        assert_eq!(connection["metrics"]["validated_paths"], 1);
        assert_eq!(connection["incomplete"], false);
        assert!(
            connection["streams"]
                .as_array()
                .unwrap()
                .iter()
                .all(|stream| stream["ranges"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|range| range.get("data_hex").is_none()))
        );
        let selected = [
            "--output",
            "json",
            "analyze",
            "quic",
            capture.to_str().unwrap(),
            "--keylog",
            keys.to_str().unwrap(),
            "--connection",
            "0",
            "--stream",
            "0",
            "--direction",
            "client",
            "--include-data",
        ];
        let selected: serde_json::Value =
            serde_json::from_str(&assert_success(&run(&selected), &selected)).unwrap();
        let streams = selected["result"]["connections"][0]["streams"]
            .as_array()
            .unwrap();
        assert_eq!(streams.len(), 1);
        assert_eq!(
            streams[0]["ranges"][0]["data_hex"],
            "68656c6c6f20776f726c64"
        );
        let ndjson = [
            "--output",
            "ndjson",
            "analyze",
            "quic",
            capture.to_str().unwrap(),
            "--keylog",
            keys.to_str().unwrap(),
            "--stream",
            "0",
            "--direction",
            "client",
            "--include-data",
        ];
        let events: Vec<serde_json::Value> = assert_success(&run(&ndjson), &ndjson)
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let payload = events
            .iter()
            .find(|event| event["event"] == "stream_data")
            .unwrap();
        assert_eq!(
            payload["result"]["stream_data"]["data_hex"],
            streams[0]["ranges"][0]["data_hex"]
        );
        assert_eq!(events.last().unwrap()["event"], "complete");
    }
}

#[test]
fn quic_exports_exact_contiguous_ranges_and_refuses_to_overwrite_them() {
    let directory = tempfile::tempdir().unwrap();
    let capture = capture_path("quic-demo-v2.pcapng");
    let keys = capture_path("quic-demo.keys");
    let args = [
        "--output",
        "json",
        "analyze",
        "quic",
        capture.to_str().unwrap(),
        "--keylog",
        keys.to_str().unwrap(),
        "--write",
        directory.path().to_str().unwrap(),
    ];
    assert_success(&run(&args), &args);
    let manifest = directory.path().join("quic-manifest.json");
    let original = std::fs::read(&manifest).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&original).unwrap();
    let streams = value["connections"][0]["streams"].as_array().unwrap();
    for (id, direction, expected) in [
        (0, "client", &b"hello world"[..]),
        (0, "server", &b"received hello world\n"[..]),
        (4, "client", &b"updated keys\n"[..]),
    ] {
        let stream = streams
            .iter()
            .find(|stream| stream["id"] == id && stream["direction"] == direction)
            .unwrap();
        let ranges = stream["ranges"].as_array().unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0]["offset"], 0);
        assert_eq!(stream["complete"], true);
        assert_eq!(
            std::fs::read(directory.path().join(ranges[0]["file"].as_str().unwrap())).unwrap(),
            expected
        );
    }
    assert!(!run(&args).status.success());
    assert_eq!(std::fs::read(&manifest).unwrap(), original);
    for stream in streams {
        let range = &stream["ranges"][0];
        assert_eq!(
            std::fs::metadata(directory.path().join(range["file"].as_str().unwrap()))
                .unwrap()
                .len(),
            range["length"].as_u64().unwrap()
        );
    }
}

#[test]
fn quic_export_budget_includes_the_complete_manifest() {
    let directory = tempfile::tempdir().unwrap();
    let capture = capture_path("quic-demo-v2.pcapng");
    let keys = capture_path("quic-demo.keys");
    let args = [
        "analyze",
        "quic",
        capture.to_str().unwrap(),
        "--keylog",
        keys.to_str().unwrap(),
        "--write",
        directory.path().to_str().unwrap(),
    ];
    assert_success(&run(&args), &args);
    let exported_bytes: u64 = std::fs::read_dir(directory.path())
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let bytes = entry.metadata().unwrap().len();
            std::fs::remove_file(entry.path()).unwrap();
            bytes
        })
        .sum();

    let too_small = (exported_bytes - 1).to_string();
    let limited = [&args[..], &["--max-application-output-bytes", &too_small]].concat();
    let output = run(&limited);
    assert!(!output.status.success(), "{}", stdout(&output));
    assert!(String::from_utf8_lossy(&output.stderr).contains("QUIC application output"));
    assert!(
        std::fs::read_dir(directory.path())
            .unwrap()
            .next()
            .is_none()
    );

    let exact = exported_bytes.to_string();
    let limited = [&args[..], &["--max-application-output-bytes", &exact]].concat();
    assert_success(&run(&limited), &limited);
}

#[test]
fn quic_missing_secrets_and_payload_limits_are_explicit() {
    let capture = capture_path("quic-demo-v1.pcap");
    let args = [
        "--output",
        "json",
        "analyze",
        "quic",
        capture.to_str().unwrap(),
    ];
    let value: serde_json::Value =
        serde_json::from_str(&assert_success(&run(&args), &args)).unwrap();
    let connection = &value["result"]["connections"][0];
    assert_eq!(connection["sni"], "quic.example.test");
    assert_eq!(connection["incomplete"], true);
    assert!(connection["pending_packets"].as_u64().unwrap() > 0);
    assert!(connection["streams"].as_array().unwrap().is_empty());
    let keys = capture_path("quic-demo.keys");
    let bounded = [
        "--output",
        "json",
        "analyze",
        "quic",
        capture.to_str().unwrap(),
        "--keylog",
        keys.to_str().unwrap(),
        "--include-data",
        "--max-application-output-bytes",
        "2",
    ];
    let output = run(&bounded);
    assert!(!output.status.success());
    assert!(stdout(&output).contains("QUIC application output"));
}

#[test]
fn quic_capture_incompleteness_reaches_retired_reports_and_exports() {
    let keys = capture_path("quic-demo.keys");
    for name in ["quic-demo-truncated.pcap", "quic-demo-incomplete-ip.pcap"] {
        for filtered in [false, true] {
            let capture = capture_path(name);
            let directory = tempfile::tempdir().unwrap();
            let mut args = vec![
                "--output",
                "json",
                "analyze",
                "quic",
                capture.to_str().unwrap(),
                "--keylog",
                keys.to_str().unwrap(),
                "--connection",
                "0",
                "--write",
                directory.path().to_str().unwrap(),
            ];
            if filtered {
                args.extend(["--filter", "udp"]);
            }
            let output = run(&args);
            assert_success(&output, &args);
            let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(report["result"]["summary"]["input_incomplete"], true);
            let connection = &report["result"]["connections"][0];
            assert_eq!(connection["incomplete"], true);
            assert_eq!(connection["closed"], true);
            assert!(
                connection["streams"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|stream| stream["complete"] == true)
            );
            let manifest: serde_json::Value = serde_json::from_slice(
                &std::fs::read(directory.path().join("quic-manifest.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(manifest["connections"][0]["incomplete"], true);
        }
    }
}

#[test]
fn quic_text_payloads_distinguish_rejected_early_data() {
    let capture = capture_path("quic-demo-early-data.pcap");
    let keys = capture_path("quic-demo-early-data.keys");
    let args = [
        "analyze",
        "quic",
        capture.to_str().unwrap(),
        "--keylog",
        keys.to_str().unwrap(),
        "--include-data",
    ];
    let output = run(&args);
    assert_success(&output, &args);
    let text = stdout(&output);
    assert!(text.lines().any(|line| line
        == "data connection=0 stream=0 direction=client offset=0 early_data=true hex=6561726c79"));
    assert!(text.lines().any(|line| line == "data connection=0 stream=0 direction=client offset=0 early_data=false hex=7265706c6163656d656e74"));
}

#[cfg(target_os = "linux")]
#[test]
fn quic_keylog_rejects_idle_nonregular_input() {
    let capture = capture_path("quic-demo-v1.pcap");
    let args = [
        "--output",
        "json",
        "analyze",
        "quic",
        capture.to_str().unwrap(),
        "--keylog",
        "/dev/stdin",
    ];
    let mut child = Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() >= until {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("nonregular key-log input must be rejected without waiting for a writer");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["error"]["message"]
            .as_str()
            .unwrap()
            .contains("regular file")
    );
}

#[test]
fn security_modes_observe_each_frame_and_finish_their_run() {
    let indicators = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/documents/indicators.json");
    let indicators = indicators.to_str().unwrap();
    let report = |mode: &str, capture: &str| {
        let capture = capture_path(capture);
        let capture = capture.to_str().unwrap();
        let args: Vec<&str> = match mode {
            "hunt" => vec![
                "--output",
                "json",
                "analyze",
                "hunt",
                capture,
                "--indicators",
                indicators,
            ],
            mode => vec!["--output", "json", "analyze", mode, capture],
        };
        let output = run(&args);
        assert_success(&output, &args);
        let report: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("JSON report");
        report["result"].clone()
    };
    let findings = |result: &serde_json::Value| -> Vec<(String, String)> {
        result["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .map(|finding| {
                (
                    finding["rule_id"].as_str().unwrap().to_owned(),
                    finding["evidence"]["context"]["protocol"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                )
            })
            .collect()
    };
    let reasons = |result: &serde_json::Value| result["completeness"]["reasons"].clone();

    let beacons = report("beacons", "beacon-periodic.pcap");
    assert_eq!(
        findings(&beacons),
        [("traffic.periodic_connections".to_owned(), String::new())]
    );

    for (capture, protocol) in [
        ("http-stream.pcap", "http_host"),
        ("tls-handshake.pcapng", "tls"),
    ] {
        let hunt = report("hunt", capture);
        assert!(
            findings(&hunt).contains(&("ioc.match".to_owned(), protocol.to_owned())),
            "{capture}: {hunt}"
        );
        assert_eq!(reasons(&hunt), serde_json::json!([]), "{capture}");
    }
    assert_eq!(
        reasons(&report("hunt", "clock-regression.pcap")),
        serde_json::json!([
            "capture clock regressions observed; beacon timing conclusions suppressed"
        ])
    );
    assert_eq!(
        reasons(&report("hunt", "quic-demo-truncated.pcap")),
        serde_json::json!(["capture contains truncated frames"])
    );

    let anomalies = report("dns-anomalies", "dns-response.pcap");
    assert_eq!(
        reasons(&anomalies),
        serde_json::json!(["DNS transactions include unanswered, orphan, or duplicate messages"])
    );
    assert_eq!(
        anomalies["measurements"]["thresholds"]["window_seconds"],
        60
    );
}

#[test]
fn verbose_security_findings_show_details_on_separate_lines() {
    let capture = capture_path("beacon-periodic.pcap");
    let args = ["--verbose", "analyze", "beacons", capture.to_str().unwrap()];
    let text = assert_success(&run(&args), &args);
    let lines: Vec<_> = text.lines().collect();
    assert!(
        lines.windows(3).any(|lines| {
            lines[0].starts_with("  frames: [")
                && lines[1].starts_with("  evidence: {")
                && lines[2].starts_with("  remediation: ")
        }),
        "{text}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn security_analysis_reports_capture_paths_with_invalid_utf8() {
    use std::os::unix::ffi::OsStrExt;

    let directory = tempfile::tempdir().expect("tempdir");
    let capture = directory.path().join(OsStr::from_bytes(b"dns-\xff.pcap"));
    std::fs::copy(capture_path("dns-response.pcap"), &capture).expect("copy capture");
    let args = [
        OsStr::new("--output"),
        OsStr::new("json"),
        OsStr::new("analyze"),
        OsStr::new("dns-anomalies"),
        capture.as_os_str(),
    ];
    let output = run(&args);
    let text = assert_success(&output, &args);
    let report: serde_json::Value = serde_json::from_str(&text).expect("JSON report");
    assert_eq!(
        report["result"]["measurements"]["capture"],
        capture.to_string_lossy().as_ref(),
    );
}

#[test]
fn report_counts_repeated_inputs_once_at_the_findings_limit() {
    let directory = tempfile::tempdir().expect("tempdir");
    let input = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/documents/output-beacons-success.json");
    let copy = directory.path().join("copy.json");
    std::fs::copy(&input, &copy).expect("copy input to a distinct path");

    let report = |inputs: &[&Path], name: &str, limit: &str| {
        let html = directory.path().join(name);
        let mut args = ["--output", "json", "analyze", "report"]
            .map(OsStr::new)
            .to_vec();
        args.extend(inputs.iter().map(|path| path.as_os_str()));
        args.extend([
            OsStr::new("--html"),
            html.as_os_str(),
            OsStr::new("--max-findings"),
            OsStr::new(limit),
        ]);
        let text = assert_success(&run(&args), &args);
        let json: serde_json::Value = serde_json::from_str(&text).expect("JSON report");
        let page = std::fs::read_to_string(html).expect("HTML report");
        assert!(page.contains(&format!("Showing {limit} of {limit} findings.")));
        json["result"].clone()
    };

    let single = report(&[&input], "single.html", "1");
    let repeated = report(&[&input, &input], "repeated.html", "1");
    assert_eq!(single["findings"].as_array().unwrap().len(), 1);
    assert_eq!(repeated["findings"], single["findings"]);
    assert_eq!(repeated["sources"], single["sources"]);

    let distinct = report(&[&input, &copy, &input], "distinct.html", "2");
    assert_eq!(distinct["findings"].as_array().unwrap().len(), 2);
    assert_eq!(distinct["findings"][0], single["findings"][0]);
    assert_eq!(
        distinct["findings"][1]["evidence"]["source_file"],
        copy.to_string_lossy().as_ref()
    );
    assert_eq!(distinct["sources"].as_array().unwrap().len(), 2);
}

#[test]
fn report_caps_the_emitted_json_result_before_writing_html() {
    let directory = tempfile::tempdir().expect("tempdir");
    let input = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/documents/output-audit-http-success.json");
    let html = directory.path().join("évaluation.html");
    let args = [
        "--output",
        "json",
        "--resource-diagnostics",
        "analyze",
        "report",
        input.to_str().unwrap(),
        "--html",
        html.to_str().unwrap(),
    ];
    let baseline = assert_success(&run(&args), &args);
    std::fs::remove_file(&html).expect("remove baseline HTML");
    let (_, tail) = baseline.split_once("\"result\":").expect("result field");
    let mut values =
        serde_json::Deserializer::from_str(tail.trim_start()).into_iter::<serde_json::Value>();
    let result = values.next().unwrap().expect("JSON result");
    let result_bytes = values.byte_offset();
    assert!(std::fs::metadata(&input).unwrap().len() < result_bytes as u64);

    let exact = result_bytes.to_string();
    let exact_args = [&args[..], &["--max-result-bytes", &exact]].concat();
    let text = assert_success(&run(&exact_args), &exact_args);
    let accepted: serde_json::Value = serde_json::from_str(&text).expect("JSON report");
    assert_eq!(accepted["result"], result);
    std::fs::remove_file(&html).expect("remove accepted HTML");

    let short = (result_bytes - 1).to_string();
    let short_args = [&args[..], &["--max-result-bytes", &short]].concat();
    let output = run(&short_args);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    assert!(stdout(&output).contains("report exceeds --max-result-bytes"));
    assert!(!html.exists(), "the oversized report published HTML");
}

#[test]
fn report_writes_a_bundle_that_binds_its_inputs() {
    let directory = tempfile::tempdir().expect("tempdir");
    let html = directory.path().join("assessment.html");
    let bundle_path = directory.path().join("bundle.json");
    let scan = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/documents/output-scan-success.json");
    let html_arg = html.to_string_lossy().into_owned();
    let bundle_arg = bundle_path.to_string_lossy().into_owned();
    let scan_arg = scan.to_string_lossy().into_owned();
    let args = [
        "analyze",
        "report",
        scan_arg.as_str(),
        "--html",
        html_arg.as_str(),
        "--bundle",
        bundle_arg.as_str(),
    ];
    let output = run(&args);
    assert_success(&output, &args);
    let bundle: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&bundle_path).expect("bundle written"))
            .expect("bundle JSON");
    assert_eq!(bundle["schema"], "packetcraftr.bundle/v1");
    assert_eq!(
        bundle["report"]["findings"][0]["rule_id"],
        "engagement.scan.summary"
    );
    let parsed = packetcraftr_core::security::bundle::Bundle::parse(
        &std::fs::read(&bundle_path).expect("bundle bytes"),
    )
    .expect("bundle validates against its inputs digest");
    assert_eq!(parsed.sources.len(), 1);
    let page = std::fs::read_to_string(&html).expect("html written");
    assert!(page.contains("engagement.scan.summary"), "{page}");
}

#[cfg(target_os = "linux")]
#[test]
fn report_accepts_input_and_output_paths_with_invalid_utf8() {
    use std::os::unix::ffi::OsStrExt;

    let directory = tempfile::tempdir().expect("tempdir");
    let source = directory.path().join(OsStr::from_bytes(b"scan-\xff.json"));
    let html = directory
        .path()
        .join(OsStr::from_bytes(b"assessment-\xff.html"));
    let bundle = directory
        .path()
        .join(OsStr::from_bytes(b"bundle-\xff.json"));
    let scan = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/documents/output-scan-success.json");
    std::fs::copy(scan, &source).expect("copy scan result");
    let args = [
        OsStr::new("--output"),
        OsStr::new("json"),
        OsStr::new("analyze"),
        OsStr::new("report"),
        source.as_os_str(),
        OsStr::new("--html"),
        html.as_os_str(),
        OsStr::new("--bundle"),
        bundle.as_os_str(),
    ];
    let output = run(&args);
    let text = assert_success(&output, &args);
    let report: serde_json::Value = serde_json::from_str(&text).expect("JSON report");
    let result = &report["result"];
    assert_eq!(
        result["findings"][0]["evidence"]["source_file"],
        source.to_string_lossy().as_ref(),
    );
    assert_eq!(
        result["measurements"]["html"],
        html.to_string_lossy().as_ref()
    );
    assert_eq!(
        result["measurements"]["bundle"],
        bundle.to_string_lossy().as_ref(),
    );
    assert!(html.is_file(), "HTML report was not written");
    assert!(bundle.is_file(), "bundle was not written");
}

#[test]
fn scan_timing_conflicts_and_seeded_order_is_reproducible() {
    let conflict = run(&[
        "network",
        "scan",
        "127.0.0.1",
        "--list",
        "--timing",
        "normal",
        "--rate",
        "5",
    ]);
    assert_eq!(conflict.status.code(), Some(2));

    let listed = |seed: &str| {
        let args = [
            "network",
            "scan",
            "127.0.0.1",
            "--list",
            "--ports",
            "1-16",
            "--shuffle-seed",
            seed,
        ];
        let output = run(&args);
        let text = assert_success(&output, &args);
        text.lines()
            .filter(|line| line.starts_with("port tcp/"))
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    assert_eq!(listed("42"), listed("42"));
    let seed_args = [
        "--output",
        "json",
        "network",
        "scan",
        "127.0.0.1",
        "--list",
        "--ports",
        "1-4",
        "--shuffle-seed",
        "42",
    ];
    let seed_output = run(&seed_args);
    let seed_text = assert_success(&seed_output, &seed_args);
    let seed_report: serde_json::Value = serde_json::from_str(&seed_text).expect("JSON list");
    assert_eq!(seed_report["result"]["shuffle_seed"], 42);
    assert_ne!(listed("42"), listed("7"));
    let mut sorted = listed("42");
    sorted.sort_by_key(|line| {
        line.trim_start_matches("port tcp/")
            .split(' ')
            .next()
            .unwrap()
            .parse::<u16>()
            .unwrap()
    });
    assert_eq!(sorted.len(), 16);
    assert!(sorted[0].starts_with("port tcp/1 "));
    assert!(sorted[15].starts_with("port tcp/16 "));
}

#[test]
fn report_rejects_identical_html_and_bundle_paths() {
    let directory = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(directory.path().join("sub")).expect("subdirectory");
    let same = directory.path().join("sub").join("..").join("same.out");
    let scan = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/documents/output-scan-success.json");
    let same_arg = same.to_string_lossy().into_owned();
    let scan_arg = scan.to_string_lossy().into_owned();
    let output = run(&[
        "analyze",
        "report",
        scan_arg.as_str(),
        "--html",
        same_arg.as_str(),
        "--bundle",
        same_arg.as_str(),
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        !directory.path().join("same.out").exists(),
        "no output may be published on rejection"
    );

    #[cfg(unix)]
    {
        let real = directory.path().join("real");
        std::fs::create_dir_all(real.join("sub")).expect("real subdirectory");
        std::os::unix::fs::symlink(real.join("sub"), directory.path().join("link"))
            .expect("symlink");
        let html = real.join("report.out");
        let bundle = directory.path().join("link").join("..").join("report.out");
        let html_arg = html.to_string_lossy().into_owned();
        let bundle_arg = bundle.to_string_lossy().into_owned();
        let output = run(&[
            "analyze",
            "report",
            scan_arg.as_str(),
            "--html",
            html_arg.as_str(),
            "--bundle",
            bundle_arg.as_str(),
        ]);
        assert_eq!(output.status.code(), Some(2));
        assert!(
            !html.exists(),
            "symlink aliases must be rejected before staging"
        );
    }
}

#[test]
fn inventory_ties_macs_only_to_arp_senders() {
    let directory = tempfile::tempdir().expect("tempdir");
    let build = |name: &str, packet: &str| {
        let path = directory.path().join(name);
        let args = [
            "--output",
            "pcapng",
            "packet",
            "build",
            "--packet",
            packet,
            "--link-type",
            "ethernet",
        ];
        let output = run(&args);
        assert_success(&output, &args);
        std::fs::write(&path, &output.stdout).expect("write capture");
        path.to_string_lossy().into_owned()
    };
    let inventory = |capture: &str| {
        let args = ["analyze", "inventory", capture];
        let output = run(&args);
        assert_success(&output, &args)
    };
    let arp = build(
        "arp.pcapng",
        "ethernet(src=02:00:00:00:00:01,dst=ff:ff:ff:ff:ff:ff)/arp(operation=1,sender_hardware=02:00:00:00:00:01,sender_protocol=192.0.2.2,target_hardware=00:00:00:00:00:00,target_protocol=192.0.2.1)",
    );
    assert!(
        inventory(&arp).contains("host=192.0.2.2 mac=02:00:00:00:00:01"),
        "ARP sender mapping is established evidence"
    );
    let routed = build(
        "routed.pcapng",
        "ethernet(src=02:00:00:00:00:09,dst=02:00:00:00:00:01)/ipv4(src=198.51.100.7,dst=192.0.2.2)/udp(sport=40000,dport=9999)/raw(text=hi)",
    );
    let probe = build(
        "probe.pcapng",
        "ethernet(src=02:00:00:00:00:01,dst=ff:ff:ff:ff:ff:ff)/arp(operation=1,sender_hardware=02:00:00:00:00:01,sender_protocol=0.0.0.0,target_hardware=00:00:00:00:00:00,target_protocol=192.0.2.1)",
    );
    assert!(
        inventory(&probe).contains("hosts=0"),
        "an ARP probe claims no address yet"
    );
    let text = inventory(&routed);
    assert!(
        text.contains("host=198.51.100.7 mac=-"),
        "a routed frame must not attribute the router MAC, got:\n{text}"
    );
}

#[test]
fn scan_resource_diagnostics_report_the_timing_preset() {
    let args = [
        "--output",
        "json",
        "--resource-diagnostics",
        "network",
        "scan",
        "127.0.0.1",
        "--connect",
        "--ports",
        "1",
        "--timing",
        "fast",
    ];
    let output = run(&args);
    let text = assert_success(&output, &args);
    let report: serde_json::Value = serde_json::from_str(&text).expect("JSON report");
    let settings = report["resources"]["settings"]
        .as_array()
        .expect("settings");
    let value = |name: &str| {
        settings
            .iter()
            .find(|setting| setting["name"] == name)
            .map(|setting| setting["value"].clone())
    };
    assert_eq!(value("--max-in-flight"), Some(serde_json::json!(16)));
    assert_eq!(value("--timeout-ms"), Some(serde_json::json!(500)));
}

#[test]
fn passive_inventory_reports_only_observed_hosts_and_ports() {
    let capture = capture_path("dns-response.pcap");
    let capture = capture.to_string_lossy().into_owned();
    let args = ["--output", "json", "analyze", "inventory", capture.as_str()];
    let output = run(&args);
    let text = assert_success(&output, &args);
    let report: serde_json::Value = serde_json::from_str(&text).expect("JSON report");
    assert_eq!(report["command"], "inventory");
    let hosts = report["result"]["hosts"].as_array().expect("hosts");
    assert_eq!(hosts.len(), 2);
    let server = hosts
        .iter()
        .find(|host| host["address"] == "192.0.2.53")
        .expect("DNS server host");
    assert_eq!(server["frames_sent"], 1);
    assert_eq!(server["observed_ports"][0]["transport"], "udp");
    assert_eq!(server["observed_ports"][0]["port"], 53);
    assert!(
        server["protocols"]
            .as_array()
            .unwrap()
            .iter()
            .any(|protocol| protocol == "dns")
    );
}

fn first_frame(capture: &str) -> packetcraftr_core::frame::Frame {
    let source = std::fs::File::open(capture_path(capture)).unwrap();
    packetcraftr_core::capture_file::Reader::with_limits(source, Default::default())
        .unwrap()
        .next_frame()
        .unwrap()
        .unwrap()
}

fn little_endian_pcapng(
    frame: &packetcraftr_core::frame::Frame,
) -> packetcraftr_core::capture_file::Writer<Vec<u8>> {
    use packetcraftr_core::capture_file::{Endianness, PcapNgOptions, Writer};

    let mut writer = Writer::pcapng_with_options(
        Vec::new(),
        PcapNgOptions {
            endianness: Endianness::Little,
            ..Default::default()
        },
    )
    .unwrap();
    writer.add_interface(frame.link_type).unwrap();
    writer
}

fn untimed_pcapng_block(frame: &packetcraftr_core::frame::Frame) -> Vec<u8> {
    let padding = [0; 3];
    let pad = &padding[..frame.bytes().len().next_multiple_of(4) - frame.bytes().len()];
    let block_size = 16 + u32::try_from(frame.bytes().len() + pad.len()).unwrap();
    [
        &3_u32.to_le_bytes()[..],
        &block_size.to_le_bytes(),
        &frame.original_length().to_le_bytes(),
        frame.bytes(),
        pad,
        &block_size.to_le_bytes(),
    ]
    .concat()
}

fn inventory_result(path: &Path, selection: &[&str]) -> serde_json::Value {
    let args = [
        &[
            "--output",
            "json",
            "analyze",
            "inventory",
            path.to_str().unwrap(),
        ][..],
        selection,
    ]
    .concat();
    let text = assert_success(&run(&args), &args);
    serde_json::from_str::<serde_json::Value>(&text).unwrap()["result"].clone()
}

#[test]
fn passive_inventory_counts_untimed_pcapng_frames() {
    let frame = first_frame("dns-response.pcap");
    let mut writer = little_endian_pcapng(&frame);
    let packet_block_size = writer.encoded_frame_size(&frame).unwrap();
    writer.write_frame(&frame).unwrap();
    writer.write_frame(&frame).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let timed = dir.path().join("timed.pcapng");
    let mixed = dir.path().join("mixed.pcapng");
    let mut capture = writer.into_inner();
    std::fs::write(&timed, &capture).unwrap();

    capture.truncate(capture.len() - packet_block_size);
    capture.extend(untimed_pcapng_block(&frame));
    std::fs::write(&mixed, &capture).unwrap();

    let expected = inventory_result(&timed, &[]);
    assert_eq!(expected["frames_read"], 2);
    assert_eq!(inventory_result(&mixed, &[]), expected);
    assert_eq!(
        inventory_result(&mixed, &["--filter", "udp.stream == 0"]),
        expected
    );
    assert_eq!(
        inventory_result(&mixed, &["--filter", "frame.number == 2"]),
        inventory_result(&timed, &["--filter", "frame.number == 2"]),
    );
    assert_eq!(
        inventory_result(&mixed, &["--start-epoch", "0"]),
        inventory_result(&timed, &["--filter", "frame.number == 1"]),
    );

    let args = [
        "--output",
        "json",
        "analyze",
        "stats",
        mixed.to_str().unwrap(),
    ];
    assert_error(&run(&args), "packet.timestamp_unavailable");
}

#[test]
fn passive_inventory_stream_numbers_ignore_time_bounds() {
    let untimed = first_frame("protocol-coap.pcap");
    let timed = first_frame("protocol-snmp.pcap");
    assert_eq!(untimed.link_type, timed.link_type);
    let mut writer = little_endian_pcapng(&timed);
    let timed_block_size = writer.encoded_frame_size(&timed).unwrap();
    writer.write_frame(&timed).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let timed_only = dir.path().join("timed.pcapng");
    let untimed_first = dir.path().join("untimed-first.pcapng");
    let mut capture = writer.into_inner();
    std::fs::write(&timed_only, &capture).unwrap();

    let timed_block = capture.split_off(capture.len() - timed_block_size);
    capture.extend(untimed_pcapng_block(&untimed));
    capture.extend(timed_block);
    std::fs::write(&untimed_first, &capture).unwrap();

    let second_flow = inventory_result(&timed_only, &[])["hosts"].clone();
    assert_ne!(second_flow, serde_json::json!([]));
    for selection in [
        &["--filter", "udp.stream == 1"][..],
        &["--start-epoch", "0", "--filter", "udp.stream == 1"],
    ] {
        assert_eq!(
            inventory_result(&untimed_first, selection)["hosts"],
            second_flow,
            "{selection:?}"
        );
    }
}

#[test]
fn inventory_attributes_vxlan_frames_and_protocols_to_each_network() {
    let capture = capture_path("scoped-vxlan.pcap");
    let args = [
        "--output",
        "json",
        "analyze",
        "inventory",
        capture.to_str().unwrap(),
    ];
    let report: serde_json::Value =
        serde_json::from_str(&assert_success(&run(&args), &args)).unwrap();
    let result = &report["result"];
    let hosts = result["hosts"].as_array().expect("hosts");
    let host = |address: &str| {
        hosts
            .iter()
            .find(|host| host["address"] == address)
            .unwrap()
    };
    let outer_sender = host("203.0.113.1");
    let shared_receiver = host("198.51.100.2");
    let inner_sender = host("192.0.2.1");

    assert_eq!(result["frames_read"], 2);
    assert_eq!(outer_sender["frames_sent"], 2, "outer sender frame count");
    assert_eq!(
        shared_receiver["frames_received"], 2,
        "a destination at both layers counts once per frame"
    );
    assert_eq!(
        outer_sender["observed_ports"],
        serde_json::json!([{"transport": "udp", "port": 40000}])
    );
    assert_eq!(
        outer_sender["protocols"],
        serde_json::json!(["ipv4", "udp", "vxlan"])
    );
    assert_eq!(inner_sender["frames_sent"], 2);
    assert_eq!(
        inner_sender["protocols"],
        serde_json::json!(["ethernet", "ipv4", "tcp"])
    );
    assert_eq!(
        shared_receiver["protocols"],
        serde_json::json!(["ethernet", "ipv4", "tcp", "udp", "vxlan"])
    );
    let protocols = result["protocols"].as_array().expect("protocol counts");
    for name in ["ethernet", "ipv4", "tcp", "udp", "vxlan"] {
        let protocol = protocols
            .iter()
            .find(|protocol| protocol["protocol"] == name)
            .unwrap();
        assert_eq!(protocol["frames"], 2, "{name} must count each frame once");
    }
}

#[test]
fn scope_denies_an_excluded_destination_before_route_lookup() {
    let scope =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/documents/scope.json");
    assert!(
        scope.is_file(),
        "example scope missing: {}",
        scope.display()
    );
    let scope = scope.to_string_lossy().into_owned();

    let args = ["network", "preflight", "--scope-file", scope.as_str()];
    let output = run(&args);
    let text = assert_success(&output, &args);
    assert!(
        text.contains("scope label=lab-segment digest="),
        "preflight should name the validated scope, got:\n{text}"
    );
    assert!(text.contains("permission=not_probed"), "{text}");

    let args = [
        "--output",
        "json",
        "network",
        "plan",
        "--packet",
        "ipv4(dst=192.0.2.1)/udp(dport=53)",
        "--scope-file",
        scope.as_str(),
    ];
    let output = run(&args);
    assert_eq!(output.status.code(), Some(6), "{}", stdout(&output));
    assert_error(&output, "policy.destination_not_allowed");
}

#[test]
fn http3_reconstructs_multiplexed_exchanges_and_hides_header_values_by_default() {
    let capture = capture_path("http3-demo.pcapng");
    let keys = capture_path("http3-demo.keys");
    let analyze = [
        "analyze",
        "http3",
        capture.to_str().unwrap(),
        "--keylog",
        keys.to_str().unwrap(),
    ];
    let args = [&["--output", "json"][..], &analyze].concat();
    let report: serde_json::Value =
        serde_json::from_str(&assert_success(&run(&args), &args)).unwrap();
    let result = &report["result"];
    let exchanges = result["exchanges"].as_array().unwrap();
    assert_eq!(exchanges.len(), 2);
    assert_eq!(result["connections"][0]["client"]["encoder_inserts"], 1);
    assert_eq!(result["connections"][0]["transport_incomplete"], false);
    let first = &exchanges[0];
    assert_eq!(first["stream"], 0);
    let request = &first["request"]["header_sections"][0];
    assert_eq!(request["method"], "GET");
    assert_eq!(request["required_insert_count"], 1);
    assert!(
        request["fields"]
            .as_array()
            .unwrap()
            .iter()
            .all(|field| field.get("value").is_none() && field.get("value_hex").is_none())
    );
    let response = &first["response"];
    assert_eq!(response["data_frames"], 1);
    assert_eq!(response["data_bytes"], b"synthetic response body".len());
    let sections = response["header_sections"].as_array().unwrap();
    assert_eq!(sections[0]["status"], 103);
    assert_eq!(sections[1]["status"], 200);
    assert_eq!(sections[2]["kind"], "trailers");
    let redacted_trailer = &sections[2]["fields"][0];
    assert_eq!(redacted_trailer["name"], "x-test");
    assert!(redacted_trailer.get("value").is_none());
    assert!(redacted_trailer.get("value_hex").is_none());
    assert_eq!(
        exchanges[1]["response"]["header_sections"][0]["status"],
        204
    );

    let args = [
        &["--output", "ndjson"][..],
        &analyze,
        &["--stream", "0", "--include-header-values"],
    ]
    .concat();
    let stream = assert_success(&run(&args), &args);
    let events: Vec<serde_json::Value> = stream
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let [connection, exchange, terminal] = events.as_slice() else {
        panic!("expected connection, exchange and complete events")
    };
    assert_eq!(connection["event"], "http3_connection");
    assert_eq!(exchange["event"], "http3_exchange");
    let selected = &exchange["result"]["exchange"];
    let fields = selected["request"]["header_sections"][0]["fields"]
        .as_array()
        .unwrap();
    assert!(
        fields
            .iter()
            .any(|field| field["name"] == ":path" && field["value"] == "/private-demo")
    );
    let trailer = &selected["response"]["header_sections"][2]["fields"][0];
    assert_eq!(trailer["value_hex"], "ff");
    assert_eq!(terminal["event"], "complete");
    assert_eq!(terminal["result"]["summary"]["exchanges"], 1);
    assert!(!stream.contains("synthetic response body"));

    let text = assert_success(&run(&analyze), &analyze);
    assert!(text.contains("request GET offset=0"));
    assert!(text.contains("response 200"));
    assert!(!text.contains("/private-demo"));
    assert!(!text.contains("hex:ff"));
}

#[test]
fn http3_caps_rendered_application_evidence() {
    let capture = capture_path("http3-demo.pcapng");
    let keys = capture_path("http3-demo.keys");
    for format in ["json", "text"] {
        let args = [
            "--output",
            format,
            "analyze",
            "http3",
            capture.to_str().unwrap(),
            "--keylog",
            keys.to_str().unwrap(),
            "--include-header-values",
        ];
        let rendered = assert_success(&run(&args), &args);
        let evidence_bytes = if format == "json" {
            ["\"connections\"", "\"exchanges\""]
                .into_iter()
                .map(|key| {
                    let (_, tail) = rendered.split_once(key).unwrap();
                    let array = &tail[tail.find('[').unwrap()..];
                    let mut values = serde_json::Deserializer::from_str(array)
                        .into_iter::<serde::de::IgnoredAny>();
                    values.next().unwrap().unwrap();
                    array[1..values.byte_offset() - 1].trim_end().len()
                })
                .sum()
        } else {
            rendered.split_once("HTTP/3 connections=").unwrap().0.len()
        };

        let exact = evidence_bytes.to_string();
        let exact_args = [&args[..], &["--max-application-output-bytes", &exact]].concat();
        assert_eq!(assert_success(&run(&exact_args), &exact_args), rendered);

        let short = (evidence_bytes - 1).to_string();
        let short_args = [&args[..], &["--max-application-output-bytes", &short]].concat();
        let output = run(&short_args);
        let error = if format == "json" {
            assert_error(&output, "policy.denied");
            stdout(&output)
        } else {
            assert!(!output.status.success());
            assert!(stdout(&output).len() < evidence_bytes);
            String::from_utf8_lossy(&output.stderr).into_owned()
        };
        assert!(error.contains("application output exceeds --max-application-output-bytes"));
    }
}

#[test]
fn http3_honors_quic_stream_retention_override() {
    let capture = capture_path("http3-demo.pcapng");
    let keys = capture_path("http3-demo.keys");
    for (limit, data_bytes, complete) in [(32, 0, false), (64, 23, true)] {
        let limit = limit.to_string();
        let args = [
            "--output",
            "json",
            "analyze",
            "http3",
            capture.to_str().unwrap(),
            "--keylog",
            keys.to_str().unwrap(),
            "--stream",
            "0",
            "--max-quic-stream-bytes",
            &limit,
        ];
        let report: serde_json::Value =
            serde_json::from_str(&assert_success(&run(&args), &args)).unwrap();
        let response = &report["result"]["exchanges"][0]["response"];
        assert_eq!(response["data_bytes"], data_bytes);
        assert_eq!(response["complete"], complete);
        if !complete {
            assert!(
                response["issues"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|issue| issue["code"] == "stream_gap")
            );
        }
    }
}

#[test]
fn http3_streaming_summary_reports_capture_loss_separately_from_recovered_exchanges() {
    let mut capture = std::fs::read(capture_path("http3-demo.pcapng")).unwrap();
    let last_block = u32::from_le_bytes(capture[capture.len() - 4..].try_into().unwrap()) as usize;
    let original_length = capture.len() - last_block + 24;
    let field = &mut capture[original_length..original_length + 4];
    let wire_bytes = u32::from_le_bytes(field.try_into().unwrap());
    field.copy_from_slice(&(wire_bytes + 1).to_le_bytes());
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), capture).unwrap();
    let keys = capture_path("http3-demo.keys");
    let args = [
        "--output",
        "ndjson",
        "analyze",
        "http3",
        file.path().to_str().unwrap(),
        "--keylog",
        keys.to_str().unwrap(),
    ];
    let output = assert_success(&run(&args), &args);
    let records: Vec<serde_json::Value> = output
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(
        records
            .iter()
            .any(|record| record["event"] == "http3_exchange"
                && record["result"]["exchange"]["response"]["complete"] == true)
    );
    let terminal = records.last().unwrap();
    assert_eq!(terminal["event"], "complete");
    assert_eq!(terminal["result"]["summary"]["input_incomplete"], true);
}

#[test]
fn dns_transactions_follow_first_captured_bytes_not_completion_order() {
    use packetcraftr_core::capture_file::{Format, Writer};
    use packetcraftr_core::frame::{Frame, LinkType};
    use packetcraftr_core::protocol::checksum_parts;
    use std::time::{Duration, UNIX_EPOCH};

    fn segment(reverse: bool, sequence: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let (src, dst, sport, dport) = if reverse {
            ([192, 0, 2, 2], [192, 0, 2, 1], 53u16, 40000u16)
        } else {
            ([192, 0, 2, 1], [192, 0, 2, 2], 40000u16, 53u16)
        };
        let mut wire = vec![0u8; 40];
        wire[0] = 0x45;
        wire[2..4].copy_from_slice(&u16::try_from(40 + payload.len()).unwrap().to_be_bytes());
        wire[8] = 64;
        wire[9] = 6;
        wire[12..16].copy_from_slice(&src);
        wire[16..20].copy_from_slice(&dst);
        wire[20..22].copy_from_slice(&sport.to_be_bytes());
        wire[22..24].copy_from_slice(&dport.to_be_bytes());
        wire[24..28].copy_from_slice(&sequence.to_be_bytes());
        if flags & 0x10 != 0 {
            wire[28..32].copy_from_slice(&(if reverse { 101u32 } else { 501 }).to_be_bytes());
        }
        wire[32] = 0x50;
        wire[33] = flags;
        wire[34..36].copy_from_slice(&65535u16.to_be_bytes());
        wire.extend_from_slice(payload);
        let length = u16::try_from(wire.len() - 20).unwrap().to_be_bytes();
        let sum = checksum_parts(&[&src, &dst, &[0, 6], &length, &wire[20..]]);
        wire[36..38].copy_from_slice(&sum.to_be_bytes());
        let sum = checksum_parts(&[&wire[..20]]);
        wire[10..12].copy_from_slice(&sum.to_be_bytes());
        wire
    }
    let query = b"\x00\x1d\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
    let mut response = query.to_vec();
    response[4..6].copy_from_slice(&0x8180u16.to_be_bytes());
    for response_started_first in [true, false] {
        let mut frames = vec![
            segment(false, 100, 2, &[]),
            segment(true, 500, 18, &[]),
            segment(false, 101, 16, &[]),
        ];
        if response_started_first {
            frames.extend([
                segment(true, 501, 24, &response[..10]),
                segment(false, 101, 24, query),
                segment(true, 511, 24, &response[10..]),
            ]);
        } else {
            frames.extend([
                segment(false, 101, 24, &query[..10]),
                segment(true, 501, 24, &response),
                segment(false, 111, 24, &query[10..]),
            ]);
        }
        let capture = tempfile::NamedTempFile::new().unwrap();
        let mut writer =
            Writer::new(capture.reopen().unwrap(), Format::Pcap, LinkType::IPV4).unwrap();
        for (index, bytes) in frames.into_iter().enumerate() {
            let frame = Frame::new(
                Some(UNIX_EPOCH + Duration::from_secs(index as u64)),
                LinkType::IPV4,
                bytes,
            )
            .unwrap();
            writer.write_frame(&frame).unwrap();
        }
        writer.flush().unwrap();
        let args = [
            "--output",
            "json",
            "analyze",
            "dns",
            capture.path().to_str().unwrap(),
        ];
        let output = run(&args);
        let result: serde_json::Value =
            serde_json::from_str(&assert_success(&output, &args)).unwrap();
        let transactions = result["result"]["transactions"].as_array().unwrap();
        let statuses: Vec<_> = transactions
            .iter()
            .map(|t| t["status"].as_str().unwrap())
            .collect();
        if response_started_first {
            assert_eq!(statuses.len(), 2, "{result}");
            assert!(
                statuses.contains(&"orphan_response") && statuses.contains(&"unanswered"),
                "{result}"
            );
        } else {
            assert_eq!(statuses, ["matched"], "{result}");
            assert_eq!(
                transactions[0]["first_query_latency"]["negative"], true,
                "{result}"
            );
        }
    }
}
