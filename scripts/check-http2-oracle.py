import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET
from collections import defaultdict


ROOT = Path(__file__).resolve().parents[1]
CAPTURES = ("http2-multiplexed.pcapng", "http2-upgrade.pcapng")


def execute(command, data=None):
    result = subprocess.run(command, input=data, capture_output=True, timeout=60)
    if result.returncode:
        raise RuntimeError(f"{command}: {result.stderr.decode(errors='replace')}")
    return result.stdout


def field(node, name, attribute="show", optional=False):
    found = node.find(f".//field[@name='{name}']")
    if found is None:
        if optional:
            return None
        raise AssertionError(f"TShark omitted {name}")
    value = found.get(attribute)
    if value is None and not optional:
        raise AssertionError(f"TShark omitted {attribute} for {name}")
    return value


def number(node, name):
    return int(field(node, name), 0)


def payload(node, name):
    return field(node, name, "value", optional=True) or ""


def normalize_oracle(root):
    frames, headers, bodies = [], defaultdict(list), defaultdict(int)
    chains = {}
    for packet in root.findall("packet"):
        physical = number(packet, "frame.number")
        for stream in packet.findall("./proto[@name='http2']/field[@name='http2.stream']"):
            if field(stream, "http2.magic", optional=True) is not None:
                continue
            kind = number(stream, "http2.type")
            sid = number(stream, "http2.streamid")
            port = number(packet, "tcp.srcport")
            flags = number(stream, "http2.flags")
            data_bytes = len(bytes.fromhex(payload(stream, "http2.data.data"))) if kind == 0 else 0
            control = None
            if kind == 4:
                control = [
                    [number(setting, "http2.settings.id"), int(list(setting)[1].get("show"))]
                    for setting in stream.findall("./field[@name='http2.settings']")
                ]
            elif kind == 3:
                control = number(stream, "http2.rst_stream.error")
            elif kind == 5:
                control = number(stream, "http2.push_promise.promised_stream_id")
            elif kind == 6:
                control = payload(stream, "http2.pong" if flags & 1 else "http2.ping")
            elif kind == 7:
                control = [
                    number(stream, "http2.goaway.last_stream_id"),
                    number(stream, "http2.goaway.error"),
                ]
            elif kind == 8:
                control = number(stream, "http2.window_update.window_size_increment")
            elif kind == 2:
                control = [
                    number(stream, "http2.stream_dependency"),
                    number(stream, "http2.headers.weight_real"),
                    field(stream, "http2.exclusive") == "True",
                ]
            frames.append([
                physical, port, kind, sid, number(stream, "http2.length"),
                flags, number(stream, "http2.r") != 0, data_bytes, control,
            ])
            if kind == 0:
                bodies[(port, sid)] += data_bytes
            if kind in (1, 5, 9):
                if kind == 9:
                    key = chains[(port, sid)]
                else:
                    key = (port, control if kind == 5 else sid, "push" if kind == 5 else "headers")
                    chains[(port, sid)] = key
                for header in stream.findall("./field[@name='http2.header']"):
                    headers[key].append([
                        field(header, "http2.header.name", "value"),
                        field(header, "http2.header.value", "value"),
                    ])
                if flags & 4:
                    del chains[(port, sid)]
    assert not chains, "fixture has unfinished header blocks"
    return frames, dict(headers), dict(bodies)


def normalize_pcr(result):
    frames, headers, bodies = [], {}, {}
    for frame in result["frames"]:
        assert len(frame["sources"]) == 1, "these fixtures use one physical source per HTTP/2 frame"
        kind = frame["frame_type"]
        control = frame["control"]
        if kind == 4:
            value = [[setting["id"], setting["value"]] for setting in control["settings"]]
        elif kind == 3:
            value = control["error_code"]
        elif kind == 5:
            value = control["promised_stream_id"]
        elif kind == 6:
            value = control["opaque_hex"]
        elif kind == 7:
            value = [control["last_stream_id"], control["error_code"]]
        elif kind == 8:
            value = control["increment"]
        elif kind == 2:
            value = [control["dependency"], control["weight"], control["exclusive"]]
        else:
            value = None
        frames.append([
            frame["sources"][0]["number"], frame["flow"]["flow"]["source_port"],
            kind, frame["http2_stream_id"], frame["length"], frame["flags"],
            frame["reserved"], frame["data_bytes"], value,
        ])
        if kind == 0:
            assert control is None and frame["payload_wire_hex"] is None
    for message in result["messages"]:
        port = message["flow"]["flow"]["source_port"]
        sid = message["http2_stream_id"]
        assert message["status"] == "complete", message
        if message["upgrade_head"] is not None:
            continue
        key = (port, sid, "push" if message["kind"] == "push_promise" else "headers")
        assert key not in headers, "fixture has one message per direction and stream"
        headers[key] = [[h["name_hex"], h["value_hex"]] for h in message["headers"] + message["trailers"]]
        if message["body_bytes"]:
            bodies[(port, sid)] = message["body_bytes"]
    return frames, headers, bodies


def compare(name, pdml, document):
    root = ET.fromstring(pdml)
    result = document["result"]
    assert document["status"] == "success"
    assert result["issues"] == [], result["issues"]
    oracle, actual = normalize_oracle(root), normalize_pcr(result)
    for label, expected, observed in zip(("frames", "headers", "body_counts"), oracle, actual):
        assert expected == observed, f"{name}: {label}\nTShark={expected!r}\nPCR={observed!r}"
    assert len(result["connections"]) == 1
    connection = result["connections"][0]
    assert connection["status"] == "complete"
    assert connection["pending_settings"] == connection["pending_pings"] == 0
    assert connection["frames"] == result["summary"]["frames"] == len(oracle[0])
    assert result["summary"]["messages"] == len(result["messages"])
    if name == CAPTURES[0]:
        assert {frame[2] for frame in oracle[0]} == set(range(10))
        assert connection["startup"] == "prior_knowledge"
        assert connection["streams"] == result["summary"]["streams"] == 4
        stream3 = next(m for m in result["messages"] if m["http2_stream_id"] == 3 and m["kind"] == "request")
        assert [s["number"] for s in stream3["sources"]] == [9, 10]
        assert 8 in [s["number"] for s in stream3["compression_sources"]]
        assert connection["server_window"] == 65_535 - sum(oracle[2].values()) + 100
    else:
        request, = [m for m in result["messages"] if m["kind"] == "request"]
        assert connection["startup"] == "h2c"
        assert connection["streams"] == result["summary"]["streams"] == 1
        assert request["http2_stream_id"] == 1
        assert request["upgrade_head"]["start"]["method"] == field(root, "http.request.method")
        assert request["upgrade_head"]["start"]["target_hex"] == field(root, "http.request.uri", "value")
        assert request["body_bytes"] == len(bytes.fromhex(field(root, "http.file_data", "value"))) == 4
        assert connection["upgrade_response"]["start"]["status"] == number(root, "http.response.code") == 101
        assert connection["client_settings"]["header_table_size"] == 0
    return {
        "capture": name,
        "frames_compared": len(oracle[0]),
        "decoded_header_fields_compared": sum(len(headers) for headers in oracle[1].values()),
        "http2_body_bytes_compared": sum(oracle[2].values()),
        "status": "pass",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=ROOT / "target/debug/packetcraftr")
    parser.add_argument("--tshark", default="tshark")
    parser.add_argument("--directory", type=Path, default=ROOT / "target/http2-oracle")
    args = parser.parse_args()
    binary = args.binary.resolve()
    version = execute([args.tshark, "--version"]).decode().splitlines()[0]
    if " 4.6.4." not in version:
        raise RuntimeError(f"requires pinned TShark 4.6.4, found {version}")
    args.directory.mkdir(parents=True, exist_ok=True)
    binary_digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    report = {"oracle": version, "binary_sha256": binary_digest, "cases": []}
    for name in CAPTURES:
        capture = (ROOT / "examples/captures" / name).read_bytes()
        pdml = execute([args.tshark, "-n", "-r", "-", "-T", "pdml"], capture)
        output = execute([str(binary), "--output", "json", "http2", "-"], capture)
        (args.directory / f"{name}.pdml").write_bytes(pdml)
        (args.directory / f"{name}.json").write_bytes(output)
        case = compare(name, pdml, json.loads(output))
        case["capture_sha256"] = hashlib.sha256(capture).hexdigest()
        report["cases"].append(case)
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == binary_digest, "binary changed during comparison"
    report["status"] = "pass"
    (args.directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
