#!/usr/bin/env python3
"""Measure bounded scanner fixtures; independent corpus expectations are the oracle."""
import argparse
import errno
import hashlib
import ipaddress
import json
import os
import pathlib
import platform
import re
import socket
import subprocess
import threading
import time
import xml.etree.ElementTree as ET

from validation_evidence import ROOT, digest

OUTPUT_LIMIT = 1024 * 1024
PROCESS_TIMEOUT = 15
CONDITIONS = ("responsive", "closed", "blocked", "silent", "malformed", "unrelated")
DISCOVERY_CONDITIONS = tuple("discovery-" + name for name in (
    "responsive", "closed-but-responsive", "silent", "blocked", "routed", "shared-link-address"))


class FixtureUnavailable(Exception):
    pass


def fixture_socket(family, address):
    fixture = None
    try:
        fixture = socket.socket(family, socket.SOCK_STREAM)
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            fixture.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        fixture.bind((address, 0))
        return fixture
    except OSError as error:
        if fixture is not None:
            fixture.close()
        if error.errno in (errno.EADDRNOTAVAIL, errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT):
            raise FixtureUnavailable(f"cannot provision {address} loopback fixture: {error}") from error
        raise


def strict_json(text):
    def object_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key: {key}")
            value[key] = item
        return value

    def invalid_constant(value):
        raise ValueError(f"non-finite JSON constant: {value}")

    return json.loads(text, object_pairs_hook=object_pairs, parse_constant=invalid_constant)


def load_corpus(path):
    with path.open("rb") as source:
        raw = source.read(OUTPUT_LIMIT + 1)
    if len(raw) > OUTPUT_LIMIT:
        raise ValueError("corpus exceeds one MiB")
    corpus = strict_json(raw)
    if corpus["schema"] != "packetcraftr.scanner-corpus/v1":
        raise ValueError("unsupported scanner corpus")
    if corpus["families"] != ["ipv4", "ipv6"] or corpus["transports"] != ["tcp", "udp", "icmp"]:
        raise ValueError("corpus must cover both families and all scanner transports")
    windows = corpus["request"]["windows"]
    if windows != [1, 2] or any(type(window) is not int for window in windows):
        raise ValueError("corpus must contain both scheduling windows [1, 2]")
    if [case["id"] for case in corpus["scenarios"]] != list(CONDITIONS):
        raise ValueError("corpus must contain the complete, ordered independent inventory")
    if [case["id"] for case in corpus["native_connect_scenarios"]] != ["connect-responsive", "connect-closed"]:
        raise ValueError("corpus must contain both native connect conditions")
    if [case["id"] for case in corpus["traceroute_scenarios"]] != ["responsive", "silent"]:
        raise ValueError("corpus must contain both first-hop traceroute conditions")
    if [case["id"] for case in corpus.get("target_planning_scenarios", [])] != [
            "numeric-source-equivalence", "numeric-narrowing", "manifest-boundaries",
            "scoped-host-local", "scoped-isolated-links"]:
        raise ValueError("corpus must contain the complete target-planning fixture inventory")
    if "adaptive_scheduling_scenarios" in corpus and [
            case["id"] for case in corpus["adaptive_scheduling_scenarios"]] != [
            "adaptive-responsive", "adaptive-selective-retry", "adaptive-rate-limited-control",
            "adaptive-fair-hosts", "adaptive-host-deadline", "adaptive-window-loss",
            "adaptive-connect-cleanup", "adaptive-plan-boundary"]:
        raise ValueError("adaptive scheduling inventory must contain each authored condition once in order")
    for family, addresses in corpus["fixture_addresses"].items():
        network = ipaddress.ip_network("192.0.2.0/24" if family == "ipv4" else "2001:db8::/32")
        if any(ipaddress.ip_address(value) not in network for value in addresses.values()):
            raise ValueError("injected fixtures must use documentation addresses")
    if "discovery_scenarios" in corpus:
        if [case["id"] for case in corpus["discovery_scenarios"]] != list(DISCOVERY_CONDITIONS):
            raise ValueError("corpus must contain the complete, ordered discovery inventory")
        for case in corpus["discovery_scenarios"]:
            if case["families"] != ["ipv4", "ipv6"]:
                raise ValueError("discovery conditions must cover both address families")
    return corpus, hashlib.sha256(raw).hexdigest()


def measured(command):
    started = time.monotonic_ns()
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=ROOT)
    buffers = [bytearray(), bytearray()]
    overflow = threading.Event()

    def drain(pipe, destination):
        with pipe:
            while block := pipe.read(8192):
                if len(destination) + len(block) > OUTPUT_LIMIT:
                    overflow.set()
                    process.kill()
                    return
                destination.extend(block)

    readers = [threading.Thread(target=drain, args=(pipe, output), daemon=True)
               for pipe, output in zip((process.stdout, process.stderr), buffers)]
    for reader in readers:
        reader.start()
    peak = None
    failure = None
    deadline = time.monotonic() + PROCESS_TIMEOUT
    try:
        if hasattr(os, "wait4"):
            while True:
                pid, status, usage = os.wait4(process.pid, os.WNOHANG)
                if pid:
                    process.returncode = os.waitstatus_to_exitcode(status)
                    peak = int(usage.ru_maxrss) * (1 if platform.system() == "Darwin" else 1024)
                    break
                if time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired(command, PROCESS_TIMEOUT)
                time.sleep(0.001)
        else:
            process.wait(timeout=PROCESS_TIMEOUT)
    except BaseException as error:
        process.kill()
        process.wait()
        failure = error
    finally:
        for reader in readers:
            reader.join(timeout=2)
    if failure is not None:
        if isinstance(failure, subprocess.TimeoutExpired):
            failure.output = buffers[0].decode('utf-8', errors='replace')
            failure.stderr = buffers[1].decode('utf-8', errors='replace')
        raise failure
    if any(reader.is_alive() for reader in readers) or overflow.is_set():
        raise ValueError("benchmark output exceeded its finite bound or did not close")
    return {
        "command": [str(value) for value in command],
        "exit_code": process.returncode,
        "elapsed_ns": time.monotonic_ns() - started,
        "peak_process_memory_bytes": peak,
        "peak_memory_method": "wait4.ru_maxrss" if peak is not None else "unavailable",
        "peak_memory_scope": "measured child process lifetime, including exec/runtime; not logical evidence charge",
        "stdout": buffers[0].decode("utf-8"),
        "stderr": buffers[1].decode("utf-8")
    }


def require_integer(value, label):
    if type(value) is not int or value < 0:
        raise ValueError(f"{label} must be a nonnegative integer")
    return value


def validate_packet(record, case, family, transport, window, adaptive=False):
    if (record["schema"] != "packetcraftr.scanner-fixture/v1"
            or record.get("workflow") != "raw_scan" or type(record["window"]) is not int):
        raise ValueError("fixture executable published an unknown contract")
    if (record["scenario"], record["family"], record["transport"], record["window"]) != (
            case["id"], family, transport, window):
        raise ValueError("fixture identity disagrees with requested condition")
    if record["execution"] != "injected_provider":
        raise ValueError("packet fixtures must not be relabeled native runtime evidence")
    if record.get("scheduling_mode", "fixed") != ("adaptive" if adaptive else "fixed"):
        raise ValueError("fixture scheduling mode disagrees with the requested mode")
    observation = record["observation"]
    if type(observation["attributed_response"]) is not bool:
        raise ValueError("packet attribution must be a boolean")
    expected = case.get("expected_by_transport", {}).get(transport, case["expected"])
    correct = (observation["classification"] == expected["attempt_classification"]
               and observation["status"] == expected["status"]
               and observation["attributed_response"] is expected["attributed_response"])
    work = require_integer(record["packets_completed"], "packets_completed")
    if work != 1 or require_integer(record["packets_attempted"], "packets_attempted") != 1:
        raise ValueError("single-probe fixture work accounting is incoherent")
    charged = require_integer(record["retained_evidence_bytes"], "retained_evidence_bytes")
    frames = record["retained_frames_hex"]
    if not isinstance(frames, list) or any(not isinstance(frame, str) or not re.fullmatch(
            r"(?:[0-9a-f]{2})*", frame) for frame in frames):
        raise ValueError("fixture lacks exact retained wire frames")
    if charged != sum(len(frame) // 2 for frame in frames) or charged > 65536:
        raise ValueError("retained wire-frame charges disagree with preserved evidence")
    delivered = record["delivered_frames_hex"]
    count = 0 if case["id"] == "silent" else 1
    if (not isinstance(delivered, list) or len(delivered) != count or any(
            not isinstance(frame, str) or not re.fullmatch(r"(?:[0-9a-f]{2})+", frame)
            for frame in delivered)):
        raise ValueError("packet fixture acquisition disagrees with the provisioned frame count")
    if case["id"] == "malformed" and delivered != ["45" if family == "ipv4" else "60"]:
        raise ValueError("malformed fixture did not preserve its exact one-byte acquisition")
    if len(frames) > len(delivered) or any(frame not in delivered for frame in frames):
        raise ValueError("retained packet evidence was not acquired by this fixture")
    if observation["attributed_response"] and not frames:
        raise ValueError("an attributed packet response lacks its retained wire frame")
    return dict(correct=correct, work_sent=work, retained_state_charged_bytes=charged,
                retained_charge_scope="workflow retained exact frame bytes; excludes allocator/struct overhead",
                workflow_elapsed_ns=require_integer(record["workflow_elapsed_ns"], "workflow_elapsed_ns"),
                observation=observation, expected=expected, fixture=record)


def validate_trace(record, case, family, transport):
    expected = dict(termination=case["expected_termination"], status=case["expected_status"],
                    attributed_response=case["expected_attributed_response"])
    if (record["schema"] != "packetcraftr.scanner-fixture/v1"
            or record.get("workflow") != "traceroute"
            or type(record["window"]) is not int
            or (record["scenario"], record["family"], record["transport"], record["window"]) != (
                case["id"], family, transport, 1)
            or record["execution"] != "injected_provider"):
        raise ValueError("traceroute fixture identity or execution is incoherent")
    observation = record["observation"]
    if type(observation["attributed_response"]) is not bool:
        raise ValueError("traceroute attribution must be a boolean")
    if any(require_integer(record[field], field) != 1 for field in ("packets_attempted", "packets_completed")):
        raise ValueError("one-hop traceroute fixture must send exactly one probe")
    frames = record["retained_frames_hex"]
    if not isinstance(frames, list) or any(not isinstance(frame, str) or not re.fullmatch(
            r"(?:[0-9a-f]{2})*", frame) for frame in frames):
        raise ValueError("traceroute fixture lacks exact retained wire frames")
    charged = require_integer(record["retained_evidence_bytes"], "retained_evidence_bytes")
    if charged != sum(len(frame) // 2 for frame in frames) or charged > 65536:
        raise ValueError("traceroute evidence charge disagrees with its preserved frames")
    delivered = record["delivered_frames_hex"]
    if (not isinstance(delivered, list) or len(delivered) != (0 if case["id"] == "silent" else 1)
            or any(not isinstance(frame, str) or not re.fullmatch(
                r"(?:[0-9a-f]{2})+", frame) for frame in delivered)):
        raise ValueError("traceroute fixture lacks its exact acquisition inventory")
    if len(frames) > len(delivered) or any(frame not in delivered for frame in frames):
        raise ValueError("retained traceroute evidence was not acquired by this fixture")
    if observation["attributed_response"] and not frames:
        raise ValueError("an attributed traceroute response lacks its retained wire frame")
    return dict(correct=observation == expected, work_sent=1, retained_state_charged_bytes=charged,
                retained_charge_scope="workflow retained exact frame bytes; excludes allocator/struct overhead",
                workflow_elapsed_ns=require_integer(record["workflow_elapsed_ns"], "workflow_elapsed_ns"),
                observation=observation, expected=expected, fixture=record)


def duration_ns(duration):
    seconds = require_integer(duration["secs"], "duration seconds")
    nanos = require_integer(duration["nanos"], "duration nanoseconds")
    if nanos >= 1_000_000_000:
        raise ValueError("duration nanoseconds are not normalized")
    return seconds * 1_000_000_000 + nanos


def nmap_identity(binary, expected):
    result = measured([binary, "--version"])
    if result["exit_code"] != 0 or not re.search(
            r"^Nmap version " + re.escape(expected) + r"(?:\s|$)", result["stdout"], re.M):
        raise ValueError("Nmap executable does not match the corpus's pinned version")
    return dict(version=expected, binary_sha256=digest(binary), build_features=result["stdout"],
                acquisition="operator-provided executable; not vendored")


def connect_case(binary, corpus, case, family, nmap, adaptive=False):
    version = socket.AF_INET if family == "ipv4" else socket.AF_INET6
    address = "127.0.0.1" if family == "ipv4" else "::1"
    with fixture_socket(version, address) as fixture:
        if case["id"] == "connect-responsive":
            fixture.listen(8)
        port = fixture.getsockname()[1]
        command = [binary, "--output", "json", "scan", address, "--connect", "--ports", str(port),
                   "--attempts", "1", "--max-probes", "1", "--max-in-flight", "1",
                   "--timeout-ms", "1000", "--max-duration-ms", "2000"]
        if adaptive:
            command.append("--adaptive")
        run = measured(command)
        if run["exit_code"] != 0:
            raise ValueError(f"native connect execution failed: {run['stderr']} {run['stdout']}")
        envelope = strict_json(run["stdout"])
        if (envelope["schema"] not in ("packetcraftr.output/v9", "packetcraftr.output/v10", "packetcraftr.output/v11")
                or envelope["status"] != "success" or envelope["command"] != "scan"):
            raise ValueError("native connect did not publish a successful scan envelope")
        result = envelope["result"]
        if envelope["schema"] in ("packetcraftr.output/v10", "packetcraftr.output/v11"):
            if result["scheduling"]["mode"] != ("adaptive" if adaptive else "fixed"):
                raise ValueError("connect scheduling mode disagrees with the requested mode")
        if adaptive:
            if envelope["schema"] not in ("packetcraftr.output/v10", "packetcraftr.output/v11"):
                raise ValueError("adaptive connect requires the v10 scheduling contract")
        endpoints = result["endpoints"]
        if result["method"] != "tcp_connect" or len(endpoints) != 1 or len(endpoints[0]["probes"]) != 1:
            raise ValueError("native connect fixture has unexpected endpoint/attempt cardinality")
        endpoint, probe = endpoints[0], endpoints[0]["probes"][0]
        if endpoint["address"] != address or endpoint["port"] != port or probe["attempted"] is not True:
            raise ValueError("native connect fixture endpoint or attempted evidence is incoherent")
        stats = result["socket_stats"]
        if any(require_integer(stats[field], field) != 1 for field in (
                "connections_scheduled", "connections_attempted")):
            raise ValueError("native connect fixture must attempt exactly one connection")
        charged = require_integer(stats["retained_evidence_bytes"], "retained_evidence_bytes")
        if charged == 0:
            raise ValueError("the retained connect probe lacks its logical evidence charge")
        if require_integer(stats["connections_succeeded"], "connections_succeeded") != (
                1 if probe["outcome"] == "connected" else 0):
            raise ValueError("connect work accounting contradicts its attempt outcome")
        run.update(correct=(probe["outcome"] == case["expected_outcome"]
                            and endpoint["classification"] == case["expected_classification"]),
                   work_sent=1, retained_state_charged_bytes=charged,
                   retained_charge_scope="workflow connect evidence charge; excludes allocator overhead",
                   workflow_elapsed_ns=duration_ns(stats["elapsed"]),
                   observation=dict(outcome=probe["outcome"], classification=endpoint["classification"]),
                   expected=dict(outcome=case["expected_outcome"], classification=case["expected_classification"]),
                   product_output=envelope, execution="native_loopback")
        if nmap:
            args = list(corpus["nmap"]["connect_arguments"])
            if family == "ipv6":
                args.append("-6")
            compared = measured([nmap, *args, "-p", str(port), address])
            if compared["exit_code"] != 0 or "<!ENTITY" in compared["stdout"].upper():
                raise ValueError("Nmap comparison failed or emitted an unsafe XML document")
            xml = ET.fromstring(compared["stdout"])
            hosts = xml.findall("./host")
            if xml.get("version") != corpus["nmap"]["version"] or len(hosts) != 1:
                raise ValueError("Nmap XML lacks the pinned version and exactly one fixture host")
            observed_addresses = [element.get("addr") for element in hosts[0].findall("./address")
                                  if element.get("addrtype") in ("ipv4", "ipv6")]
            ports = hosts[0].findall("./ports/port")
            if (observed_addresses != [address] or len(ports) != 1
                    or ports[0].get("protocol") != "tcp" or ports[0].get("portid") != str(port)):
                raise ValueError("Nmap comparison does not identify the held loopback fixture")
            states = [element.attrib["state"] for element in ports[0].findall("./state")]
            run["nmap"] = dict(**compared, observed_states=states, expected=case["nmap_expected"],
                               explained_divergence=case["divergence"],
                               agrees_with_fixture=(states == [case["nmap_expected"]]))
        return run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--fixture-binary", type=pathlib.Path)
    parser.add_argument("--nmap", type=pathlib.Path)
    parser.add_argument("--corpus", type=pathlib.Path, default=ROOT / "docs/scanner-corpus.v1.json")
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--report", type=pathlib.Path, required=True)
    parser.add_argument("--adaptive", action="store_true",
                        help="exercise opt-in scheduling on the same M2 fixtures and hard ceilings")
    args = parser.parse_args()
    if not 1 <= args.repetitions <= 10:
        parser.error("repetitions must be 1..=10")
    report = dict(schema="packetcraftr.scanner-benchmark/v1", platform=platform.platform(),
                  scheduling_mode="adaptive" if args.adaptive else "fixed",
                  measured_inventory="m2_single_probe_scan_connect_and_traceroute",
                  adaptive_scenario_performance="not_benchmarked",
                  repetitions=args.repetitions, cases=[], status="incomplete",
                  coverage_complete=False, comparison_complete=False, tools={})

    def tool(path, name):
        if path is None:
            report["tools"][name] = dict(status="unavailable", reason="no executable provided")
            return None
        path = path.resolve()
        if not path.is_file():
            report["tools"][name] = dict(status="unavailable", path=str(path),
                                        reason="provided executable is not a regular file")
            return None
        report["tools"][name] = dict(status="available", path=str(path), sha256=digest(path))
        return path

    try:
        corpus, corpus_digest = load_corpus(args.corpus)
        report.update(dataset_version=corpus["dataset_version"], corpus_sha256=corpus_digest,
                      settings=dict(raw=corpus["request"], connect=dict(
                          attempts=1, max_probes=1, max_in_flight=1,
                          timeout_ms=1000, max_duration_ms=2000)),
                      commit=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                      dirty=bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)))
        binary = tool(args.binary, "binary")
        args.fixture_binary = tool(args.fixture_binary, "fixture_binary")
        args.nmap = tool(args.nmap, "nmap")
        if binary:
            report["binary_sha256"] = report["tools"]["binary"]["sha256"]
        if args.fixture_binary:
            report["fixture_binary_sha256"] = report["tools"]["fixture_binary"]["sha256"]
        report["nmap"] = (nmap_identity(args.nmap, corpus["nmap"]["version"]) if args.nmap else
                          dict(status="unavailable", reason=report["tools"]["nmap"]["reason"]))
        for repetition in range(args.repetitions):
            for family in corpus["families"]:
                for case in corpus["native_connect_scenarios"]:
                    row = dict(id=case["id"], family=family, workflow="tcp_connect", repetition=repetition)
                    report["cases"].append(row)
                    if binary is None:
                        row.update(status="unavailable", reason="no PacketcraftR CLI executable")
                        continue
                    try:
                        row.update(connect_case(binary, corpus, case, family, args.nmap, args.adaptive),
                                   status="exercised")
                    except FixtureUnavailable as error:
                        row.update(status="unavailable", execution="native_loopback", reason=str(error))
                    except Exception as error:
                        row.update(status="failed", error=str(error))
                for transport in corpus["transports"]:
                    for window in corpus["request"]["windows"]:
                        for case in corpus["scenarios"]:
                            row = dict(id=case["id"], family=family, transport=transport, workflow="raw_scan",
                                       window=window, repetition=repetition)
                            report["cases"].append(row)
                            if not args.fixture_binary:
                                row.update(status="unavailable", reason="no injected-provider fixture executable")
                                continue
                            try:
                                command = [args.fixture_binary, case["id"], family, transport, str(window)]
                                if args.adaptive:
                                    command.append("adaptive")
                                run = measured(command)
                                if run["exit_code"] != 0:
                                    raise ValueError(f"fixture execution failed: {run['stderr']} {run['stdout']}")
                                run.update(validate_packet(strict_json(run["stdout"]), case, family, transport,
                                                           window, args.adaptive))
                                row.update(run, status="exercised", execution="injected_provider")
                            except Exception as error:
                                row.update(status="failed", error=str(error))
                    for case in corpus["traceroute_scenarios"]:
                        row = dict(id=case["id"], family=family, transport=transport,
                                   workflow="traceroute", window=1, repetition=repetition)
                        report["cases"].append(row)
                        if not args.fixture_binary:
                            row.update(status="unavailable", reason="no injected-provider fixture executable")
                            continue
                        try:
                            run = measured([args.fixture_binary, case["id"], family, transport, "1", "traceroute"])
                            if run["exit_code"] != 0:
                                raise ValueError(f"traceroute fixture failed: {run['stderr']} {run['stdout']}")
                            run.update(validate_trace(strict_json(run["stdout"]), case, family, transport))
                            row.update(run, status="exercised", execution="injected_provider")
                        except Exception as error:
                            row.update(status="failed", error=str(error))
        for family in corpus["families"]:
            for workflow in ("tcp_connect", "raw_scan", "traceroute"):
                rows = [row for row in report["cases"] if row["family"] == family
                        and row["workflow"] == workflow and row["status"] == "exercised"]
                report.setdefault("accuracy", []).append(dict(
                    family=family, workflow=workflow, correct=sum(row["correct"] for row in rows),
                    evaluated=len(rows), unavailable_or_failed=sum(
                        row["family"] == family and row["workflow"] == workflow
                        and row["status"] != "exercised" for row in report["cases"])))
        failed = any(row["status"] == "failed" or row.get("correct") is False for row in report["cases"])
        incomplete = any(row["status"] == "unavailable" or row.get("peak_process_memory_bytes") is None
                         for row in report["cases"])
        report["status"] = "failed" if failed else "incomplete" if incomplete else "exercised"
        report["coverage_complete"] = all(row["status"] == "exercised" for row in report["cases"])
        report["comparison_complete"] = bool(args.nmap) and all(
            row["status"] == "exercised" and "nmap" in row
            for row in report["cases"] if row["workflow"] == "tcp_connect")
    except Exception as error:
        report.update(status="failed", setup_error=str(error))
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(args.report)
    return 1 if report["status"] != "exercised" else 0


if __name__ == "__main__":
    raise SystemExit(main())
