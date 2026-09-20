#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Opt-in native capture checks on an operator-authorized isolated loopback adapter.

Requires the installed backend/driver and privileges. Does not send traffic.
Output can contain captured data: retain the private evidence directory locally.
This is not a substitute for the isolated Linux native contract inventory.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import platform

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("regression", ROOT / "scripts/forwarding-regression.py")
REGRESSION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REGRESSION)


def terminal(path):
    result = None
    with path.open("rb") as source:
        for sequence, line in enumerate(iter(lambda: source.readline(16 * 1024 * 1024 + 1), b"")):
            if len(line) > 16 * 1024 * 1024 or not line.endswith(b"\n") or result is not None:
                raise ValueError("invalid or oversized capture stream")
            try:
                row = json.loads(
                    line, object_pairs_hook=REGRESSION.CONSUMER.unique_object,
                    parse_constant=REGRESSION.CONSUMER.reject_constant,
                )
            except (UnicodeError, ValueError, RecursionError) as error:
                raise ValueError(f"invalid capture JSON: {error}") from error
            if not isinstance(row, dict):
                raise ValueError("capture envelope must be an object")
            if (row.get("schema") != "packetcraftr.output/v6" or row.get("command") != "capture"
                    or type(row.get("sequence")) is not int or row["sequence"] != sequence):
                raise ValueError("unexpected capture envelope")
            if row.get("event") in ("complete", "error"):
                result = row
    if result is None:
        raise ValueError("missing capture terminal event")
    return result


def completed_sources(row):
    if row.get("event") != "complete" or row.get("status") != "success":
        raise ValueError("capture did not complete")
    sources = row["result"]["sources"]
    if not isinstance(sources, list) or len(sources) != 1 or not all(
        isinstance(source, dict) and all(
            source.get(field) is True for field in ("ready", "shutdown_confirmed", "metadata_valid")
        )
        for source in sources
    ):
        raise ValueError("activation, metadata, or shutdown was not confirmed")
    return sources


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--interface", required=True, help="explicit isolated loopback adapter name or index")
    parser.add_argument("--authorize-isolated-loopback", action="store_true", required=True)
    parser.add_argument("--output", type=Path, required=True, help="new evidence directory")
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, exist_ok=False)
    binary = args.binary.resolve(strict=True)
    report = {"platform": platform.platform(), "binary_sha256": REGRESSION.digest(binary),
              "authorization": "operator-confirmed isolated loopback", "interface": args.interface,
              "traffic_generated": False, "scenarios": [], "cancellation": {
                  "status": "not_exercised",
                  "reason": "use the backend-specific cancellation contract; process signals alone do not prove idle readiness"
              }}
    base = [str(binary), "--output", "ndjson", "capture", "--interface", args.interface,
            "--timeout-ms", "200", "--capture-filter", "udp port 65534"]
    scenarios = [
        ("activation", []), ("reopen-after-shutdown", []),
        ("requested-settings", ["--capture-buffer-bytes", "1048576", "--timestamp-precision", "micro"]),
        ("filter-error", ["--capture-filter", "udp and ("]),
        ("reopen-after-filter-error", []),
    ]
    failed = False
    for name, extra in scenarios:
        scenario = {"name": name, "status": "not_exercised"}
        report["scenarios"].append(scenario)
        argv = base.copy()
        if name == "filter-error":
            argv = argv[:-2]  # Replace, rather than duplicate, the existing BPF argument.
        argv += extra
        scenario["argv"] = argv
        try:
            stdout, stderr = args.output / f"{name}.ndjson", args.output / f"{name}.stderr"
            code, elapsed = REGRESSION.run_bounded(argv, stdout, stderr, seconds=10)
            row = terminal(stdout)
            scenario.update(exit_code=code, elapsed_seconds=elapsed,
                            output_sha256=REGRESSION.digest(stdout))
            if name == "filter-error":
                if code == 0 or row.get("status") != "error" or not row.get("error", {}).get("code"):
                    raise ValueError("invalid filter did not produce a typed failure")
            else:
                if code:
                    raise ValueError("native capture process failed")
                sources = completed_sources(row)
                scenario["sources"] = sources
                if name == "requested-settings":
                    settings = sources[0]["capture_settings"]
                    for field, requested in (("buffer_size", 1048576), ("timestamp_precision", "micro")):
                        if settings[field]["requested"] != requested or settings[field]["applied"] != requested:
                            raise ValueError(f"{field} request was not reported as applied")
                    # effective=null is preserved; it is not invented from the request.
            scenario["status"] = "passed"
        except (OSError, ValueError, KeyError, RuntimeError) as error:
            scenario.update(status="failed", error=str(error))
            failed = True
    report["status"] = "failed" if failed else "capture_smoke_passed"
    report["note"] = "Only these passive capture scenarios were exercised; cancellation and active native I/O are not certified."
    REGRESSION.write_manifest(args.output, report)
    print(args.output / "manifest.json")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
