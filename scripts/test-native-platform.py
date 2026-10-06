#!/usr/bin/env python3
"""Reviewed, host-local macOS/Windows native routes; never substitutes for Linux namespaces."""
import argparse
import ctypes
import json
import os
import pathlib
import platform
import re
import subprocess
import uuid

from native_platform_evidence import PROFILES, SCENARIOS, SCHEMA, scoped_paths, status_of, validate
from validation_evidence import ROOT, digest

FEATURES = {
    "portable": ["--no-default-features"],
    "default": [],
    "layer2": ["--no-default-features", "--features", "native-layer2"],
    "pcap-free": ["--no-default-features", "--features", "native-layer3"],
    "full-native": ["--all-features"],
}
MARKER = "PACKETCRAFTR_NATIVE_UNAVAILABLE="
MAX_OUTPUT_BYTES = 1024 * 1024


def current_platform():
    return {"Darwin": "macOS", "Windows": "Windows", "Linux": "Linux"}.get(platform.system())


def privileged():
    if current_platform() == "macOS":
        return os.geteuid() == 0
    if current_platform() == "Windows":
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    return False


def unavailable(scenario, code, reason):
    scenario.update(status="unavailable", reason_code=code, reason=reason)


def unavailable_report(reason):
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, timeout=30).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, timeout=30))
    corpus_path = ROOT / "docs/scanner-corpus.v1.json"
    corpus = json.loads(corpus_path.read_bytes())
    return dict(schema=SCHEMA, platform=current_platform(), commit=commit, dirty=dirty,
                corpus_sha256=digest(corpus_path), corpus_dataset_version=corpus["dataset_version"],
                isolation=dict(kind="host_local_only" if current_platform() != "Linux" else "unavailable",
                               external_destinations=False, interface_mutation=False),
                profiles=[dict(name=profile, status="incomplete", scenarios=[
                    dict(name=name, status="unavailable", reason_code="runtime_evidence_missing", reason=reason)
                    for name in SCENARIOS]) for profile in PROFILES], status="incomplete")


def build(profile, report):
    arguments = FEATURES[profile]
    command = ["cargo", "build", "--locked", "-p", "packetcraftr-cli", *arguments, "--message-format=json"]
    compiled = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=900)
    report["cli_build"] = dict(command=command, exit_code=compiled.returncode,
                               stdout=compiled.stdout, stderr=compiled.stderr, execution="compilation")
    if compiled.returncode:
        raise RuntimeError("CLI profile build failed; compilation is not native evidence")
    binary, = [row["executable"] for row in map(json.loads, compiled.stdout.splitlines())
               if row.get("reason") == "compiler-artifact" and row.get("executable")
               and row.get("target", {}).get("name") == "packetcraftr"]
    test_arguments = ["--features", "native-route"] if profile == "default" else arguments
    command = ["cargo", "test", "--locked", "-p", "packetcraftr-netio", *test_arguments,
               "--test", "native_loopback", "--no-run", "--message-format=json"]
    compiled = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=900)
    report["test_build"] = dict(command=command, exit_code=compiled.returncode,
                                stdout=compiled.stdout, stderr=compiled.stderr, execution="compilation")
    if compiled.returncode:
        raise RuntimeError("native test profile build failed; compilation is not native evidence")
    test_binary, = [row["executable"] for row in map(json.loads, compiled.stdout.splitlines())
                    if row.get("reason") == "compiler-artifact" and row.get("executable")
                    and row.get("target", {}).get("name") == "native_loopback"]
    report.update(binary_sha256=digest(binary), test_binary_sha256=digest(test_binary))
    return pathlib.Path(binary), pathlib.Path(test_binary)


def run_scenario(binary, test_binary, scenario, token):
    name = scenario["name"]
    if name == "iface_disappearance_driver_fail_cleans_up":
        unavailable(scenario, "isolation_unavailable",
                    "Host loopback route forbids interface mutation; no disposable interface isolation is provisioned.")
        return
    command = [str(test_binary), "--ignored", "--exact", name, "--nocapture", "--test-threads=1"]
    env = dict(os.environ, PACKETCRAFTR_NATIVE_LOOPBACK_TOKEN=token,
               PACKETCRAFTR_NATIVE_LOOPBACK_PLATFORM=current_platform(), PACKETCRAFTR_NATIVE_CLI=str(binary))
    scenario.update(command=command, execution="privileged_native", privilege_granted=True)
    for field in ("reason", "reason_code"):
        scenario.pop(field, None)
    try:
        completed = subprocess.run(command, env=env, cwd=ROOT, capture_output=True, text=True, timeout=30)
        scenario.update(exit_code=completed.returncode, stdout=completed.stdout, stderr=completed.stderr)
        if len(completed.stdout.encode()) + len(completed.stderr.encode()) > MAX_OUTPUT_BYTES:
            raise RuntimeError("native scenario output exceeds finite evidence bound")
        markers = [line.split(MARKER, 1)[1] for line in completed.stdout.splitlines() if MARKER in line]
        if completed.returncode != 0:
            scenario.update(status="failed", error="native scenario process failed")
        elif markers:
            if len(markers) != 1:
                raise RuntimeError("native scenario emitted ambiguous unavailable reasons")
            reason = json.loads(markers[0])
            unavailable(scenario, reason["reason_code"], reason["reason"])
        elif re.search(r"\b1 passed; 0 failed; 0 ignored;", completed.stdout):
            scenario["status"] = "exercised"
            if name == "scoped_ipv6_targets":
                scenario["scoped_paths"] = scoped_paths(completed.stdout)
        else:
            scenario.update(status="failed", error="zero exit without exactly one exercised test")
    except subprocess.TimeoutExpired as error:
        def text(value):
            return value.decode(errors="replace") if isinstance(value, bytes) else value or ""
        scenario.update(status="failed", exit_code=-1, error="native scenario exceeded 30-second deadline",
                        stdout=text(error.stdout), stderr=text(error.stderr))
    except Exception as error:
        scenario.update(status="failed", exit_code=scenario.get("exit_code", -1), error=str(error),
                        stdout=scenario.get("stdout", ""), stderr=scenario.get("stderr", ""))


def execute(args, report):
    if current_platform() not in ("macOS", "Windows"):
        raise RuntimeError("use test-native-isolated.py on Linux; this route admits only macOS or Windows")
    if args.emit_unavailable:
        return
    if not args.reviewed_commit or not re.fullmatch(r"[0-9a-f]{40}", args.reviewed_commit):
        raise RuntimeError("native execution requires a full reviewed commit identifier")
    if report["commit"] != args.reviewed_commit or report["dirty"]:
        raise RuntimeError("refusing native execution outside the clean reviewed checkout")
    if not privileged():
        for profile in report["profiles"]:
            for scenario in profile["scenarios"]:
                unavailable(scenario, "privilege_not_granted", "Root/administrator admission was not granted.")
        return
    report["reviewed_commit"] = args.reviewed_commit
    token = str(uuid.uuid4())
    for profile in report["profiles"]:
        try:
            binary, test_binary = build(profile["name"], profile)
            listed = subprocess.check_output([test_binary, "--ignored", "--list"], cwd=ROOT,
                                              text=True, timeout=10)
            names = [line.removesuffix(": test") for line in listed.splitlines() if line.endswith(": test")]
            if sorted(names) != sorted(SCENARIOS):
                raise RuntimeError("native executable does not contain the exact declared scenario inventory")
            for scenario in profile["scenarios"]:
                if args.scenario == "all" or args.scenario == scenario["name"]:
                    run_scenario(binary, test_binary, scenario, token)
        except Exception as error:
            profile["error"] = str(error)
            for scenario in profile["scenarios"]:
                if scenario["status"] == "unavailable":
                    unavailable(scenario, "runtime_evidence_missing",
                                "Profile could not build or admit its exact test inventory: " + str(error))
        profile["status"] = status_of(profile["scenarios"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reviewed-commit")
    parser.add_argument("--scenario", choices=("all", *SCENARIOS), default="all",
                        help="run one scenario across all profiles; all others remain explicitly unexercised")
    parser.add_argument("--emit-unavailable", action="store_true",
                        help="publish honest unexercised inventory without building or running native code")
    parser.add_argument("--report", type=pathlib.Path, required=True)
    args = parser.parse_args()
    report = unavailable_report("Native route has not exercised this scenario.")
    try:
        execute(args, report)
    except Exception as error:
        report["error"] = str(error)
    finally:
        for profile in report["profiles"]:
            profile["status"] = status_of(profile["scenarios"])
        report["status"] = status_of([case for profile in report["profiles"] for case in profile["scenarios"]])
        try:
            validate(report, expected_commit=args.reviewed_commit)
        except ValueError as error:
            report["validation_error"] = str(error)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(args.report)
    return 1 if report.get("error") or report.get("validation_error") or report["status"] == "failed" or any(
        profile.get("error") for profile in report["profiles"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
