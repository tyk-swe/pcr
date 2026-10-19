import argparse
import hashlib
import importlib.util
import pathlib

from script_support import prepare_report, same_json, write_json_atomic
from validation_evidence import valid_digest

ROOT = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("benchmark_scanner", ROOT / "benchmark-scanner.py")
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)
MAX_REPORT_BYTES = 32 * 1024 * 1024
TARGETS = {
    "status": "proposed_nonregression_budgets_not_optimization_acceptance",
    "accuracy": "every exercised candidate cell matches the independently authored corpus",
    "work": "candidate median work does not exceed fixed median work on each identical cell",
    "latency": "candidate median workflow latency <= fixed median * 1.5 + 1000000 ns",
    "peak_memory": "candidate median peak child RSS <= fixed median peak child RSS + 8388608 bytes",
}


def load(path):
    with path.open("rb") as source:
        raw = source.read(MAX_REPORT_BYTES + 1)
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError("benchmark report exceeds 32 MiB")
    value = benchmark.strict_json(raw)
    if value["schema"] != "packetcraftr.scanner-benchmark/v1":
        raise ValueError("unknown benchmark report contract")
    if value.get("setup_error") or value.get("status") not in ("exercised", "incomplete"):
        raise ValueError("a failed benchmark cannot establish scheduling evidence")
    return value, hashlib.sha256(raw).hexdigest()


def key(row):
    for field in ("workflow", "id", "family"):
        if not isinstance(row.get(field), str) or not row[field]:
            raise ValueError(f"case {field} must be a non-empty string")
    if row["workflow"] == "tcp_connect":
        if row.get("transport") is not None or row.get("window") is not None:
            raise ValueError("connect case must not invent packet scheduling fields")
    else:
        benchmark.require_integer(row.get("window"), "window")
        if not isinstance(row.get("transport"), str):
            raise ValueError("packet case transport must be a string")
    return tuple(row.get(field) for field in ("workflow", "id", "family", "transport", "window"))


def rows(report):
    grouped = {}
    seen = set()
    repetitions = benchmark.require_integer(report["repetitions"], "repetitions")
    if not 1 <= repetitions <= 10:
        raise ValueError("repetitions must be within 1..=10")
    for row in report["cases"]:
        identity = key(row)
        repetition = benchmark.require_integer(row["repetition"], "repetition")
        if repetition >= repetitions or (identity, repetition) in seen:
            raise ValueError("duplicate or out-of-range case repetition")
        seen.add((identity, repetition))
        if row["status"] not in ("exercised", "unavailable", "failed"):
            raise ValueError("unknown case status")
        grouped.setdefault(identity, []).append(row)
    if not grouped or any(len(group) != repetitions for group in grouped.values()):
        raise ValueError("benchmark omitted a case repetition")
    expected = set()
    for family in ("ipv4", "ipv6"):
        expected.update({
            ("raw_scan", condition, family, transport, window)
            for condition in benchmark.CONDITIONS
            for transport in ("tcp", "udp", "icmp") for window in (1, 2)
        })
        expected.update(("traceroute", condition, family, transport, 1)
                        for condition in ("responsive", "silent") for transport in ("tcp", "udp", "icmp"))
        expected.update(("tcp_connect", condition, family, None, None)
                        for condition in ("connect-responsive", "connect-closed"))
    if expected != grouped.keys():
        raise ValueError("benchmark omitted or invented a declared scanner fixture cell")
    return grouped


def median(group, field):
    twice = benchmark.median_twice(row[field] for row in group)
    return twice // 2 if twice % 2 == 0 else twice / 2


def compare(baseline, candidate):
    if baseline.get("scheduling_mode", "fixed") != "fixed" or candidate.get("scheduling_mode") != "adaptive":
        raise ValueError("comparison requires a fixed baseline and an explicitly adaptive candidate")
    for report in (baseline, candidate):
        if not valid_digest(report.get("corpus_sha256")):
            raise ValueError("comparison requires the exact corpus SHA-256")
        if not isinstance(report.get("platform"), str) or not report["platform"].strip():
            raise ValueError("comparison requires a named platform")
        if not isinstance(report.get("settings"), dict) or not report["settings"]:
            raise ValueError("comparison requires explicit hard settings")
    for field in ("platform", "settings", "corpus_sha256", "repetitions"):
        if field not in baseline or field not in candidate or not same_json(baseline[field], candidate[field]):
            raise ValueError(f"comparison differs in {field}; rerun with identical fixtures and settings")
    fixed, adaptive = rows(baseline), rows(candidate)
    if fixed.keys() != adaptive.keys():
        raise ValueError("baseline and candidate fixture cells differ")
    cells = []
    for identity in sorted(fixed, key=lambda item: tuple(str(part) for part in item)):
        left, right = fixed[identity], adaptive[identity]
        cell = dict(zip(("workflow", "id", "family", "transport", "window"), identity))
        cells.append(cell)
        if any(row["status"] == "failed" for row in left + right):
            cell.update(status="failed", reason="fixture execution failed")
            continue
        if any(row["status"] != "exercised" for row in left + right):
            cell.update(status="unavailable", reason="not every repetition exercised the same fixture")
            continue
        if any(type(row.get("correct")) is not bool for row in left + right):
            raise ValueError("accuracy must be an explicit boolean")
        if not isinstance(left[0].get("expected"), dict) or not left[0]["expected"]:
            raise ValueError("comparison requires independent fixture expectations")
        if any(not same_json(row.get("expected"), left[0].get("expected")) for row in left + right):
            raise ValueError("independent fixture expectations changed between repetitions")
        if any(row.get("execution") != left[0].get("execution") for row in left + right):
            raise ValueError("execution surface changed between repetitions")
        expected_execution = "native_loopback" if identity[0] == "tcp_connect" else "injected_provider"
        if left[0].get("execution") != expected_execution:
            raise ValueError("fixture execution surface disagrees with the declared workflow")
        if not all(row["correct"] for row in left + right):
            cell.update(status="failed", reason="fixture accuracy failed")
            continue
        if any(row.get("peak_process_memory_bytes") is None for row in left + right):
            cell.update(status="unavailable", reason="exact-process peak memory method unavailable")
            continue
        metrics = ("workflow_elapsed_ns", "work_sent", "retained_state_charged_bytes", "peak_process_memory_bytes")
        cell["baseline_medians"] = {field: median(left, field) for field in metrics}
        cell["candidate_medians"] = {field: median(right, field) for field in metrics}
        # Keep budget decisions exact even when a displayed half-median is
        # rounded by JSON's floating-point representation.
        before = {field: benchmark.median_twice(row[field] for row in left) for field in metrics}
        after = {field: benchmark.median_twice(row[field] for row in right) for field in metrics}
        cell["checks"] = dict(
            baseline_accuracy=all(row["correct"] for row in left),
            candidate_accuracy=all(row["correct"] for row in right),
            work=after["work_sent"] <= before["work_sent"],
            latency=after["workflow_elapsed_ns"] * 2 <= before["workflow_elapsed_ns"] * 3 + 4_000_000,
            peak_memory=after["peak_process_memory_bytes"] <= before["peak_process_memory_bytes"] + 2 * 8_388_608,
        )
        cell["status"] = "within_proposed_budgets" if all(cell["checks"].values()) else "outside_proposed_budgets"
    return dict(
        schema="packetcraftr.scheduling-comparison/v1",
        platform=baseline["platform"], settings=baseline["settings"],
        corpus_sha256=baseline["corpus_sha256"], targets=TARGETS, cells=cells,
        status=("failed" if any(cell["status"] in ("failed", "outside_proposed_budgets") for cell in cells)
                else "incomplete" if any(cell["status"] == "unavailable" for cell in cells) else "measured"),
        optimization_accepted=False,
        limitations=[
            "Single-probe fixtures measure preservation, not multi-host adaptive throughput.",
            "Proposed budgets require review before optimization acceptance.",
            "A platform report is not runtime evidence for either other supported platform.",
            "Logical retained-byte charges are separate from exact-process peak memory.",
        ],
    )


def main():
    parser = argparse.ArgumentParser(description="Compare frozen fixed and adaptive scanner measurements without claiming optimization acceptance.")
    parser.add_argument("--baseline", type=pathlib.Path, required=True)
    parser.add_argument("--candidate", type=pathlib.Path, required=True)
    parser.add_argument("--report", type=pathlib.Path, required=True)
    args = parser.parse_args()
    try:
        prepare_report(args.report, args.baseline, args.candidate)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    report = dict(schema="packetcraftr.scheduling-comparison/v1", status="failed",
                  optimization_accepted=False)
    try:
        baseline, baseline_digest = load(args.baseline)
        candidate, candidate_digest = load(args.candidate)
        report = compare(baseline, candidate)
        report.update(baseline_sha256=baseline_digest, candidate_sha256=candidate_digest)
    except (KeyError, TypeError, ValueError, OSError) as error:
        report["error"] = str(error)
    write_json_atomic(args.report, report)
    print(args.report)
    return 0 if report["status"] == "measured" else 1


if __name__ == "__main__":
    raise SystemExit(main())
