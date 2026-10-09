import argparse
import importlib.util
import json
import pathlib
import platform
import statistics

ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("scanner_measurements", ROOT / "scripts/benchmark-scanner.py")
measurements = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(measurements)

SCENARIOS = {
    "responsive-many": dict(ports=16, attempts=3, timeout_ms=20, max_duration_ms=2000,
                            max_prepared_bytes=1048576),
    "selective-silence": dict(ports=2, attempts=3, timeout_ms=20, max_duration_ms=2000,
                             max_prepared_bytes=1048576),
    "plan-retention": dict(ports=128, attempts=32, timeout_ms=5, max_duration_ms=60000,
                           max_prepared_bytes=131072),
}
LIMITATIONS = [
    "Both modes execute the current binary; the reference is its preserved fixed scheduling path.",
    "The frozen pre-change binary is measured separately by benchmark-scanner.py.",
    "These are real-clock injected packet providers, not native network throughput evidence.",
    "Three controlled scenarios do not establish every adaptive corpus behavior or platform gate.",
    "Latency/RSS nonregression budgets are proposed, not agreed optimization acceptance.",
    "Evidence-byte charges exclude scheduler preparation charges; exact-process RSS is separate.",
]


def expected(scenario, mode):
    config = SCENARIOS[scenario]
    rejected = scenario == "plan-retention" and mode == "fixed"
    attempts = config["attempts"] if mode == "fixed" else 1
    endpoints = {
        str(port): dict(classification="open", attempts=list(range(1, attempts + 1)))
        for port in range(9000, 9000 + config["ports"])
    }
    if scenario == "selective-silence":
        endpoints["9000"] = dict(classification="timeout", attempts=[1, 2, 3])
    return dict(status="rejected" if rejected else "success",
                endpoints={} if rejected else endpoints,
                work_sent=0 if rejected else sum(len(row["attempts"]) for row in endpoints.values()),
                error_code="policy.scan_pipeline_limit" if rejected else None)


def validate(record, scenario, family, mode):
    if (record.get("schema") != "packetcraftr.scheduling-fixture/v1"
            or record.get("scenario") != scenario or record.get("family") != family
            or record.get("scheduling_mode") != mode
            or record.get("execution") != "injected_provider_real_clock"):
        raise ValueError("fixture identity or execution surface disagrees")
    config = SCENARIOS[scenario]
    settings = dict(config, hosts=1, max_in_flight=2,
                    max_probes=config["ports"] * config["attempts"], max_evidence_bytes=1048576)
    if record.get("settings") != settings:
        raise ValueError("fixture changed the independently specified hard settings")
    oracle = expected(scenario, mode)
    work = measurements.require_integer(record["work_sent"], "work_sent")
    elapsed = measurements.require_integer(record["operation_elapsed_ns"], "operation_elapsed_ns")
    charged = measurements.require_integer(record["retained_evidence_charged_bytes"], "evidence charge")
    if elapsed > settings["max_duration_ms"] * 1_000_000:
        raise ValueError("operation exceeded the declared duration")
    if charged > settings["max_evidence_bytes"]:
        raise ValueError("fixture exceeded its evidence charge ceiling")
    if record.get("status") != oracle["status"] or work != oracle["work_sent"]:
        raise ValueError("fixture outcome or work disagrees with the independent oracle")
    if oracle["status"] == "rejected":
        if (record.get("error_code") != oracle["error_code"]
                or record.get("capture_sessions") != 0
                or "prepared" not in str(record.get("error_cause", "")).lower()):
            raise ValueError("oversized fixed plan did not fail before active capture/traffic")
    else:
        if (record.get("endpoints") != oracle["endpoints"]
                or record.get("incomplete") != [] or record.get("conditions") != []):
            raise ValueError("endpoint accuracy or scheduling evidence disagrees")
        peak = measurements.require_integer(record["observed_peak_window"], "observed peak")
        if not 1 <= peak <= settings["max_in_flight"]:
            raise ValueError("observed pending count exceeded its ceiling")
        retries = measurements.require_integer(record["retries_started"], "retries")
        if retries != work - settings["ports"]:
            raise ValueError("retry count disagrees with actual additional probe starts")
    return dict(correct=True, expected=oracle, settings=settings)


def run(binary, repetitions):
    digest = measurements.digest(binary)
    cases = []
    for scenario in SCENARIOS:
        for family in ("ipv4", "ipv6"):
            for mode in ("fixed", "adaptive"):
                for repetition in range(repetitions):
                    row = dict(scenario=scenario, family=family, scheduling_mode=mode,
                               repetition=repetition, status="failed")
                    cases.append(row)
                    try:
                        result = measurements.measured([str(binary), scenario, family, mode])
                        row.update(result)
                        if result["exit_code"] != 0:
                            raise ValueError(f"fixture failed: {result['stderr']}")
                        record = measurements.strict_json(result["stdout"])
                        row["record"] = record
                        row.update(**validate(record, scenario, family, mode), status="exercised")
                    except (ValueError, KeyError, TypeError, OSError) as error:
                        row["error"] = str(error)
    if measurements.digest(binary) != digest:
        raise ValueError("fixture binary changed during measurement")
    cells = []
    metrics = ("operation_elapsed_ns", "work_sent", "retained_evidence_charged_bytes")
    for scenario in SCENARIOS:
        for family in ("ipv4", "ipv6"):
            cell = dict(scenario=scenario, family=family, status="failed")
            cells.append(cell)
            groups = {
                mode: [row for row in cases if row["scenario"] == scenario
                       and row["family"] == family and row["scheduling_mode"] == mode]
                for mode in ("fixed", "adaptive")
            }
            if any(row["status"] != "exercised" for group in groups.values() for row in group):
                continue
            cell["medians"] = {
                mode: {metric: statistics.median(row["record"][metric] for row in group)
                       for metric in metrics}
                for mode, group in groups.items()
            }
            if any(row.get("peak_process_memory_bytes") is None
                   for group in groups.values() for row in group):
                cell["status"] = "memory_unavailable"
                continue
            for mode, group in groups.items():
                cell["medians"][mode]["peak_process_memory_bytes"] = statistics.median(
                    row["peak_process_memory_bytes"] for row in group)
            fixed, adaptive = cell["medians"]["fixed"], cell["medians"]["adaptive"]
            cell["checks"] = dict(
                accuracy=True,
                peak_memory=adaptive["peak_process_memory_bytes"]
                <= fixed["peak_process_memory_bytes"] + 8_388_608,
            )
            if scenario == "plan-retention":
                cell["checks"]["bounded_admission"] = True
            else:
                cell["checks"].update(
                    less_work=adaptive["work_sent"] < fixed["work_sent"],
                    latency=adaptive["operation_elapsed_ns"]
                    <= fixed["operation_elapsed_ns"] * 1.5 + 1_000_000,
                )
            cell["status"] = ("within_proposed_budgets" if all(cell["checks"].values())
                              else "outside_proposed_budgets")
    return dict(
        schema="packetcraftr.adaptive-scenario-benchmark/v1",
        platform=platform.platform(), binary_sha256=digest, repetitions=repetitions,
        status=("failed" if any(cell["status"] in ("failed", "outside_proposed_budgets")
                                for cell in cells)
                else "incomplete" if any(cell["status"] == "memory_unavailable" for cell in cells)
                else "measured"),
        optimization_accepted=False, limitations=LIMITATIONS, cells=cells, cases=cases,
    )


def main():
    parser = argparse.ArgumentParser(description="Measure controlled adaptive scheduling scenarios.")
    parser.add_argument("--fixture-binary", type=pathlib.Path, required=True)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--report", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.repetitions <= 10:
        parser.error("repetitions must be within 1..=10")
    try:
        report = run(args.fixture_binary.resolve(strict=True), args.repetitions)
    except (ValueError, OSError) as error:
        report = dict(schema="packetcraftr.adaptive-scenario-benchmark/v1",
                      status="failed", optimization_accepted=False, error=str(error))
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(args.report)
    return 0 if report["status"] == "measured" else 1


if __name__ == "__main__":
    raise SystemExit(main())
