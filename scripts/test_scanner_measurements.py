import importlib.util
import copy
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import native_platform_evidence as native

spec = importlib.util.spec_from_file_location("benchmark_scanner", ROOT / "benchmark-scanner.py")
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)
comparison_spec = importlib.util.spec_from_file_location("compare_scheduling", ROOT / "compare-scheduling.py")
comparison = importlib.util.module_from_spec(comparison_spec)
comparison_spec.loader.exec_module(comparison)
adaptive_spec = importlib.util.spec_from_file_location("adaptive_scenarios", ROOT / "benchmark-adaptive-scenarios.py")
adaptive_scenarios = importlib.util.module_from_spec(adaptive_spec)
adaptive_spec.loader.exec_module(adaptive_scenarios)


class AdaptiveScenarioMeasurements(unittest.TestCase):
    def record(self, scenario="responsive-many", mode="adaptive"):
        config = adaptive_scenarios.SCENARIOS[scenario]
        oracle = adaptive_scenarios.expected(scenario, mode)
        return dict(
            schema="packetcraftr.scheduling-fixture/v1", scenario=scenario, family="ipv6",
            scheduling_mode=mode, execution="injected_provider_real_clock",
            settings=dict(config, hosts=1, max_in_flight=2, max_evidence_bytes=1048576,
                          max_probes=config["ports"] * config["attempts"]),
            status=oracle["status"], work_sent=oracle["work_sent"],
            endpoints=oracle["endpoints"], operation_elapsed_ns=1000000,
            retained_evidence_charged_bytes=0, capture_sessions=0 if mode == "fixed"
            and scenario == "plan-retention" else 1,
            observed_peak_window=2, retries_started=oracle["work_sent"] - config["ports"],
            conditions=[], incomplete=[], error_code=oracle["error_code"],
            error="scan pipeline execution failed", error_cause="prepared descriptions exceed limit",
        )

    def test_independent_oracles_define_selective_work_and_fail_closed_plan(self):
        expected = adaptive_scenarios.expected
        self.assertEqual(expected("responsive-many", "fixed")["work_sent"], 48)
        self.assertEqual(expected("responsive-many", "adaptive")["work_sent"], 16)
        self.assertEqual(expected("selective-silence", "fixed")["work_sent"], 6)
        self.assertEqual(expected("selective-silence", "adaptive")["work_sent"], 4)
        self.assertEqual(expected("plan-retention", "fixed")["status"], "rejected")
        self.assertEqual(expected("plan-retention", "adaptive")["work_sent"], 128)
        for scenario in adaptive_scenarios.SCENARIOS:
            for mode in ("fixed", "adaptive"):
                adaptive_scenarios.validate(self.record(scenario, mode), scenario, "ipv6", mode)

    def test_changed_work_accuracy_settings_and_surface_are_rejected(self):
        for field, value in (
            ("work_sent", True), ("work_sent", 17), ("endpoints", {}),
            ("settings", {}), ("execution", "privileged_native"),
            ("observed_peak_window", 3), ("retries_started", 1),
            ("incomplete", ["2001:db8::2"]), ("conditions", ["suspected_response_rate_limit"]),
            ("retained_evidence_charged_bytes", 1048577),
            ("operation_elapsed_ns", 2000000001),
        ):
            with self.subTest(field=field):
                record = self.record()
                record[field] = value
                with self.assertRaises(ValueError):
                    adaptive_scenarios.validate(record, "responsive-many", "ipv6", "adaptive")

    def test_a_resource_rejection_after_active_capture_is_not_a_boundary_pass(self):
        record = self.record("plan-retention", "fixed")
        record["capture_sessions"] = 1
        with self.assertRaises(ValueError):
            adaptive_scenarios.validate(record, "plan-retention", "ipv6", "fixed")


class SchedulingComparison(unittest.TestCase):
    def test_report_size_is_bounded_before_loading_the_entire_file(self):
        path = mock.Mock()
        source = mock.MagicMock()
        path.open.return_value = source
        source.__enter__.return_value = source
        source.read.return_value = b"x" * 17
        with mock.patch.object(comparison, "MAX_REPORT_BYTES", 16):
            with self.assertRaises(ValueError):
                comparison.load(path)
        path.open.assert_called_once_with("rb")
        source.read.assert_called_once_with(17)

    def reports(self):
        cases = []
        for family in ("ipv4", "ipv6"):
            for condition in benchmark.CONDITIONS:
                for transport in ("tcp", "udp", "icmp"):
                    for window in (1, 2):
                        cases.append(dict(workflow="raw_scan", id=condition, family=family,
                                          transport=transport, window=window))
            for condition in ("responsive", "silent"):
                for transport in ("tcp", "udp", "icmp"):
                    cases.append(dict(workflow="traceroute", id=condition, family=family,
                                      transport=transport, window=1))
            for condition in ("connect-responsive", "connect-closed"):
                cases.append(dict(workflow="tcp_connect", id=condition, family=family))
        for row in cases:
            row.update(repetition=0, status="exercised", correct=True, expected={"fixture": row["id"]},
                       execution="native_loopback" if row["workflow"] == "tcp_connect" else "injected_provider",
                       workflow_elapsed_ns=2_000_000, work_sent=1, retained_state_charged_bytes=64,
                       peak_process_memory_bytes=1_000_000)
        fixed = dict(schema="packetcraftr.scanner-benchmark/v1", platform="test-platform",
                     settings={"attempts": 1}, corpus_sha256="a" * 64, repetitions=1,
                     scheduling_mode="fixed", cases=cases)
        adaptive = copy.deepcopy(fixed)
        adaptive["scheduling_mode"] = "adaptive"
        return fixed, adaptive

    def test_measurements_do_not_claim_optimization_acceptance(self):
        fixed, adaptive = self.reports()
        result = comparison.compare(fixed, adaptive)
        self.assertEqual(result["status"], "measured")
        self.assertEqual(len(result["cells"]), 88)
        self.assertFalse(result["optimization_accepted"])
        self.assertEqual(result["cells"][0]["baseline_medians"]["work_sent"], 1)

    def test_changed_settings_missing_cells_and_duplicates_fail_closed(self):
        fixed, adaptive = self.reports()
        adaptive["settings"]["attempts"] = 2
        with self.assertRaises(ValueError):
            comparison.compare(fixed, adaptive)
        fixed, adaptive = self.reports()
        fixed["cases"].pop()
        adaptive["cases"].pop()
        with self.assertRaises(ValueError):
            comparison.compare(fixed, adaptive)
        fixed, adaptive = self.reports()
        adaptive["cases"].append(copy.deepcopy(adaptive["cases"][0]))
        with self.assertRaises(ValueError):
            comparison.compare(fixed, adaptive)

    def test_bad_accuracy_excess_work_and_latency_do_not_pass_budgets(self):
        for field, value in (("correct", False), ("work_sent", 2),
                             ("workflow_elapsed_ns", 4_000_001), ("peak_process_memory_bytes", 9_388_609)):
            with self.subTest(field=field):
                fixed, adaptive = self.reports()
                adaptive["cases"][0][field] = value
                self.assertEqual(comparison.compare(fixed, adaptive)["status"], "failed")

    def test_unavailable_memory_and_fixture_remain_incomplete(self):
        for field, value in (("status", "unavailable"), ("peak_process_memory_bytes", None)):
            fixed, adaptive = self.reports()
            adaptive["cases"][0][field] = value
            result = comparison.compare(fixed, adaptive)
            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(len(result["cells"]), 88)
            self.assertFalse(result["optimization_accepted"])

    def test_boolean_metrics_and_drifting_expectations_fail_closed(self):
        for field, value in (("work_sent", True), ("expected", {"other": "oracle"}),
                             ("execution", "privileged_native")):
            fixed, adaptive = self.reports()
            adaptive["cases"][0][field] = value
            with self.assertRaises(ValueError):
                comparison.compare(fixed, adaptive)


class ScannerMeasurements(unittest.TestCase):
    def test_fixture_absence_does_not_masquerade_as_product_failure(self):
        with mock.patch.object(benchmark.socket, "socket", side_effect=OSError(
                benchmark.errno.EAFNOSUPPORT, "fixture family absent")):
            with self.assertRaises(benchmark.FixtureUnavailable):
                benchmark.fixture_socket(benchmark.socket.AF_INET6, "::1")
        with mock.patch.object(benchmark.socket, "socket", side_effect=OSError(
                benchmark.errno.EMFILE, "unexpected resource exhaustion")):
            with self.assertRaises(OSError):
                benchmark.fixture_socket(benchmark.socket.AF_INET6, "::1")

    def test_echo_refusal_is_unreachable_not_port_closure(self):
        corpus, _ = benchmark.load_corpus(ROOT.parent / "docs/scanner-corpus.v1.json")
        closed = next(case for case in corpus["scenarios"] if case["id"] == "closed")
        self.assertEqual(closed["expected"]["attempt_classification"], "closed")
        self.assertEqual(closed["expected_by_transport"]["icmp"]["attempt_classification"], "unreachable")

    def test_missing_tools_are_reported_without_losing_the_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = pathlib.Path(directory) / "missing"
            report = pathlib.Path(directory) / "report.json"
            arguments = ["benchmark-scanner", "--binary", str(missing), "--fixture-binary", str(missing),
                         "--nmap", str(missing), "--report", str(report), "--repetitions", "1"]
            with mock.patch.object(sys, "argv", arguments):
                self.assertEqual(benchmark.main(), 1)
            output = json.loads(report.read_text())
            self.assertEqual(output["status"], "incomplete")
            self.assertEqual(len(output["cases"]), 88)
            self.assertFalse(output["coverage_complete"])
            self.assertFalse(output["comparison_complete"])
            self.assertTrue(all(row["status"] == "unavailable" for row in output["cases"]))
            self.assertTrue(all(row["status"] == "unavailable" for row in output["tools"].values()))

    def test_inventory_is_independent_complete_and_documentation_only(self):
        corpus, digest = benchmark.load_corpus(ROOT.parent / "docs/scanner-corpus.v1.json")
        self.assertEqual(len(digest), 64)
        self.assertEqual(len(corpus["scenarios"]) * len(corpus["families"])
                         * len(corpus["transports"]) * len(corpus["request"]["windows"]), 72)
        self.assertEqual(corpus["scenarios"][3]["expected"]["attempt_classification"], "timeout")
        self.assertEqual(len({case["id"] for case in corpus["adaptive_scheduling_scenarios"]}), 8)
        self.assertTrue(all(case["families"] == ["ipv4", "ipv6"]
                            for case in corpus["adaptive_scheduling_scenarios"]))

    def test_invalid_window_inventory_fails_before_reporting_complete_coverage(self):
        corpus, _ = benchmark.load_corpus(ROOT.parent / "docs/scanner-corpus.v1.json")
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "corpus.json"
            report = pathlib.Path(directory) / "report.json"
            arguments = ["benchmark-scanner", "--binary", sys.executable, "--corpus", str(path),
                         "--report", str(report), "--repetitions", "1"]
            for windows in ([], [1], [2], [2, 1], [1, 1, 2], [1, 2, 3], [True, 2], [1.0, 2]):
                with self.subTest(windows=windows):
                    corpus["request"]["windows"] = windows
                    path.write_text(json.dumps(corpus))
                    with mock.patch.object(sys, "argv", arguments):
                        self.assertEqual(benchmark.main(), 1)
                    output = json.loads(report.read_text())
                    self.assertEqual(output["status"], "failed")
                    self.assertIn("scheduling windows [1, 2]", output["setup_error"])
                    self.assertFalse(output["coverage_complete"])
                    self.assertEqual(output["cases"], [])

    def test_boolean_is_not_a_count(self):
        with self.assertRaises(ValueError):
            benchmark.require_integer(True, "work_sent")
        for text in ('{"count":1,"count":2}', '{"latency":NaN}'):
            with self.assertRaises(ValueError):
                benchmark.strict_json(text)

    def test_packet_accuracy_uses_expected_observation_and_exact_frame_charges(self):
        case = {"id": "responsive", "expected": {
            "attempt_classification": "open", "status": "response", "attributed_response": True}}
        record = dict(schema="packetcraftr.scanner-fixture/v1", workflow="raw_scan", scenario="responsive",
                      family="ipv6", transport="udp", window=2, execution="injected_provider",
                      packets_attempted=1, packets_completed=1, retained_evidence_bytes=2,
                      retained_frames_hex=["0102"], delivered_frames_hex=["0102"],
                      workflow_elapsed_ns=1, observation=dict(
                          classification="open", status="response", attributed_response=True))
        result = benchmark.validate_packet(record, case, "ipv6", "udp", 2)
        self.assertTrue(result["correct"])
        record["observation"]["classification"] = "closed"
        self.assertFalse(benchmark.validate_packet(record, case, "ipv6", "udp", 2)["correct"])
        record["retained_evidence_bytes"] = 3
        with self.assertRaises(ValueError):
            benchmark.validate_packet(record, case, "ipv6", "udp", 2)
        record["retained_evidence_bytes"] = 2
        record["delivered_frames_hex"] = ["0304"]
        with self.assertRaises(ValueError):
            benchmark.validate_packet(record, case, "ipv6", "udp", 2)

    def test_adaptive_packet_requires_explicit_fixture_mode(self):
        case = {"id": "silent", "expected": {
            "attempt_classification": "timeout", "status": "timeout", "attributed_response": False}}
        record = dict(schema="packetcraftr.scanner-fixture/v1", workflow="raw_scan", scenario="silent",
                      family="ipv4", transport="tcp", window=1, execution="injected_provider",
                      packets_attempted=1, packets_completed=1, retained_evidence_bytes=0,
                      retained_frames_hex=[], delivered_frames_hex=[], workflow_elapsed_ns=20_000_000,
                      observation=dict(classification="timeout", status="timeout", attributed_response=False))
        with self.assertRaises(ValueError):
            benchmark.validate_packet(record, case, "ipv4", "tcp", 1, adaptive=True)
        record["scheduling_mode"] = "adaptive"
        self.assertTrue(benchmark.validate_packet(record, case, "ipv4", "tcp", 1, adaptive=True)["correct"])
        with self.assertRaises(ValueError):
            benchmark.validate_packet(record, case, "ipv4", "tcp", 1)

    def test_measured_process_keeps_exit_output_and_per_child_memory(self):
        row = benchmark.measured([sys.executable, "-c", "print('fixture')"])
        self.assertEqual(row["exit_code"], 0)
        self.assertEqual(row["stdout"], "fixture\n")
        self.assertGreater(row["elapsed_ns"], 0)
        if hasattr(benchmark.os, "wait4"):
            self.assertGreater(row["peak_process_memory_bytes"], 0)
        failed = benchmark.measured([sys.executable, "-c", "raise SystemExit(3)"])
        self.assertEqual(failed["exit_code"], 3)

    def test_measured_output_has_a_hard_bound(self):
        with self.assertRaises(ValueError):
            benchmark.measured([sys.executable, "-c", "print('x' * 1100000)"])

    def test_trace_has_its_own_termination_oracle(self):
        case = dict(id="silent", expected_termination="timeout", expected_status="timeout",
                    expected_attributed_response=False)
        record = dict(schema="packetcraftr.scanner-fixture/v1", workflow="traceroute", scenario="silent",
                      family="ipv4", transport="icmp", window=1, execution="injected_provider",
                      packets_attempted=1, packets_completed=1, retained_evidence_bytes=0,
                      retained_frames_hex=[], delivered_frames_hex=[], workflow_elapsed_ns=1, observation=dict(
                          termination="timeout", status="timeout", attributed_response=False))
        self.assertTrue(benchmark.validate_trace(record, case, "ipv4", "icmp")["correct"])
        record["observation"]["termination"] = "maximum_hops"
        self.assertFalse(benchmark.validate_trace(record, case, "ipv4", "icmp")["correct"])

    def test_full_measurement_inventory_and_denominators(self):
        corpus, _ = benchmark.load_corpus(ROOT.parent / "docs/scanner-corpus.v1.json")
        cases = {case["id"]: case for case in corpus["scenarios"]}
        traces = {case["id"]: case for case in corpus["traceroute_scenarios"]}

        def measured(command):
            _, condition, family, transport, window, *workflow = command
            expected = cases[condition].get("expected_by_transport", {}).get(
                transport, cases[condition]["expected"])
            observation = dict(classification=expected["attempt_classification"],
                               status=expected["status"], attributed_response=expected["attributed_response"])
            if workflow:
                expected = traces[condition]
                observation = dict(termination=expected["expected_termination"], status=expected["expected_status"],
                                   attributed_response=expected["expected_attributed_response"])
            output = dict(schema="packetcraftr.scanner-fixture/v1", workflow="traceroute" if workflow else "raw_scan",
                          scenario=condition, family=family, transport=transport, window=int(window),
                          execution="injected_provider", packets_attempted=1, packets_completed=1,
                          retained_evidence_bytes=2 if observation["attributed_response"] else 0,
                          retained_frames_hex=["0102"] if observation["attributed_response"] else [],
                          workflow_elapsed_ns=1,
                          delivered_frames_hex=[] if condition == "silent" else
                          ["45" if family == "ipv4" else "60"] if condition == "malformed" else ["0102"],
                          observation=observation)
            return dict(exit_code=0, stdout=json.dumps(output), stderr="", elapsed_ns=1,
                        peak_process_memory_bytes=1024)

        with tempfile.TemporaryDirectory() as directory:
            binary, fixture, report = [pathlib.Path(directory) / name for name in ("cli", "fixture", "report.json")]
            binary.touch()
            fixture.touch()
            arguments = ["benchmark-scanner", "--binary", str(binary), "--fixture-binary", str(fixture),
                         "--report", str(report), "--repetitions", "1"]
            with mock.patch.object(sys, "argv", arguments), mock.patch.object(benchmark, "measured", measured), \
                    mock.patch.object(benchmark, "connect_case", return_value=dict(
                        correct=True, execution="native_loopback", peak_process_memory_bytes=1024)):
                self.assertEqual(benchmark.main(), 0)
            output = json.loads(report.read_text())
            self.assertEqual(len(output["cases"]), 88)
            self.assertTrue(output["coverage_complete"])
            self.assertEqual(len(output["accuracy"]), 6)
            for row in output["accuracy"]:
                count = {"raw_scan": 36, "traceroute": 6, "tcp_connect": 2}[row["workflow"]]
                self.assertEqual((row["correct"], row["evaluated"], row["unavailable_or_failed"]), (count, count, 0))


class NativeEvidence(unittest.TestCase):
    def report(self):
        profiles = []
        for profile in native.PROFILES:
            scenarios = [dict(name=scenario, status="unavailable",
                              reason_code="runtime_evidence_missing",
                              reason="No runtime execution supplied in this validation fixture.")
                         for scenario in native.SCENARIOS]
            profiles.append(dict(name=profile, scenarios=scenarios, status="incomplete"))
        return dict(schema=native.SCHEMA, platform="macOS", commit="a" * 40,
                    corpus_sha256="c" * 64, corpus_dataset_version="fixture",
                    dirty=False, isolation=dict(kind="loopback_only",
                                               external_destinations=False,
                                               interface_mutation=False),
                    profiles=profiles, status="incomplete")

    def test_incomplete_evidence_is_valid_but_cannot_close_a_gate(self):
        report = self.report()
        native.validate(report, expected_commit="a" * 40)
        with self.assertRaises(ValueError):
            native.validate(report, require_complete=True)

    def test_profile_scenario_inventory_and_unavailable_reasons_are_mandatory(self):
        for mutate in (
            lambda report: report["profiles"].pop(),
            lambda report: report["profiles"][0]["scenarios"].pop(),
            lambda report: report["profiles"][0]["scenarios"][0].pop("reason"),
            lambda report: report.update(commit="main"),
            lambda report: report.update(status="exercised"),
            lambda report: report.pop("corpus_sha256"),
            lambda report: report.update(corpus_dataset_version=""),
        ):
            report = self.report()
            mutate(report)
            with self.assertRaises(ValueError):
                native.validate(report)

    def test_fake_or_zero_exit_test_listing_is_not_native_evidence(self):
        report = self.report()
        scenario = report["profiles"][-1]["scenarios"][0]
        scenario.update(status="exercised", exit_code=0, command=["fixture", "--list"],
                        execution="injected_provider", privilege_granted=True, stdout="", stderr="")
        with self.assertRaises(ValueError):
            native.validate(report)

    def test_linux_requires_namespace_identity_and_exact_commit(self):
        report = self.report()
        report["platform"] = "Linux"
        with self.assertRaises(ValueError):
            native.validate(report)
        report["isolation"] = dict(kind="fresh_network_namespace", namespace=5, parent_namespace=5)
        with self.assertRaises(ValueError):
            native.validate(report)
        report["isolation"]["parent_namespace"] = 4
        native.validate(report)
        with self.assertRaises(ValueError):
            native.validate(report, expected_commit="b" * 40)

    def test_scoped_paths_must_match_the_preserved_native_output(self):
        report = self.report()
        profile = report["profiles"][0]
        profile.update(binary_sha256="b" * 64, test_binary_sha256="c" * 64)
        scenario = profile["scenarios"][-1]
        paths = dict(selection="exercised", connect="exercised", raw="unsupported_capability")
        scenario.update(status="exercised", exit_code=0,
                        command=["native-test", "--ignored", "--exact", "scoped_ipv6_targets"],
                        execution="privileged_native", privilege_granted=True, scoped_paths=paths.copy(),
                        stdout=native.SCOPED_MARKER + json.dumps(paths), stderr="")
        native.validate(report)
        scenario["scoped_paths"]["raw"] = "exercised"
        with self.assertRaises(ValueError):
            native.validate(report)


if __name__ == "__main__":
    unittest.main()
