"""Contracts for preserved native scenario evidence, not native runtime proof."""
import importlib.util
import json
import pathlib
import subprocess
import unittest
from unittest import mock

import native_platform_evidence as evidence

spec = importlib.util.spec_from_file_location("native_launcher", pathlib.Path(__file__).with_name("test-native-platform.py"))
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


class NativeScenarioEvidence(unittest.TestCase):
    def run_case(self, stdout, returncode=0):
        scenario = dict(name="scoped_ipv6_targets", status="unavailable")
        completed = subprocess.CompletedProcess([], returncode, stdout, "preserved stderr")
        with mock.patch.object(launcher, "current_platform", return_value="macOS"), mock.patch.object(
                launcher.subprocess, "run", return_value=completed):
            launcher.run_scenario(pathlib.Path("cli"), pathlib.Path("native-test"), scenario, "fixture-token")
        return scenario

    def output(self, paths):
        return evidence.SCOPED_MARKER + json.dumps(paths) + "\n1 passed; 0 failed; 0 ignored;\n"

    def test_supported_and_capability_failure_paths_remain_distinct(self):
        for paths in (
            dict(selection="exercised", connect="exercised", raw="exercised"),
            dict(selection="exercised", connect="exercised", raw="unsupported_capability"),
            dict(selection="unsupported_capability", connect="unsupported_capability", raw="unsupported_capability"),
        ):
            output = self.output(paths)
            scenario = self.run_case(output)
            self.assertEqual(scenario["status"], "exercised")
            self.assertEqual(scenario["scoped_paths"], paths)
            self.assertEqual(scenario["stdout"], output)
            self.assertEqual(scenario["stderr"], "preserved stderr")

    def test_zero_exit_or_test_listing_is_not_scoped_execution(self):
        for output in ("", "scoped_ipv6_targets: test", "1 passed; 0 failed; 0 ignored;\n"):
            self.assertEqual(self.run_case(output)["status"], "failed")

    def test_ambiguous_incomplete_or_contradictory_path_evidence_fails(self):
        good = self.output(dict(selection="exercised", connect="exercised", raw="exercised"))
        for output in (
            good + good,
            evidence.SCOPED_MARKER + "not-json\n1 passed; 0 failed; 0 ignored;\n",
            self.output(dict(selection="exercised", connect="exercised")),
            self.output(dict(selection="exercised", connect="unavailable", raw="exercised")),
            self.output(dict(selection="exercised", connect="unsupported_capability", raw="exercised")),
            self.output(dict(selection="unsupported_capability", connect="unsupported_capability", raw="exercised")),
        ):
            self.assertEqual(self.run_case(output)["status"], "failed")

    def test_missing_local_fixture_stays_unavailable(self):
        output = launcher.MARKER + json.dumps(dict(reason_code="isolation_unavailable", reason="no local link-local address"))
        scenario = self.run_case(output + "\n1 passed; 0 failed; 0 ignored;\n")
        self.assertEqual(scenario["status"], "unavailable")
        self.assertEqual(scenario["reason_code"], "isolation_unavailable")
        self.assertNotIn("scoped_paths", scenario)

    def test_failed_native_test_cannot_be_overridden_by_a_success_marker(self):
        output = self.output(dict(selection="exercised", connect="exercised", raw="exercised"))
        scenario = self.run_case(output, 101)
        self.assertEqual(scenario["status"], "failed")
        self.assertEqual(scenario["exit_code"], 101)

    def test_timeout_preserves_partial_output(self):
        scenario = dict(name="scoped_ipv6_targets", status="unavailable")
        with mock.patch.object(launcher, "current_platform", return_value="macOS"), mock.patch.object(
                launcher.subprocess, "run", side_effect=subprocess.TimeoutExpired([], 30, b"partial", b"error")):
            launcher.run_scenario(pathlib.Path("cli"), pathlib.Path("native-test"), scenario, "fixture-token")
        self.assertEqual(scenario["status"], "failed")
        self.assertEqual(scenario["stdout"], "partial")
        self.assertEqual(scenario["stderr"], "error")
        self.assertEqual(scenario["exit_code"], -1)


if __name__ == "__main__":
    unittest.main()
