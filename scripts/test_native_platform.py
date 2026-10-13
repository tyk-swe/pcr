"""Contracts for preserved native scenario evidence, not native runtime proof."""
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import native_platform_evidence as evidence

spec = importlib.util.spec_from_file_location("native_launcher", pathlib.Path(__file__).with_name("test-native-platform.py"))
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)

os_spec = importlib.util.spec_from_file_location("os_native_launcher", pathlib.Path(__file__).with_name("test-os-identification-native.py"))
os_launcher = importlib.util.module_from_spec(os_spec)
os_spec.loader.exec_module(os_launcher)


class OsNativeExecutable(unittest.TestCase):
    def test_listeners_are_loopback_only_unless_isolated(self):
        for isolated, addresses in ((False, ("127.0.0.1", "::1")), (True, ("0.0.0.0", "::"))):
            with self.subTest(isolated=isolated):
                sockets = [mock.Mock() for _ in range(4)]
                with mock.patch.object(os_launcher.socket, "socket", side_effect=sockets):
                    if isolated:
                        result = os_launcher.listeners(isolated=True)
                    else:
                        result = os_launcher.listeners()
                self.assertEqual(result, sockets)
                for listener, address, port in zip(sockets, (addresses[0], addresses[0], addresses[1], addresses[1]),
                                                   (os_launcher.OPEN_PORT, os_launcher.OTHER_OPEN_PORT) * 2):
                    listener.bind.assert_called_once_with((address, port))
                    listener.listen.assert_called_once_with(32)

    def test_default_binary_uses_the_platform_executable_suffix(self):
        for system, filename in (("Windows", "packetcraftr.exe"), ("Linux", "packetcraftr"),
                                 ("Darwin", "packetcraftr")):
            with self.subTest(system=system), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                binary = root / "target/debug" / filename
                binary.parent.mkdir(parents=True)
                binary.write_bytes(b"fixture executable")
                output = root / "report.json"
                with mock.patch.object(os_launcher, "ROOT", root), \
                        mock.patch.object(os_launcher.platform, "system", return_value=system), \
                        mock.patch.object(os_launcher, "source_identity", return_value={}), \
                        mock.patch.object(sys, "argv", ["os-native", "--initialize-only", "--output", str(output)]):
                    self.assertEqual(os_launcher.main(), 0)
                self.assertEqual(json.loads(output.read_text())["binary_sha256"], os_launcher.sha256(binary))


class NativeScenarioEvidence(unittest.TestCase):
    def run_case(self, stdout, returncode=0):
        scenario = dict(name="scoped_ipv6_targets", status="unavailable", reason_code="runtime_evidence_missing",
                        reason="not executed yet")
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
            self.assertNotIn("reason", scenario)
            self.assertNotIn("reason_code", scenario)

    def test_zero_exit_or_test_listing_is_not_scoped_execution(self):
        for output in ("", "scoped_ipv6_targets: test", "1 passed; 0 failed; 0 ignored;\n"):
            self.assertEqual(self.run_case(output)["status"], "failed")

    def test_ambiguous_incomplete_or_contradictory_path_evidence_fails(self):
        good = self.output(dict(selection="exercised", connect="exercised", raw="exercised"))
        for output in (
            good + good,
            evidence.SCOPED_MARKER + '{"selection":"unsupported_capability","selection":"exercised",'
            '"connect":"exercised","raw":"exercised"}\n1 passed; 0 failed; 0 ignored;\n',
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
