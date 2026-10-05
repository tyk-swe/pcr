"""Versioned native platform evidence, separate from Linux namespace evidence v1."""
import re

SCHEMA = "packetcraftr.native-platform-evidence/v2"
PLATFORMS = ("Linux", "macOS", "Windows")
PROFILES = ("portable", "default", "layer2", "pcap-free", "full-native")
SCENARIOS = (
    "loopback_exchange",
    "readiness_and_repeated_cleanup",
    "idle_deadline_and_cancellation",
    "bounded_queue_reports_real_capture_loss",
    "native_set_before_realized_values",
    "native_filter_error_releases_admission",
    "iface_disappearance_driver_fail_cleans_up",
)
UNAVAILABLE_REASONS = (
    "unsupported_capability",
    "privilege_not_granted",
    "backend_not_installed",
    "isolation_unavailable",
    "runtime_evidence_missing",
)


def hexadecimal(value, width):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{" + str(width) + r"}", value) is not None


def status_of(scenarios):
    if any(item["status"] == "failed" for item in scenarios):
        return "failed"
    if any(item["status"] == "unavailable" for item in scenarios):
        return "incomplete"
    return "exercised"


def validate(report, expected_commit=None, require_complete=False):
    if not isinstance(report, dict) or report.get("schema") != SCHEMA:
        raise ValueError("native platform evidence has an unsupported schema")
    if report.get("platform") not in PLATFORMS:
        raise ValueError("native platform evidence must identify an actual platform")
    if not hexadecimal(report.get("commit"), 40) or type(report.get("dirty")) is not bool:
        raise ValueError("native platform evidence must bind a commit and checkout cleanliness")
    if expected_commit is not None and report["commit"] != expected_commit:
        raise ValueError("native platform evidence is not for the requested reviewed commit")
    if require_complete and report["dirty"]:
        raise ValueError("dirty native evidence cannot close an exact-commit gate")
    isolation = report.get("isolation")
    if not isinstance(isolation, dict) or isolation.get("kind") not in (
            "fresh_network_namespace", "loopback_only", "unavailable"):
        raise ValueError("native platform evidence lacks declared isolation")
    if report["platform"] == "Linux" and isolation["kind"] == "loopback_only":
        raise ValueError("Linux native validation must retain namespace isolation")
    if isolation["kind"] == "fresh_network_namespace":
        current, parent = isolation.get("namespace"), isolation.get("parent_namespace")
        if (report["platform"] != "Linux" or type(current) is not int or type(parent) is not int
                or min(current, parent) <= 0 or current == parent):
            raise ValueError("native evidence lacks distinct positive Linux namespace identities")
    if isolation["kind"] == "loopback_only" and (
            isolation.get("external_destinations") is not False
            or isolation.get("interface_mutation") is not False):
        raise ValueError("host loopback validation must refuse external traffic and interface mutation")
    profiles = report.get("profiles")
    if not isinstance(profiles, list) or [item.get("name") for item in profiles] != list(PROFILES):
        raise ValueError("native evidence lacks the complete ordered profile inventory")
    for profile in profiles:
        scenarios = profile.get("scenarios")
        if not isinstance(scenarios, list) or [item.get("name") for item in scenarios] != list(SCENARIOS):
            raise ValueError(f"{profile['name']}: incomplete or reordered native scenario inventory")
        for scenario in scenarios:
            state = scenario.get("status")
            if state not in ("exercised", "failed", "unavailable"):
                raise ValueError("native scenarios must distinguish exercised, failed and unavailable")
            if state == "unavailable":
                if (scenario.get("reason_code") not in UNAVAILABLE_REASONS
                        or not isinstance(scenario.get("reason"), str) or not scenario["reason"].strip()):
                    raise ValueError("unavailable native scenarios require a specific reason")
                continue
            if isolation["kind"] == "unavailable":
                raise ValueError("native scenarios cannot execute without isolation")
            if scenario.get("execution") != "privileged_native":
                raise ValueError("compilation and injected providers are not native runtime evidence")
            if scenario.get("privilege_granted") is not True:
                raise ValueError("native runtime evidence lacks explicit privilege admission")
            for field in ("binary_sha256", "test_binary_sha256"):
                if not hexadecimal(profile.get(field), 64):
                    raise ValueError("executed native scenario lacks executable digests")
            command = scenario.get("command")
            if (not isinstance(command, list) or not command or not all(
                    isinstance(argument, str) and argument for argument in command)):
                raise ValueError("executed native scenario lacks its exact command")
            if "--list" in command or "--no-run" in command:
                raise ValueError("test listing or compilation is not native scenario execution")
            code = scenario.get("exit_code")
            if type(code) is not int or (state == "exercised" and code != 0):
                raise ValueError("exercised native scenario lacks successful process exit evidence")
            if state == "failed" and code == 0:
                if not isinstance(scenario.get("error"), str) or not scenario["error"].strip():
                    raise ValueError("zero-exit failed native scenario lacks semantic failure evidence")
            if (not isinstance(scenario.get("stdout"), str) or not isinstance(
                    scenario.get("stderr"), str)):
                raise ValueError("native scenario must preserve process output even on failure")
        if profile.get("status") != status_of(scenarios):
            raise ValueError("native profile status disagrees with its scenarios")
    scenarios = [scenario for profile in profiles for scenario in profile["scenarios"]]
    if report.get("status") != status_of(scenarios):
        raise ValueError("native report status disagrees with its required profiles")
    if require_complete and report["status"] != "exercised":
        raise ValueError("unavailable or failed scenarios cannot close the runtime evidence gate")
    return report
