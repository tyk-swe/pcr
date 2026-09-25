#!/usr/bin/env python3
# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Independent downstream contract failures and semantic mutation checks."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("forwarding_consumer", ROOT / "examples/consumers/forwarding.py")
consumer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(consumer)
FIXTURE = json.loads((ROOT / "examples/consumers/fixtures/v6-forwarding.json").read_text())


def encoded(value):
    return json.dumps(value).encode() + b"\n"


def with_expect(value):
    """Adds a declared `expect` rule and its consistent per-match check evidence."""
    report = value["result"]
    report["rules"]["expect"] = [{"field": "udp.source_port", "value": "40000"}]
    for match in report["matches"]:
        match["checks"].append({
            "check": {"kind": "expect", "field": "udp.source_port", "value": "40000"},
            "outcome": "satisfied",
            "expected_state": None,
            "actual_state": "observed",
            "actual": {"type": "unsigned", "value": 40000},
        })
    report["summary"]["checks_evaluated"] += len(report["matches"])
    report["summary"]["checks_satisfied"] += len(report["matches"])
    return value


class ConsumerTests(unittest.TestCase):
    def consume(self, value=FIXTURE, code=0):
        return consumer.consume(io.BytesIO(encoded(value)), "ndjson", code)

    def consume_json(self, value=FIXTURE, code=0):
        aggregate = copy.deepcopy(value)
        aggregate["mode"] = "aggregate"
        for key in ("sequence", "event"):
            aggregate.pop(key, None)
        return consumer.consume(io.BytesIO(json.dumps(aggregate).encode()), "json", code)

    def test_valid_frozen_consumer_fixture(self):
        self.assertEqual(self.consume()["verdict"], "pass")

    def test_additive_fields_are_accepted(self):
        value = copy.deepcopy(FIXTURE)
        value["future_metadata"] = {"opaque": True}
        self.assertEqual(self.consume(value)["verdict"], "pass")

    def test_prior_schema_requires_explicit_migration(self):
        value = copy.deepcopy(FIXTURE)
        value["schema"] = "packetcraftr.output/v5"
        with self.assertRaisesRegex(consumer.ContractError, "unsupported schema"):
            self.consume(value)

    def test_truncated_missing_and_repeated_terminal_rejected(self):
        data = encoded(FIXTURE)
        for invalid in (b"", data[:-1], data + data):
            with self.subTest(data=invalid[:30]), self.assertRaises(consumer.ContractError):
                consumer.consume(io.BytesIO(invalid), "ndjson", 0)

    def test_sequence_gap_and_unknown_enums_rejected(self):
        for key, value in (("sequence", 2), ("event", "finished"), ("status", "okay")):
            invalid = copy.deepcopy(FIXTURE)
            invalid[key] = value
            with self.subTest(key=key), self.assertRaises(consumer.ContractError):
                self.consume(invalid)

    def test_missing_fields_cannot_be_positive_evidence(self):
        for state in ("absent", "truncated", "decode_incomplete", "field_budget", "future_state"):
            invalid = copy.deepcopy(FIXTURE)
            check = invalid["result"]["matches"][0]["checks"][0]
            check.update(actual_state=state, expected_state=state, actual=None, expected=None)
            with self.subTest(state=state), self.assertRaises(consumer.ContractError):
                self.consume(invalid)

    def test_intentional_contradiction_is_detected(self):
        invalid = copy.deepcopy(FIXTURE)
        invalid["result"]["matches"][0]["checks"][0]["actual"]["value"] = 63
        with self.assertRaisesRegex(consumer.ContractError, "contradicts values"):
            self.consume(invalid)

    def test_invalid_counter_types_and_relations_rejected(self):
        for value in (-1, True, 2**64, 99):
            invalid = copy.deepcopy(FIXTURE)
            invalid["result"]["summary"]["checks_satisfied"] = value
            with self.subTest(value=value), self.assertRaises(consumer.ContractError):
                self.consume(invalid)

    def test_detail_omission_does_not_change_verdict(self):
        value = copy.deepcopy(FIXTURE)
        value["result"]["matches"] = []
        value["result"]["omitted"]["matches"] = 2
        self.assertEqual(self.consume(value)["verdict"], "pass")

    def test_matches_cannot_exceed_either_capture_census(self):
        for sides in (("ingress",), ("egress",), ("ingress", "egress")):
            invalid = copy.deepcopy(FIXTURE)
            for side in sides:
                invalid["result"]["captures"][side].update(
                    read=0, selected=0, keyed=0, unkeyed=0, incomplete=0)
            with self.subTest(sides=sides), self.assertRaisesRegex(consumer.ContractError, "capture census"):
                self.consume(invalid)

    def test_comparison_counters_must_account_for_all_keyed_observations(self):
        for field, count in (("ingress_only", 1), ("egress_only", 1),
                             ("ambiguous_observations", 1), ("ambiguous_groups", 1)):
            invalid = copy.deepcopy(FIXTURE)
            invalid["result"]["summary"][field] = count
            with self.subTest(field=field), self.assertRaisesRegex(consumer.ContractError, "capture census"):
                self.consume(invalid)
        invalid = copy.deepcopy(FIXTURE)
        for side in ("ingress", "egress"):
            invalid["result"]["captures"][side].update(read=3, selected=3, keyed=3)
        with self.assertRaisesRegex(consumer.ContractError, "capture census"):
            self.consume(invalid)

    def test_mixed_capture_census_with_omitted_details(self):
        value = copy.deepcopy(FIXTURE)
        report = value["result"]
        report["verdict"] = "inconclusive"
        report["captures"]["ingress"].update(read=8, selected=7, keyed=6, unkeyed=1)
        report["captures"]["egress"].update(read=7, selected=7, keyed=5, unkeyed=2)
        report["summary"].update(ingress_only=3, egress_only=1,
                                 ambiguous_groups=1, ambiguous_observations=3)
        report["omitted"].update(unmatched_ingress=3, unmatched_egress=1,
                                 unkeyed_ingress=1, unkeyed_egress=2,
                                 ambiguous_groups=1, group_members=3)
        self.assertEqual(self.consume(value, code=1)["verdict"], "inconclusive")
        for field, count in (("ambiguous_groups", 0), ("ambiguous_groups", 2),
                             ("ambiguous_observations", 2), ("ambiguous_observations", 4)):
            invalid = copy.deepcopy(value)
            invalid["result"]["summary"][field] = count
            with self.subTest(field=field, count=count), self.assertRaisesRegex(consumer.ContractError, "capture census"):
                self.consume(invalid, code=1)

    def test_ambiguous_groups_need_both_sides_and_more_than_one_pair(self):
        for ingress, egress in ((0, 3), (3, 0), (1, 1)):
            invalid = copy.deepcopy(FIXTURE)
            report = invalid["result"]
            report["verdict"] = "inconclusive"
            for side, extra in (("ingress", ingress), ("egress", egress)):
                report["captures"][side].update(read=2 + extra, selected=2 + extra, keyed=2 + extra)
            report["summary"].update(ambiguous_groups=1, ambiguous_observations=ingress + egress)
            report["omitted"].update(ambiguous_groups=1, group_members=ingress + egress)
            with self.subTest(ingress=ingress, egress=egress), self.assertRaisesRegex(consumer.ContractError, "capture census"):
                self.consume(invalid, code=1)

    def test_aggregate_json_validates_retained_checks(self):
        self.assertEqual(self.consume_json()["verdict"], "pass")

    def test_retained_checks_must_match_declared_rules(self):
        mutations = {
            "removed": lambda match: match.update(checks=[]),
            "not a list": lambda match: match.update(checks="ipv4.ttl"),
            "substituted field": lambda match: match["checks"][0]["check"].update(
                field="ipv4.source"),
            "substituted kind": lambda match: match["checks"][0]["check"].update(
                kind="preserve_presence"),
            "duplicated": lambda match: match["checks"].append(
                copy.deepcopy(match["checks"][0])),
        }
        for consume in (self.consume, self.consume_json):
            for name, mutate in mutations.items():
                invalid = copy.deepcopy(FIXTURE)
                for match in invalid["result"]["matches"]:
                    mutate(match)
                with self.subTest(mutation=name), self.assertRaises(consumer.ContractError):
                    consume(invalid)

    def test_substituted_checks_identify_the_match_and_descriptor(self):
        invalid = copy.deepcopy(FIXTURE)
        for match in invalid["result"]["matches"]:
            match["checks"][0]["check"]["field"] = "ipv4.source"
        with self.assertRaisesRegex(consumer.ContractError,
                                    r"match 0 \(ingress frame \d+\): check 0 .*does not match declared check"):
            self.consume(invalid)

    def test_declared_expectations_are_enforced_per_match(self):
        self.assertEqual(self.consume(with_expect(copy.deepcopy(FIXTURE)))["verdict"], "pass")
        self.assertEqual(self.consume_json(with_expect(copy.deepcopy(FIXTURE)))["verdict"], "pass")
        mutations = {
            "literal": lambda match: match["checks"][1]["check"].update(value="40001"),
            "field": lambda match: match["checks"][1]["check"].update(field="udp.destination_port"),
            "kind": lambda match: match["checks"][1]["check"].update(kind="expect_absent"),
            "dropped literal": lambda match: match["checks"][1]["check"].pop("value"),
            "omitted": lambda match: match["checks"].pop(1),
            "reordered": lambda match: match["checks"].reverse(),
        }
        for consume in (self.consume, self.consume_json):
            for name, mutate in mutations.items():
                invalid = with_expect(copy.deepcopy(FIXTURE))
                for match in invalid["result"]["matches"]:
                    mutate(match)
                with self.subTest(mutation=name), self.assertRaises(consumer.ContractError):
                    consume(invalid)

    def test_partial_match_omission_keeps_complete_check_evidence(self):
        value = copy.deepcopy(FIXTURE)
        value["result"]["matches"] = value["result"]["matches"][:1]
        value["result"]["omitted"]["matches"] = 1
        self.assertEqual(self.consume(value)["verdict"], "pass")
        self.assertEqual(self.consume_json(value)["verdict"], "pass")

    def test_requested_checks_cannot_silently_disappear(self):
        invalid = copy.deepcopy(FIXTURE)
        report = invalid["result"]
        report["matches"] = []
        report["omitted"]["matches"] = report["summary"]["unique_matches"]
        for key in ("checks_evaluated", "checks_satisfied", "checks_violated", "checks_unevaluable"):
            report["summary"][key] = 0
        with self.assertRaisesRegex(consumer.ContractError, "requested checks were not all evaluated"):
            self.consume(invalid)

    def test_oversized_record_and_duplicate_keys_rejected(self):
        for invalid in (b" " * (consumer.MAX_RECORD + 1),
                        encoded(FIXTURE).replace(b'"sequence": 0', b'"sequence": 0, "sequence": 0')):
            with self.assertRaises(consumer.ContractError):
                consumer.consume(io.BytesIO(invalid), "ndjson", 0)

    def test_exit_code_does_not_replace_terminal_contract(self):
        with self.assertRaisesRegex(consumer.ContractError, "exit code"):
            self.consume(code=1)

    def test_execution_error_is_not_a_domain_verdict(self):
        value = {"schema": consumer.SCHEMA, "command": "verify-forwarding", "mode": "stream",
                 "sequence": 0, "event": "error", "status": "error",
                 "error": {"code": "policy.duration_limit"}}
        result = self.consume(value, code=1)
        self.assertEqual(result["execution"], "error")
        self.assertIsNone(result["verdict"])
        with self.assertRaises(consumer.ContractError):
            self.consume(value, code=0)


if __name__ == "__main__":
    unittest.main()
