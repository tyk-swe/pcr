# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only
"""Reject mutated evidence while retaining forward-compatible additive metadata."""
import copy
import io
import json
import unittest
from unittest.mock import patch

from support import ROOT, load_script

consumer = load_script('forwarding', 'examples/consumers/forwarding.py')


def envelope():
    return json.loads((ROOT / 'examples/consumers/fixtures/forwarding.json').read_text())


def consume(value, exit_code=0):
    return consumer.consume(io.BytesIO(json.dumps(value).encode() + b'\n'), 'ndjson', exit_code)


class ForwardingConsumerTests(unittest.TestCase):
    def test_retained_checks_must_match_declarations(self) -> None:
        for mismatch in ('field', 'kind', 'missing', 'extra'):
            value = envelope()
            checks = value['result']['matches'][0]['checks']
            if mismatch == 'field':
                checks[0]['check']['field'] += '.undeclared'
            elif mismatch == 'kind':
                checks[0]['check']['kind'] = 'preserve_presence'
            elif mismatch == 'missing':
                checks.clear()
            else:
                checks.append(copy.deepcopy(checks[0]))
            with self.subTest(mismatch=mismatch), self.assertRaises(consumer.ContractError):
                consume(value)

    def test_rule_budgets_include_every_declaration_and_utf8_literal(self) -> None:
        for category in ('identity', 'preserve', 'preserve_presence', 'expect', 'expect_absent'):
            rules = dict(identity=[], preserve=[], preserve_presence=[], expect=[], expect_absent=[])
            declaration = {'field': 'ip.ttl', 'value': 'é'} if category == 'expect' else 'ip.ttl'
            with patch.object(consumer, 'MAX_RULE_DECLARATIONS', 2):
                rules[category] = [declaration, declaration]
                consumer.validate_rule_budget(rules)
                rules[category].append(declaration)
                with self.subTest(category=category), self.assertRaises(consumer.ContractError):
                    consumer.validate_rule_budget(rules)
            rules[category] = [declaration]
            size = len('ip.ttl'.encode()) + (1 + len('é'.encode()) if category == 'expect' else 0)
            with patch.object(consumer, 'MAX_RULE_DECLARATION_BYTES', size):
                consumer.validate_rule_budget(rules)
            with patch.object(consumer, 'MAX_RULE_DECLARATION_BYTES', size - 1):
                with self.subTest(category=category), self.assertRaises(consumer.ContractError):
                    consumer.validate_rule_budget(rules)

    def test_capture_timestamps_preserve_the_full_signed_range(self) -> None:
        for seconds in (-(2**63), -(2**32), 2**32, 2**63 - 1):
            value = envelope()
            value['result']['matches'][0]['ingress']['timestamp']['unix_seconds'] = seconds
            with self.subTest(seconds=seconds):
                report = consume(value)['report']
                self.assertEqual(report['matches'][0]['ingress']['timestamp']['unix_seconds'], seconds)
        for seconds in (-(2**63) - 1, 2**63):
            value = envelope()
            value['result']['matches'][0]['ingress']['timestamp']['unix_seconds'] = seconds
            with self.subTest(seconds=seconds), self.assertRaises(consumer.ContractError):
                consume(value)

    def test_decoding_rejects_other_commands_and_preserves_additive_fields(self) -> None:
        value = envelope()
        value['future'] = {'name': 'é', 'number': 1}
        self.assertEqual(consumer.decode(json.dumps(value).encode()), value)
        for command in ('analyze', 'verify-forwarding-other', '', None):
            value['command'] = command
            with self.subTest(command=command), self.assertRaises(consumer.ContractError):
                consumer.decode(json.dumps(value).encode())

    def test_typed_evidence_validates_bounds_and_preserves_values(self) -> None:
        for kind, value, expected in (
            ('bool', False, False), ('unsigned', 2**64 - 1, 2**64 - 1),
            ('signed', -(2**63), -(2**63)), ('signed', 2**63 - 1, 2**63 - 1),
            ('text', 'é', 'é'), ('bytes', [0, 255], (0, 255)),
            ('mac', [0, 1, 2, 3, 4, 255], (0, 1, 2, 3, 4, 255)),
        ):
            with self.subTest(kind=kind, value=value):
                self.assertEqual(consumer.field_value({'type': kind, 'value': value}), (kind, expected))
        for kind, value in (
            ('bool', 0), ('unsigned', -1), ('unsigned', 2**64), ('unsigned', True),
            ('signed', -(2**63) - 1), ('signed', 2**63), ('signed', False),
            ('text', '\ud800'), ('bytes', [-1]), ('bytes', [256]), ('bytes', [True]),
            ('mac', [0] * 5), ('mac', [0] * 7), ('ipv4', '::1'),
            ('ipv6', '192.0.2.1'), ('ipv6', 'fe80::1%eth0'), ('unknown', 1),
        ):
            with self.subTest(kind=kind, value=value), self.assertRaises(consumer.ContractError):
                consumer.field_value({'type': kind, 'value': value})

    def test_json_envelopes_reject_ambiguous_and_invalid_input(self) -> None:
        prefix = json.dumps(envelope()).encode()[:-1]
        for value in (
            prefix + b',"schema":"packetcraftr.output/v1"}',
            prefix + b',"extra":{"duplicate":0,"duplicate":0}}',
            prefix + b',"extra":NaN}', prefix + b',"extra":1e9999}',
            prefix + b',"extra":"\\ud800"}', b'\xff',
        ):
            with self.subTest(value=value), self.assertRaises(consumer.ContractError):
                consumer.decode(value)

    def test_presence_and_absence_outcomes_follow_readable_states(self) -> None:
        for actual in ('observed', 'absent'):
            for expected in ('observed', 'absent'):
                check = dict(check={'kind': 'preserve_presence'}, actual_state=actual,
                             expected_state=expected,
                             actual={'type': 'unsigned', 'value': 1} if actual == 'observed' else None,
                             expected={'type': 'unsigned', 'value': 2} if expected == 'observed' else None,
                             outcome='satisfied' if actual == expected else 'violated')
                consumer.validate_check(check)
                check['outcome'] = 'violated' if check['outcome'] == 'satisfied' else 'satisfied'
                with self.subTest(actual=actual, expected=expected), self.assertRaises(consumer.ContractError):
                    consumer.validate_check(check)
            check = dict(check={'kind': 'expect_absent'}, actual_state=actual,
                         expected_state=None,
                         actual={'type': 'unsigned', 'value': 1} if actual == 'observed' else None,
                         outcome='satisfied' if actual == 'absent' else 'violated')
            consumer.validate_check(check)
            check['outcome'] = 'violated' if check['outcome'] == 'satisfied' else 'satisfied'
            with self.assertRaises(consumer.ContractError):
                consumer.validate_check(check)

    def test_stream_enforces_contiguous_sequence_terminal_and_exit_status(self) -> None:
        terminal = envelope()
        encoded = json.dumps(terminal).encode() + b'\n'
        self.assertEqual(consumer.consume(io.BytesIO(encoded), 'ndjson', 0)['verdict'], 'pass')
        for invalid in (b'', encoded.rstrip(b'\n'), encoded + encoded):
            with self.subTest(invalid=invalid), self.assertRaises(consumer.ContractError):
                consumer.consume(io.BytesIO(invalid), 'ndjson', 0)
        for exit_code in (-1, 1, True):
            with self.subTest(exit_code=exit_code), self.assertRaises(consumer.ContractError):
                consumer.consume(io.BytesIO(encoded), 'ndjson', exit_code)
        terminal['sequence'] += 1
        with self.assertRaises(consumer.ContractError):
            consume(terminal)

    def test_record_and_stream_limits_accept_the_boundary_and_reject_overflow(self) -> None:
        encoded = json.dumps(envelope()).encode() + b'\n'
        for limit in ('MAX_RECORD', 'MAX_STREAM'):
            with patch.object(consumer, limit, len(encoded)):
                self.assertEqual(consumer.consume(io.BytesIO(encoded), 'ndjson', 0)['verdict'], 'pass')
            with patch.object(consumer, limit, len(encoded) - 1), self.assertRaises(consumer.ContractError):
                consumer.consume(io.BytesIO(encoded), 'ndjson', 0)

    def test_retained_examples_remain_valid(self) -> None:
        self.assertEqual(consume(envelope())['verdict'], 'pass')
        for name in ('success', 'complete', 'error'):
            path = ROOT / f'examples/documents/output-verify-forwarding-{name}.json'
            value = json.loads(path.read_text())
            mode = 'json' if value['mode'] == 'aggregate' else 'ndjson'
            code = 2 if value['status'] == 'error' else 0
            with self.subTest(name=name):
                consumer.consume(io.BytesIO(json.dumps(value).encode() + b'\n'), mode, code)

    def test_malformed_retained_evidence_is_rejected(self) -> None:
        mutations = {
            'frame zero': lambda r: r['matches'][0]['ingress'].update(frame=0),
            'frame outside capture': lambda r: r['matches'][0]['egress'].update(frame=3),
            'boolean frame': lambda r: r['matches'][0]['ingress'].update(frame=True),
            'nanosecond overflow': lambda r: r['matches'][0]['ingress']['timestamp'].update(nanoseconds=10**9),
            'timestamp overflow': lambda r: r['matches'][0]['ingress']['timestamp'].update(unix_seconds=2**63),
            'boolean timestamp': lambda r: r['matches'][0]['ingress']['timestamp'].update(unix_seconds=True),
            'link type overflow': lambda r: r['matches'][0]['ingress'].update(link_type=2**32),
            'interface negative': lambda r: r['matches'][0]['ingress'].update(interface=-1),
            'unknown incomplete': lambda r: r['matches'][0]['ingress'].update(incomplete='other'),
            'diagnostic shape': lambda r: r['matches'][0]['ingress'].update(diagnostics='truncated'),
            'incomplete census': lambda r: r['matches'][0]['ingress'].update(incomplete='truncated'),
            'key arity': lambda r: r['matches'][0].update(key=[]),
            'key type': lambda r: r['matches'][0].update(key=[{'type': 'unsigned', 'value': True}]),
            'empty identity field': lambda r: r['rules'].update(identity=['']),
            'duplicate frame': lambda r: r['matches'][1]['ingress'].update(frame=1),
            'rank out of range': lambda r: r['matches'][1].update(egress_order=2),
            'rank duplicate': lambda r: r['matches'][1].update(egress_order=0),
            'match ordering': lambda r: r['matches'].reverse(),
            'nonboolean reorder': lambda r: r['matches'][0].update(reordered=0),
            'invented reorder': lambda r: r['matches'][0].update(reordered=True),
            'reorder census': lambda r: r['summary'].update(reordered_pairs=1),
            'unmatched omission': lambda r: r['omitted'].update(unmatched_ingress=1),
            'unkeyed omission': lambda r: r['omitted'].update(unkeyed_egress=1),
            'group member omission': lambda r: r['omitted'].update(group_members=1),
            'unexpected typed check': lambda r: r['matches'][0]['checks'][0].update(actual={'type': 'unsigned', 'value': True}),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                value = envelope()
                mutate(value['result'])
                with self.assertRaises(consumer.ContractError):
                    consume(value)

    def test_identity_groups_are_unique_even_with_additive_wrapper_metadata(self) -> None:
        value = envelope()
        first, second = value['result']['matches']
        second['key'] = copy.deepcopy(first['key'])
        second['key'][0]['future'] = 'ignored metadata'
        with self.assertRaisesRegex(consumer.ContractError, 'identity occurs'):
            consume(value)

    def test_object_identity_is_hashable_and_ignores_member_order(self) -> None:
        value = envelope()
        first, second = value['result']['matches']
        a = {'type': 'unsigned', 'value': 1}
        b = {'type': 'text', 'value': 'two'}
        first['key'] = [{'type': 'object', 'value': {'a': a, 'b': b}}]
        self.assertEqual(consume(value)['verdict'], 'pass')
        second['key'] = [{'type': 'object', 'value': {'b': b, 'a': a}}]
        with self.assertRaisesRegex(consumer.ContractError, 'identity occurs'):
            consume(value)

    def test_utf8_scalar_and_finite_numbers_apply_to_additive_fields(self) -> None:
        for extra in ('1e9999', '"\\ud800"', '{"\\ud800": 0}'):
            data = json.dumps(envelope()).encode()[:-1] + b', "future": ' + extra.encode() + b'}'
            with self.subTest(extra=extra), self.assertRaises(consumer.ContractError):
                consumer.decode(data)
        for encoding in ('utf-16', 'utf-32'):
            with self.subTest(encoding=encoding), self.assertRaises(consumer.ContractError):
                consumer.decode(json.dumps(envelope()).encode(encoding))

    def test_explicit_depth_and_record_limits(self) -> None:
        value = envelope()
        value['future'] = json.loads('[' * 70 + '0' + ']' * 70)
        with self.assertRaises(consumer.ContractError):
            consume(value)
        from unittest.mock import patch
        with patch.object(consumer, 'MAX_RECORD', 10), self.assertRaises(consumer.ContractError):
            consumer.decode(json.dumps(envelope()).encode())

    def test_additive_metadata_and_pre_epoch_timestamp(self) -> None:
        value = envelope()
        value['future'] = {'unicode': '\u65e5\u672c', 'finite': 1.5}
        value['result']['matches'][0]['ingress']['timestamp']['unix_seconds'] = -1
        self.assertEqual(consume(value)['verdict'], 'pass')

    def test_invalid_exit_codes(self) -> None:
        for code in (False, True, -1, 0.0):
            with self.subTest(code=code), self.assertRaises(consumer.ContractError):
                consume(envelope(), code)

    def test_nonterminal_error_cannot_precede_success(self) -> None:
        value = envelope()
        event = dict(value, event='event', status='error', sequence=0)
        value['sequence'] = 1
        stream = '\n'.join(json.dumps(row) for row in (event, value)) + '\n'
        with self.assertRaises(consumer.ContractError):
            consumer.consume(io.BytesIO(stream.encode()), 'ndjson', 0)

    def test_every_check_kind_validates_its_typed_operands(self) -> None:
        for kind in ('preserve_presence', 'expect', 'expect_absent'):
            check = dict(check={'kind': kind}, outcome='violated', actual_state='observed',
                         expected_state=None, actual={'type': 'unsigned', 'value': True})
            with self.subTest(kind=kind), self.assertRaises(consumer.ContractError):
                consumer.validate_check(check)

    def test_observed_and_absent_states_agree_with_values(self) -> None:
        for state, actual in (('observed', None), ('absent', {'type': 'unsigned', 'value': 1})):
            check = dict(check={'kind': 'expect_absent'}, outcome='unevaluable',
                         actual_state=state, expected_state=None, actual=actual)
            with self.subTest(state=state), self.assertRaises(consumer.ContractError):
                consumer.validate_check(check)

    def test_evaluable_checks_cannot_be_marked_unevaluable(self) -> None:
        check = envelope()['result']['matches'][0]['checks'][0]
        check['outcome'] = 'unevaluable'
        with self.assertRaises(consumer.ContractError):
            consumer.validate_check(check)
        check['actual_state'] = 'truncated'
        consumer.validate_check(check)  # A partial value may legitimately remain attached.

    def test_expectations_do_not_invent_ingress_states(self) -> None:
        check = dict(check={'kind': 'expect'}, outcome='satisfied', actual_state='observed',
                     expected_state='observed', actual={'type': 'unsigned', 'value': 1})
        with self.assertRaises(consumer.ContractError):
            consumer.validate_check(check)

    def test_visible_reordering_with_omitted_pairs(self) -> None:
        value = envelope()
        report = value['result']
        a, b = report['matches']
        a['egress'], b['egress'] = b['egress'], a['egress']
        a['egress_order'], b['egress_order'] = 1, 0
        b['reordered'] = True
        report['summary']['reordered_pairs'] = 1
        self.assertEqual(consume(value)['verdict'], 'pass')
        b['reordered'] = False
        with self.assertRaises(consumer.ContractError):
            consume(value)

    def test_violation_evidence_is_not_an_unchecked_side_channel(self) -> None:
        value = envelope()
        report = value['result']
        pair = report['matches'][0]
        pair['checks'][0]['actual']['value'] = 63
        pair['checks'][0]['outcome'] = 'violated'
        report['summary'].update(checks_satisfied=1, checks_violated=1)
        report['verdict'] = 'fail'
        violation = {key: copy.deepcopy(pair[key]) for key in ('key', 'ingress', 'egress')}
        violation.update({key: copy.deepcopy(pair['checks'][0][key]) for key in ('check', 'expected', 'actual')})
        report['violations'] = [violation]
        self.assertEqual(consume(value, 1)['verdict'], 'fail')
        for change in ('undeclared', 'equal', 'missing_ingress', 'frame', 'key'):
            mutated = copy.deepcopy(value)
            row = mutated['result']['violations'][0]
            if change == 'undeclared': row['check']['field'] = 'tcp.flags'
            elif change == 'equal': row['actual'] = row['expected']
            elif change == 'missing_ingress': del row['ingress']
            elif change == 'frame': row['egress']['frame'] = 0
            else: row['key'] = []
            with self.subTest(change=change), self.assertRaises(consumer.ContractError):
                consume(mutated, 1)

    def test_ambiguous_group_and_omission_census(self) -> None:
        value = envelope()
        report = value['result']
        report['verdict'] = 'inconclusive'
        report['rules']['preserve'] = []
        report['rules']['comparison'] = 'correspondence_only'
        report['captures']['egress'].update(read=1, selected=1, keyed=1)
        group = dict(key=report['matches'][0]['key'],
                     ingress=[p['ingress'] for p in report['matches']],
                     egress=[report['matches'][0]['egress']], ingress_total=2, egress_total=1,
                     ingress_indistinguishable=True, egress_indistinguishable=True)
        report.update(matches=[], ambiguous=[group])
        report['summary'].update(unique_matches=0, checks_evaluated=0, checks_satisfied=0,
                                 ambiguous_groups=1, ambiguous_observations=3)
        self.assertEqual(consume(value, 1)['verdict'], 'inconclusive')
        for label, change in (
            ('member total', lambda g: g.update(ingress_total=1)),
            ('boolean total', lambda g: g.update(egress_total=True)),
            ('flag', lambda g: g.update(egress_indistinguishable=1)),
            ('order', lambda g: g['ingress'].reverse()),
        ):
            mutated = copy.deepcopy(value)
            change(mutated['result']['ambiguous'][0])
            with self.subTest(label=label), self.assertRaises(consumer.ContractError):
                consume(mutated, 1)
        report['ambiguous'] = []
        report['omitted'].update(ambiguous_groups=1, group_members=3)
        self.assertEqual(consume(value, 1)['verdict'], 'inconclusive')


if __name__ == '__main__':
    unittest.main()
