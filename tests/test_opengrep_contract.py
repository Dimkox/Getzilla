from __future__ import annotations

import copy
import importlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))


class OpenGrepContractTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('getzilla.opengrep_contract'),
                             'the shared complete-report contract is required')
        self.contract = importlib.import_module('getzilla.opengrep_contract')
        self.clean = {'version': '1.30.1', 'results': [], 'errors': [],
                      'paths': {'scanned': ['src/app.py']}}

    def validate(self, value, code=0, expected=('src/app.py',)):
        return self.contract.validate_report(value, expected, code)

    def test_complete_clean_and_finding_preserve_distinct_outcomes(self):
        self.assertEqual(self.validate(self.clean)['outcome'], 'pass')
        finding = {'check_id': 'rule', 'path': 'src/app.py', 'start': {'line': 2},
                   'extra': {'severity': 'WARNING', 'message': 'inert', 'is_ignored': False}}
        self.clean['results'] = [finding]
        for code in (0, 1):
            self.assertEqual(self.validate(self.clean, code)['outcome'], 'finding')

    def test_every_diagnostic_blocks_before_findings(self):
        for diagnostic in ({'level': 'warn', 'type': 'PartialParsing'},
                           {'level': 'info', 'type': 'Timeout'},
                           {'level': 'error'}, None, 'invalid'):
            for findings in ([], [{'check_id': 'accepted-finding'}]):
                value = copy.deepcopy(self.clean)
                value.update(errors=[diagnostic], results=findings)
                with self.subTest(diagnostic=diagnostic, findings=findings), self.assertRaisesRegex(
                        self.contract.OpenGrepError, '^analysis_diagnostics$'):
                    self.validate(value)

    def test_required_shapes_version_and_exit_are_closed(self):
        values = [{}, {**self.clean, 'version': 'unknown'},
                  {**self.clean, 'errors': None}, {**self.clean, 'results': [None]},
                  {**self.clean, 'paths': {}}, {**self.clean, 'paths': {'scanned': None}},
                  {**self.clean, 'unknown_safety_field': True},
                  {**self.clean, 'paths': {'scanned': ['src/app.py'], 'unknown_safety_field': True}},
                  {**self.clean, 'interfile_languages_used': ['unknown']}]
        for value in values:
            with self.subTest(value=value), self.assertRaises(self.contract.OpenGrepError):
                self.validate(value)
        for code in (1, 2, 124, -9, True):
            with self.subTest(code=code), self.assertRaises(self.contract.OpenGrepError):
                self.validate(self.clean, code)

    def test_missing_extra_duplicate_and_aliased_paths_are_never_coverage(self):
        for paths in ([], ['other.py'], ['src/app.py', 'extra.py'], ['src/app.py'] * 2,
                      ['./src/app.py'], ['/src/app.py'], ['src/../app.py'], [1]):
            value = copy.deepcopy(self.clean)
            value['paths']['scanned'] = paths
            with self.subTest(paths=paths), self.assertRaises(self.contract.OpenGrepError):
                self.validate(value)

    def test_expected_roster_cannot_silently_deduplicate_or_be_empty(self):
        for paths in ([], ['src/app.py'] * 2, ['Src/app.py', 'src/app.py'],
                      ['src\\app.py'], ['../app.py'], ['a\n.py'], [None]):
            with self.subTest(paths=paths), self.assertRaises(self.contract.OpenGrepError):
                self.contract.targets(paths)

    def test_findings_are_typed_bound_and_not_suppressed(self):
        finding = {'check_id': 'rule', 'path': 'src/app.py', 'start': {'line': 2}, 'extra': {}}
        for change in ({'path': 'other.py'}, {'start': {'line': True}}, {'start': {'line': 0}},
                       {'check_id': ''}, {'extra': []}, {'extra': {'is_ignored': True}}):
            value = copy.deepcopy(self.clean)
            value['results'] = [{**finding, **change}]
            with self.subTest(change=change), self.assertRaises(self.contract.OpenGrepError):
                self.validate(value)

    def test_strict_bounded_json_rejects_duplicates_nonfinite_and_truncation(self):
        self.assertEqual(self.contract.decode_report(json.dumps(self.clean)), self.clean)
        for raw in ('{"results":[],"results":[]}', '{"value":NaN}', '{', '[]'):
            with self.subTest(raw=raw), self.assertRaises(self.contract.OpenGrepError):
                self.contract.decode_report(raw)

    def test_direct_core_binds_empty_findings_to_exact_rules_and_physical_source(self):
        self.assertTrue(callable(getattr(self.contract, 'project_core_report', None)),
                        'the actual core schema needs a bounded typed projection')
        core = {**self.clean, 'paths': {'scanned': ['/proc/self/fd/5']},
                'rules_by_engine': [['rule', 'OSS']], 'engine_requested': 'OSS',
                'interfile_languages_used': [], 'skipped_rules': []}
        rules = {'rule': {'id': 'rule', 'severity': 'WARNING', 'message': 'inert'}}
        value = self.contract.project_core_report(core, {'/proc/self/fd/5': 'src/app.py'}, rules, 0)
        self.assertEqual(value['outcome'], 'pass')
        self.assertEqual(value['coverage']['expected'], ['src/app.py'])
        for change in ({'rules_by_engine': []}, {'rules_by_engine': [['other', 'OSS']]},
                       {'rules_by_engine': [['rule', 'OSS']] * 2}, {'engine_requested': 'unknown'},
                       {'unknown_safety_field': True}, {'paths': {'scanned': ['/other.py']}}):
            with self.subTest(change=change), self.assertRaises(self.contract.OpenGrepError):
                self.contract.project_core_report({**core, **change}, {'/proc/self/fd/5': 'src/app.py'}, rules, 0)

    def test_direct_core_diagnostics_precede_all_findings_and_projection(self):
        self.assertTrue(callable(getattr(self.contract, 'project_core_report', None)))
        core = {'version': '1.30.1', 'errors': [{'severity': 'warning'}],
                'results': [{'check_id': 'accepted'}]}
        with self.assertRaisesRegex(self.contract.OpenGrepError, '^analysis_diagnostics$'):
            self.contract.project_core_report(core, {'/proc/self/fd/5': 'src/app.py'},
                                              {'rule': {'id': 'rule', 'severity': 'WARNING', 'message': 'inert'}}, 0)

    def test_direct_core_otherwise_valid_diagnostics_cannot_become_clean_or_finding(self):
        core = {'version': '1.30.1', 'errors': [{'severity': 'warning', 'type': 'PartialParsing'}],
                'paths': {'scanned': ['/proc/self/fd/5']}, 'rules_by_engine': [['rule', 'OSS']],
                'engine_requested': 'OSS', 'interfile_languages_used': [], 'skipped_rules': []}
        finding = {'check_id': 'rule', 'path': '/proc/self/fd/5',
                   'start': {'line': 1, 'col': 1, 'offset': 0},
                   'end': {'line': 1, 'col': 2, 'offset': 1},
                   'extra': {'engine_kind': 'OSS', 'is_ignored': False, 'metavars': {}}}
        for findings in ([], [finding]):
            with self.subTest(findings=findings), self.assertRaisesRegex(
                    self.contract.OpenGrepError, '^analysis_diagnostics$'):
                self.contract.project_core_report({**core, 'results': findings},
                    {'/proc/self/fd/5': 'src/app.py'},
                    {'rule': {'id': 'rule', 'severity': 'WARNING', 'message': 'inert'}}, 0)


if __name__ == '__main__':
    unittest.main()
