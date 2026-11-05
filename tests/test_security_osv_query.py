"""Qualified OSV query transcripts: public fixtures, no actual network."""
from __future__ import annotations

import copy
import importlib
import io
import json
from pathlib import Path
import sys
import unittest
from datetime import timedelta
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from tests.test_known_vulns import _repo
from tests.test_security_data import NOW
from getzilla import known_vulns as KV

ID = 'PUBLIC-QUERY-1'
MODIFIED = '2026-11-01T00:00:00.123456789Z'


def detail(identifier=ID):
    return {'id': identifier, 'modified': MODIFIED, 'aliases': None,
            'affected': [{'package': {'ecosystem': 'PyPI', 'name': 'public-package'}, 'versions': ['1.0.0']}]}


def rewrite(payload, edit):
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        members = {item.filename: archive.read(item) for item in archive.infolist()}
    edit(members)
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return output.getvalue()


class QueryTests(unittest.TestCase):
    def setUp(self):
        try:
            self.query = importlib.import_module('getzilla.security_osv_query')
        except ModuleNotFoundError:
            self.query = None
        self.assertIsNotNone(self.query, 'qualified inventory-bound query transcript implementation is missing')
        temporary, self.root = _repo({'requirements.txt': 'public-package==1.0.0\npublic-safe==2.0\n'})
        self.addCleanup(temporary.cleanup)
        self.inventory = KV.dependency_inventory(self.root, KV.load_config(self.root))[2]
        self.calls = []

    def transport(self, method, url, body, deadline, maximum):
        self.calls.append((method, url, body, deadline))
        if method == 'POST':
            request = json.loads(body)
            answer = {'results': [{} for _ in request['queries']]}
        else:
            answer = detail()
        return self.query.QueryResponse(method, url, body, json.dumps(answer).encode(), 200, url)

    def build(self, transport=None):
        return self.query.acquire_transcript(self.inventory, transport=transport or self.transport, now=NOW)

    def test_complete_zero_hit_transcript_is_portable_but_not_global_catalog(self):
        payload, acquisition, coverage = self.build()
        replay = self.query.validate_transcript(payload, expected_inventory=self.inventory)
        self.assertEqual(coverage, {'scopes': ['PyPI'], 'complete': True, 'record_count': 0, 'schema': 'osv-query-1'})
        self.assertEqual(replay['hits'], [])
        self.assertEqual(len(replay['plan']), 2)
        self.assertEqual(acquisition['last_verified_sync_utc'], NOW.isoformat())
        self.assertEqual(len(self.calls), 1)
        temporary, root = _repo({'requirements.txt': 'public-package==1.0.0\npublic-safe==2.0\n'})
        with temporary:
            other = KV.dependency_inventory(root, KV.load_config(root))[2]
            self.assertNotEqual(self.inventory, other)
            self.query.validate_transcript(payload, expected_inventory=other)

    def test_positive_details_have_exact_identity_and_are_not_placeholders(self):
        def transport(method, url, body, deadline, maximum):
            if method == 'POST':
                request = json.loads(body)
                answer = {'results': [{'vulns': [{'id': ID, 'modified': MODIFIED}]} if q['package']['name'] == 'public-package'
                                      else {} for q in request['queries']]}
                return self.query.QueryResponse(method, url, body, json.dumps(answer).encode(), 200, url)
            return self.transport(method, url, body, deadline, maximum)
        payload, _, coverage = self.build(transport)
        replay = self.query.validate_transcript(payload, expected_inventory=self.inventory)
        self.assertEqual(coverage['record_count'], 1)
        self.assertEqual([item['id'] for item in replay['hits']], [ID])
        self.assertEqual(replay['records'][ID]['modified'], MODIFIED)
        self.assertIsNone(replay['records'][ID]['aliases'])

    def test_missing_results_and_repeated_continuation_are_incomplete(self):
        for missing in (True, False):
            calls = []
            def transport(method, url, body, deadline, maximum):
                calls.append(method)
                answer = {'results': [] if missing else [
                    {'next_page_token': 'repeat'} for _ in json.loads(body)['queries']]}
                return self.query.QueryResponse(method, url, body, json.dumps(answer).encode(), 200, url)
            with self.subTest(missing=missing), self.assertRaises(self.query.SecurityDataError):
                self.build(transport)
            self.assertLessEqual(len(calls), 2, 'a known repeated cursor must not consume the entire request budget')

    def test_mismatched_detail_identity_or_modified_or_aliases_refuses(self):
        for changed in ({'id': 'PUBLIC-WRONG'}, {'modified': '2026-11-01T00:00:00.123456788Z'},
                        {'aliases': ['PUBLIC-BAD,']}):
            def transport(method, url, body, deadline, maximum):
                answer = {'results': [{'vulns': [{'id': ID, 'modified': MODIFIED}]}, {}]} if method == 'POST' else {**detail(), **changed}
                return self.query.QueryResponse(method, url, body, json.dumps(answer).encode(), 200, url)
            with self.subTest(changed=changed), self.assertRaises(self.query.SecurityDataError):
                self.build(transport)

    def test_detail_cap_refuses_before_detail_request(self):
        calls = []
        def transport(method, url, body, deadline, maximum):
            calls.append(method)
            answer = {'results': [{'vulns': [{'id': ID, 'modified': MODIFIED}]}, {}]}
            return self.query.QueryResponse(method, url, body, json.dumps(answer).encode(), 200, url)
        with patch.object(self.query, 'MAX_DETAIL_FETCHES', 0), self.assertRaises(self.query.SecurityDataError):
            self.build(transport)
        self.assertEqual(calls, ['POST'])

    def test_actual_301_detail_census_refuses_without_any_placeholder_fetch(self):
        calls = []
        def transport(method, url, body, deadline, maximum):
            calls.append(method)
            answer = {'results': [{'vulns': [{'id': f'PUBLIC-QUERY-{i:04}', 'modified': MODIFIED}
                                            for i in range(301)]}, {}]} if method == 'POST' else detail(url.rsplit('/', 1)[1])
            return self.query.QueryResponse(method, url, body, json.dumps(answer).encode(), 200, url)
        with self.assertRaises(self.query.SecurityDataError):
            self.build(transport)
        self.assertEqual(calls, ['POST'])

    def test_earliest_request_clock_is_not_replaced_by_completion_time(self):
        with patch.object(self.query, '_clock', side_effect=[NOW, NOW + timedelta(seconds=1)]):
            payload, acquisition, _ = self.query.acquire_transcript(self.inventory, transport=self.transport)
        self.assertEqual(acquisition['last_verified_sync_utc'], NOW.isoformat())
        replay = self.query.validate_transcript(payload, expected_inventory=self.inventory)
        self.assertEqual(replay['completed_at_utc'], (NOW + timedelta(seconds=1)).isoformat())

    def test_detail_for_another_package_cannot_support_a_positive_query(self):
        def transport(method, url, body, deadline, maximum):
            answer = {'results': [{'vulns': [{'id': ID, 'modified': MODIFIED}]}, {}]} if method == 'POST' else detail()
            if method == 'GET':
                answer['affected'][0]['package']['name'] = 'public-unrelated'
            return self.query.QueryResponse(method, url, body, json.dumps(answer).encode(), 200, url)
        with self.assertRaises(self.query.SecurityDataError):
            self.build(transport)

    def test_malformed_range_cannot_hide_behind_a_positive_exact_version(self):
        def transport(method, url, body, deadline, maximum):
            answer = {'results': [{'vulns': [{'id': ID, 'modified': MODIFIED}]}, {}]} if method == 'POST' else detail()
            if method == 'GET':
                answer['affected'][0]['ranges'] = [{'type': 'ECOSYSTEM', 'events': [
                    {'introduced': '0'}, {'fixed': '1.5'}, {'introduced': '2'}, {'last_affected': '3'}]}]
            return self.query.QueryResponse(method, url, body, json.dumps(answer).encode(), 200, url)
        with self.assertRaises(self.query.SecurityDataError):
            self.build(transport)

    def test_malformed_consumed_detail_metadata_has_a_closed_refusal(self):
        def transport(method, url, body, deadline, maximum):
            answer = {'results': [{'vulns': [{'id': ID, 'modified': MODIFIED}]}, {}]} if method == 'POST' else detail()
            if method == 'GET':
                answer['affected'][0]['database_specific'] = 'public unsupported shape'
            return self.query.QueryResponse(method, url, body, json.dumps(answer).encode(), 200, url)
        with self.assertRaises(self.query.SecurityDataError):
            self.build(transport)

    def test_deadline_must_be_finite_and_cannot_be_exceeded(self):
        for deadline in (float('nan'), float('inf'), -1):
            with self.subTest(deadline=deadline), self.assertRaises(self.query.SecurityDataError):
                self.query.acquire_transcript(self.inventory, transport=self.transport, now=NOW, deadline=deadline)

    def test_complete_pagination_keeps_query_identity_and_every_detail(self):
        calls = []
        def transport(method, url, body, deadline, maximum):
            calls.append((method, url, body))
            if method == 'POST':
                request = json.loads(body)
                if 'page_token' in request['queries'][0]:
                    self.assertEqual(len(request['queries']), 1)
                    self.assertEqual(request['queries'][0]['package']['name'], 'public-package')
                    answer = {'results': [{'vulns': [{'id': ID + '-2', 'modified': MODIFIED}]}]}
                else:
                    answer = {'results': [{'vulns': [{'id': ID, 'modified': MODIFIED}], 'next_page_token': 'page-2'}, {}]}
            else:
                answer = detail(url.rsplit('/', 1)[1])
            return self.query.QueryResponse(method, url, body, json.dumps(answer).encode(), 200, url)
        payload, _, coverage = self.build(transport)
        replay = self.query.validate_transcript(payload, expected_inventory=self.inventory)
        self.assertEqual(coverage['record_count'], 2)
        self.assertEqual({item['query_index'] for item in replay['hits']}, {0})
        self.assertEqual(len(calls), 4)

    def test_changed_inventory_and_raw_body_never_reuse_old_coverage(self):
        payload, _, _ = self.build()
        changed = copy.deepcopy(self.inventory)
        changed['objects'][0]['version'] = '9.0.0'
        with self.assertRaises(self.query.SecurityDataError):
            self.query.validate_transcript(payload, expected_inventory=changed)
        def change(members):
            name = next(name for name in members if name.startswith('responses/'))
            members[name] = b'{"results":[]}'
        with self.assertRaises(self.query.SecurityDataError):
            self.query.validate_transcript(rewrite(payload, change), expected_inventory=self.inventory)

    def test_semantically_equal_same_length_response_cannot_replace_exact_bytes(self):
        payload, _, _ = self.build()
        def change(members):
            name = next(name for name in members if name.startswith('responses/'))
            original = members[name]
            members[name] = original.replace(b' ', b'\t', 1)
            self.assertNotEqual(original, members[name])
            self.assertEqual(len(original), len(members[name]))
            self.assertEqual(json.loads(original), json.loads(members[name]))
        with self.assertRaises(self.query.SecurityDataError):
            self.query.validate_transcript(rewrite(payload, change), expected_inventory=self.inventory)

    def test_same_length_request_for_another_package_cannot_borrow_old_binding(self):
        payload, _, _ = self.build()
        def change(members):
            name = next(name for name in members if name.startswith('requests/'))
            original = members[name]
            members[name] = original.replace(b'public-package', b'publix-package')
            self.assertNotEqual(original, members[name])
            self.assertEqual(len(original), len(members[name]))
        with self.assertRaises(self.query.SecurityDataError):
            self.query.validate_transcript(rewrite(payload, change), expected_inventory=self.inventory)

    def test_closed_archive_membership_and_count_refuse_extra_or_missing(self):
        payload, _, _ = self.build()
        for action in (lambda members: members.update({'public-extra.json': b'{}'}),
                       lambda members: members.pop(next(name for name in members if name.startswith('responses/')))):
            with self.subTest(action=action), self.assertRaises(self.query.SecurityDataError):
                self.query.validate_transcript(rewrite(payload, action), expected_inventory=self.inventory)

    def test_query_census_precedes_zipfile_member_materialization(self):
        payload, _, _ = self.build()
        original = self.query.zipfile.ZipFile
        with patch.object(self.query, 'MAX_EXCHANGES', 0), \
                patch.object(self.query.zipfile, 'ZipFile', wraps=original) as constructor:
            with self.assertRaises(self.query.SecurityDataError):
                self.query.validate_transcript(payload, expected_inventory=self.inventory)
        constructor.assert_not_called()

    def test_empty_inventory_is_absent_not_a_query_source(self):
        temporary, root = _repo({'README.md': 'public empty root\n'})
        with temporary:
            inventory = KV.dependency_inventory(root, KV.load_config(root))[2]
            with self.assertRaises(self.query.SecurityDataError):
                self.query.acquire_transcript(inventory, transport=self.transport, now=NOW)
        self.assertEqual(self.calls, [])
