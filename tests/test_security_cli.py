from __future__ import annotations

import copy
import unittest
from datetime import datetime, timedelta, timezone

from getzilla.security_cli import REQUIRED_CHECKS, finalize_report
from getzilla.security_licenses import ALLOWED, _select_expression
from getzilla.expanded_security import CHECK_FAMILIES
from getzilla.security_data import SOURCE_URLS

NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)


class SecurityCliTests(unittest.TestCase):
    def report(self):
        source = {'head_sha': 'a' * 40, 'tree_sha': 'b' * 40,
                  'checker_sha': 'c' * 40, 'checker_tree_sha': 'd' * 40,
                  'candidate_clean': True, 'checker_clean': True, 'same_project': True}
        checks = [{'name': name, 'status': 'pass', 'summary': 'observed', 'details': [{
            'kind': 'security-result', 'schema_version': 1, 'outcome': 'pass',
            'family': CHECK_FAMILIES.get(name,name), 'inventory_sha256':'e'*64, 'policy_sha256':'f'*64,
            'assurance':'local-input-integrity-only', 'findings':[], 'gaps':[], 'data_sources': []}]} for name in REQUIRED_CHECKS]
        required={'known-vulnerabilities':'osv:PyPI','security-kev':'kev','security-epss':'epss',
                  'security-malicious-packages':'osv:PyPI','security-licenses':'artifact-license-catalog',
                  'security-container-images':'trivy-db'}
        for check in checks:
            detail=check['details'][0]
            if check['name'] in required:
                detail['data_sources']=[self.source(required[check['name']])]
            if check['name'] in {'opengrep','bandit','trivy-config'}:
                detail['coverage']={'expected':['src/example.py'],'observed':['src/example.py']}

        return source, checks

    def source(self, source_id):
        url=SOURCE_URLS.get(source_id, 'urn:getzilla:artifact-license-catalog:1' if source_id=='artifact-license-catalog'
                           else 'ghcr.io/aquasecurity/trivy-db:2')
        return {'database':'fixture','source_id':source_id,'source_url':url,'content_sha256':'a'*64,
                'payload_size':1,'acquisition':{'last_verified_sync_utc':NOW.isoformat(),
                'source_published_at':NOW.isoformat(),
                'retrieval_kind':'catalog-binding' if source_id=='artifact-license-catalog' else 'download'},
                'coverage':{'schema':'fixture','scopes': ['PyPI'] if source_id.startswith('osv:') else ['CVE'] if source_id in {'kev','epss'} else ['catalog'] if source_id=='artifact-license-catalog' else ['container-images'],'complete':True,'record_count':1}}

    def test_informational_and_disposed_findings_keep_their_existing_semantics(self):
        source, checks=self.report()
        by_name={c['name']:c['details'][0] for c in checks}
        by_name['known-vulnerabilities']['accepted']=[{'ecosystem':'PyPI','package':'example','version':'1.0.0',
            'manifest':'requirements.txt','id':'OSV-accepted','aliases':[],'summary':'accepted fixture',
            'severity':'MODERATE','fixed':[],'accepted_until':'2026-11-04'}]
        by_name['secret-scan']['findings']=[{'rule':'generic-secret','path':'src/example.py','line':1,'column':1,
            'file_sha256':'b'*64,'disposition':'PUBLIC_TOKEN_1'}]
        by_name['security-epss']['findings']=[{'id':'CVE-2026-12345','aliases':[],
            'intelligence':{},'enrichment_reason':'cve-aliases'}]
        self.assertEqual(finalize_report(source,source,checks,'e'*64,'f'*64,now=NOW)['status'],'pass')
        by_name['secret-scan']['findings'][0]['disposition']=None
        self.assertEqual(finalize_report(source,source,checks,'e'*64,'f'*64,now=NOW)['status'],'fail')

    def test_license_integrity_records_remain_informational_when_they_pass(self):
        source,checks=self.report()
        detail=next(c['details'][0] for c in checks if c['name']=='security-licenses')
        detail['findings']=[{'ecosystem':'PyPI','package':'example','version':'1.0.0','manifest':'requirements.txt',
            'status':'pass','expression':'MIT','selected_expression':'MIT','distribution':'internal',
            'artifact_sha256':'a'*64,'origin':{},'license_files':[{'path':'LICENSE','sha256':'b'*64}],
            'notice_files':[],'obligations':'internal use; license evidence retained'}]
        self.assertEqual(finalize_report(source,source,checks,'e'*64,'f'*64,now=NOW)['status'],'pass')
        detail['findings'][0]['status']='fail'
        self.assertEqual(finalize_report(source,source,checks,'e'*64,'f'*64,now=NOW)['status'],'fail')

    def accepted(self, deadline, identifier='OSV-accepted'):
        return {'ecosystem':'PyPI','package':'example','version':'1.0.0','manifest':'requirements.txt',
                'id':identifier,'aliases':[],'summary':'accepted fixture','severity':'MODERATE',
                'fixed':[],'accepted_until':deadline}

    def test_selected_license_must_match_an_approved_original_branch(self):
        cases=[('MIT OR Apache-2.0','Apache-2.0','pass'),
               ('GPL-3.0-only OR MIT','MIT','pass'),
               ('(MIT OR Apache-2.0) AND BSD-2-Clause','Apache-2.0 AND BSD-2-Clause','pass'),
               ('MIT AND Apache-2.0','Apache-2.0 AND MIT','pass'),
               ('GPL-3.0-only','MIT','fail'), ('MIT AND Apache-2.0','MIT','fail'),
               ('MIT OR Apache-2.0','BSD-2-Clause','fail'),
               ('MIT OR Apache-2.0','MIT AND Apache-2.0','fail'),
               ('MIT','MIT OR Apache-2.0','fail'), ('MIT AND GPL-3.0-only','MIT','fail'),
               ('MIT OR (Apache-2.0 AND BSD-2-Clause)','Apache-2.0','fail'),
               ('LicenseRef-custom OR MIT','MIT','fail')]
        for expression,selected,want in cases:
            with self.subTest(expression=expression,selected=selected):
                source,checks=self.report()
                detail=next(c['details'][0] for c in checks if c['name']=='security-licenses')
                detail['findings']=[{'ecosystem':'PyPI','package':'example','version':'1.0.0',
                    'manifest':'requirements.txt','status':'pass','expression':expression,
                    'selected_expression':selected,'distribution':'internal','artifact_sha256':'a'*64,
                    'origin':{},'license_files':[{'path':'LICENSE','sha256':'b'*64}],
                    'notice_files':[],'obligations':'internal use; license evidence retained'}]
                result=finalize_report(source,source,checks,'e'*64,'f'*64,now=NOW)
                self.assertEqual(result['status'],want,result['qualification_gaps'])

    def test_not_applicable_accepted_requires_an_empty_list_or_absence(self):
        for accepted in (False, True, None, 0, '', 'accepted', {}, {'id': 'OSV-example'},
                         (), set(), [[]], [False], [self.accepted('2026-11-04')], []):
            with self.subTest(accepted=accepted):
                source, checks = self.report()
                check = next(c for c in checks if c['name'] == 'known-vulnerabilities')
                check['status'] = 'skip'
                detail = check['details'][0]
                detail.update(outcome='not_applicable', data_sources=[], accepted=accepted,
                    applicability_evidence={'complete': True, 'inventory_sha256': 'e'*64,
                                            'reason': 'complete-inventory-no-objects'})
                result = finalize_report(source, source, checks, 'e'*64, 'f'*64, now=NOW)
                self.assertEqual(result['status'], 'pass' if accepted == [] else 'fail')
                if accepted != []:
                    self.assertIsNone(result['valid_until_utc'])
                    self.assertTrue(result['qualification_gaps'])
        detail.pop('accepted')
        self.assertEqual(finalize_report(source, source, checks, 'e'*64, 'f'*64, now=NOW)['status'], 'pass')

    def test_selected_license_can_prove_overlapping_original_alternatives(self):
        cases = [
            ('(MIT OR Apache-2.0) AND (MIT OR BSD-2-Clause)', 'MIT AND BSD-2-Clause', 'pass'),
            ('(MIT OR Apache-2.0) AND (MIT OR BSD-2-Clause)', 'Apache-2.0 AND MIT', 'pass'),
            ('(MIT OR BSD-2-Clause) AND (MIT OR Apache-2.0)', 'BSD-2-Clause AND MIT', 'pass'),
            ('(MIT OR Apache-2.0) AND (MIT OR BSD-2-Clause)', 'MIT', 'pass'),
            ('(MIT OR Apache-2.0) AND (MIT OR BSD-2-Clause)', 'Apache-2.0 AND BSD-2-Clause', 'pass'),
            ('(MIT OR Apache-2.0) AND (MIT OR BSD-2-Clause)', 'MIT AND Apache-2.0 AND BSD-2-Clause', 'fail'),
            ('(MIT OR Apache-2.0) AND (MIT OR BSD-2-Clause)', 'Apache-2.0', 'fail'),
            ('(MIT OR Apache-2.0) AND (MIT OR BSD-2-Clause)', 'MIT AND ISC', 'fail'),
            ('(MIT OR Apache-2.0) AND (GPL-3.0-only OR BSD-2-Clause)', 'MIT AND BSD-2-Clause', 'pass'),
            ('(MIT OR Apache-2.0) AND GPL-3.0-only', 'MIT', 'fail'),
            ('(MIT OR Apache-2.0) AND (MIT OR LicenseRef-custom)', 'MIT', 'fail'),
            ('(MIT OR Apache-2.0) AND (MIT OR unknown-license)', 'MIT', 'fail'),
            ('(MIT OR Apache-2.0) AND (MIT OR Apache-2.0 WITH LLVM-exception)', 'MIT', 'fail'),
        ]
        for expression, selected, expected in cases:
            with self.subTest(expression=expression, selected=selected):
                source, checks = self.report()
                detail = next(c['details'][0] for c in checks if c['name'] == 'security-licenses')
                detail['findings'] = [{'ecosystem': 'PyPI', 'package': 'example', 'version': '1.0.0',
                    'manifest': 'requirements.txt', 'status': 'pass', 'expression': expression,
                    'selected_expression': selected, 'distribution': 'internal', 'artifact_sha256': 'a'*64,
                    'origin': {}, 'license_files': [{'path': 'LICENSE', 'sha256': 'b'*64}],
                    'notice_files': [], 'obligations': 'internal use; license evidence retained'}]
                result = finalize_report(source, source, checks, 'e'*64, 'f'*64, now=NOW)
                self.assertEqual(result['status'], expected, result['qualification_gaps'])

    def test_exact_license_proof_remains_bounded_by_policy_and_parser_limits(self):
        group = '(' + ' OR '.join(ALLOWED) + ')'
        expression = ' AND '.join([group] * 18)  # 251 tokens, with exponentially many raw branches.
        selected, identifiers = _select_expression(expression, list(ALLOWED), require_all=True)
        self.assertEqual(selected, list(ALLOWED))
        self.assertEqual(identifiers, set(ALLOWED))
        for expression, allowed in (
                (' AND '.join([group] * 19), list(ALLOWED)),
                ('('*33 + 'MIT' + ')'*33, ['MIT']),
                ('MIT' + ' '*4096, ['MIT']),
                ('MIT', list(ALLOWED) + ['GPL-3.0-only']),
                ('MIT', ['GPL-3.0-only']),
                ('MIT', [])):
            with self.subTest(expression=expression[:80], allowed=allowed), self.assertRaises(ValueError):
                _select_expression(expression, allowed, require_all=True)

    def test_exact_license_policy_guard_is_independently_enforced(self):
        allowed = list(ALLOWED)
        expression = ' AND '.join(allowed)
        selected, identifiers = _select_expression(expression, allowed, require_all=True)
        self.assertEqual(selected, allowed)
        self.assertEqual(identifiers, set(allowed))
        # Each rejected selection matches a complete expression branch. A later
        # branch-mismatch refusal must not conceal a missing policy guard.
        for expression, selected in (
                (expression, allowed + [allowed[0]]),
                (' AND '.join(allowed + ['GPL-3.0-only']), allowed + ['GPL-3.0-only']),
                ('GPL-3.0-only', ['GPL-3.0-only'])):
            with self.subTest(expression=expression, selected=selected), self.assertRaises(ValueError):
                _select_expression(expression, selected, require_all=True)

    def test_accepted_exception_validity_stops_at_the_inclusive_utc_date_boundary(self):
        source,checks=self.report()
        checks[1]['details'][0]['accepted']=[self.accepted('2026-11-03')]
        for current in (NOW,datetime(2026,11,3,23,59,59,999999,tzinfo=timezone.utc)):
            result=finalize_report(source,source,checks,'e'*64,'f'*64,now=current)
            self.assertEqual(result['status'],'pass',result['qualification_gaps'])
            self.assertEqual(result['valid_until_utc'],'2026-11-04T00:00:00+00:00')
        result=finalize_report(source,source,checks,'e'*64,'f'*64,
                               now=datetime(2026,11,4,tzinfo=timezone.utc))
        self.assertEqual(result['status'],'fail')
        self.assertIsNone(result['valid_until_utc'])

    def test_earliest_exception_and_source_deadlines_both_bound_report_validity(self):
        for older_hours,want in ((0,'2026-11-04T00:00:00+00:00'),(60,'2026-11-03T12:00:00+00:00')):
            for dates in (('2026-11-05','2026-11-03'),('2026-11-03','2026-11-05')):
                with self.subTest(source_age=older_hours,dates=dates):
                    source,checks=self.report()
                    checks[1]['details'][0]['accepted']=[self.accepted(d,'OSV-'+str(i)) for i,d in enumerate(dates)]
                    checks[3]['details'][0]['data_sources'][0]['acquisition']['source_published_at']=(NOW-timedelta(hours=older_hours)).isoformat()
                    result=finalize_report(source,source,checks,'e'*64,'f'*64,now=NOW)
                    self.assertEqual(result['status'],'pass',result['qualification_gaps'])
                    self.assertEqual(result['valid_until_utc'],want)

    def test_malformed_exception_dates_refuse_and_far_future_dates_keep_source_bound(self):
        for deadline in ('bad-date','2026-02-30','2026-11-03T00:00:00',None):
            source,checks=self.report()
            checks[1]['details'][0]['accepted']=[self.accepted(deadline)]
            with self.subTest(deadline=deadline):
                result=finalize_report(source,source,checks,'e'*64,'f'*64,now=NOW)
                self.assertEqual(result['status'],'fail')
                self.assertIsNone(result['valid_until_utc'])
        source,checks=self.report()
        checks[1]['details'][0]['accepted']=[self.accepted('9999-12-31')]
        result=finalize_report(source,source,checks,'e'*64,'f'*64,now=NOW)
        self.assertEqual(result['status'],'pass',result['qualification_gaps'])
        self.assertEqual(result['valid_until_utc'],'2026-11-06T00:00:00+00:00')

    def test_incomplete_sources_coverage_and_expired_acceptance_block(self):
        source, baseline=self.report()
        cases=[('source',None),('coverage',None),('expired',None),('shape',None)]
        for kind,_ in cases:
            checks=copy.deepcopy(baseline)
            if kind=='source':
                checks[1]['details'][0]['data_sources'][0]['coverage']['complete']=False
            elif kind=='coverage':
                checks[-1]['details'][0]['coverage']['observed']=[]
            elif kind=='shape':
                checks[1]['details'][0]['data_sources'][0]['unknown_override']=True
            else:
                checks[1]['details'][0]['accepted']=[{'id':'OSV-expired','accepted_until':'2020-01-01'}]
            with self.subTest(kind=kind):
                self.assertEqual(finalize_report(source,source,checks,'e'*64,'f'*64,now=NOW)['status'],'fail')

    def test_whole_report_requires_unique_complete_checks_and_unchanged_clean_source(self):
        source, checks = self.report()
        self.assertEqual(finalize_report(source, source, checks, 'e' * 64, 'f' * 64, now=NOW)['status'], 'pass')
        for altered in (checks[:-1], checks + [checks[0]], checks + [{'name': 'unknown', 'status': 'pass'}]):
            with self.subTest(count=len(altered)):
                self.assertEqual(finalize_report(source, source, altered, 'e' * 64, 'f' * 64, now=NOW)['status'], 'fail')
        for key, value in (('head_sha', '9' * 40), ('candidate_clean', False), ('checker_clean', False), ('same_project', False)):
            after = {**source, key: value}
            self.assertEqual(finalize_report(source, after, checks, 'e' * 64, 'f' * 64, now=NOW)['status'], 'fail')

    def test_contradictory_bindings_gaps_and_unaccepted_findings_cannot_pass(self):
        source, baseline = self.report()
        cases = [('inventory_sha256', '0'*64), ('policy_sha256', '0'*64),
                 ('gaps', [{'code':'unresolved-dependency'}]),
                 ('findings', [{'id':'OSV-unaccepted'}]), ('data_sources', 'not-a-list'),
                 ('unknown_override', True)]
        for key,value in cases:
            with self.subTest(key=key):
                checks=copy.deepcopy(baseline)
                checks[1]['details'][0][key]=value
                self.assertEqual(finalize_report(source,source,checks,'e'*64,'f'*64,now=NOW)['status'],'fail')

    def test_missing_or_malformed_result_fields_are_structured_refusals(self):
        source, baseline=self.report()
        for key in ('inventory_sha256','policy_sha256','data_sources','findings','gaps'):
            checks=copy.deepcopy(baseline)
            checks[1]['details'][0].pop(key,None)
            with self.subTest(key=key):
                self.assertEqual(finalize_report(source,source,checks,'e'*64,'f'*64,now=NOW)['status'],'fail')

    def test_malformed_envelopes_and_source_identities_are_refused(self):
        source,baseline=self.report()
        altered={**source,'head_sha':'not-a-Git-identity'}
        self.assertEqual(finalize_report(altered,altered,baseline,'e'*64,'f'*64,now=NOW)['status'],'fail')
        self.assertEqual(finalize_report(None,None,baseline,'e'*64,'f'*64,now=NOW)['status'],'fail')
        checks=copy.deepcopy(baseline)
        checks[1]['name']=[]
        self.assertEqual(finalize_report(source,source,checks,'e'*64,'f'*64,now=NOW)['status'],'fail')
        checks=copy.deepcopy(baseline)
        checks[1]['details'][0]['schema_version']=True
        self.assertEqual(finalize_report(source,source,checks,'e'*64,'f'*64,now=NOW)['status'],'fail')

    def test_skip_needs_structural_na_proof_for_this_inventory(self):
        source, checks = self.report()
        checks[1]['status'] = 'skip'
        self.assertEqual(finalize_report(source, source, checks, 'e' * 64, 'f' * 64, now=NOW)['status'], 'fail')
        checks[1]['details'][0]['data_sources']=[]
        checks[1]['details'][0].update(outcome='not_applicable', applicability_evidence={
            'complete': True, 'inventory_sha256': 'e' * 64, 'reason': 'complete-inventory-no-objects'})
        self.assertEqual(finalize_report(source, source, checks, 'e' * 64, 'f' * 64, now=NOW)['status'], 'pass')
        checks[1]['details'][0]['applicability_evidence']['inventory_sha256'] = '0' * 64
        self.assertEqual(finalize_report(source, source, checks, 'e' * 64, 'f' * 64, now=NOW)['status'], 'fail')

    def test_expiry_is_the_earliest_source_or_forecast_and_never_future_renewed(self):
        source, checks = self.report()
        acquisition = {'retrieval_kind':'download', 'last_verified_sync_utc': NOW.isoformat(),
                       'source_published_at': (NOW - timedelta(hours=48)).isoformat()}
        checks[3]['details'][0]['data_sources'] = [{**self.source('epss'), 'acquisition': acquisition}]
        result = finalize_report(source, source, checks, 'e' * 64, 'f' * 64, now=NOW)
        self.assertEqual(result['valid_until_utc'], (NOW + timedelta(hours=24)).isoformat())
        stale = copy.deepcopy(checks)
        stale[3]['details'][0]['data_sources'][0]['acquisition']['source_published_at'] = (NOW - timedelta(hours=73)).isoformat()
        self.assertEqual(finalize_report(source, source, stale, 'e' * 64, 'f' * 64, now=NOW)['status'], 'fail')
        future = copy.deepcopy(checks)
        future[3]['details'][0]['data_sources'][0]['acquisition']['last_verified_sync_utc'] = (NOW + timedelta(seconds=1)).isoformat()
        self.assertEqual(finalize_report(source, source, future, 'e' * 64, 'f' * 64, now=NOW)['status'], 'fail')


if __name__ == '__main__':
    unittest.main()
