"""Public synthetic OSV data exercises the native offline consumer, never online services."""
import copy
import json
import sys
import tempfile
import unittest
import subprocess
import os
from datetime import date, datetime, timezone
from unittest.mock import patch
from pathlib import Path

from tests import test_known_vulns as fixtures
sys.path.insert(0,str(fixtures.ROOT/'.getzilla'))
from getzilla import known_vulns as KV


def affected(events,*,kind='SEMVER',ecosystem='npm',versions=None):
    result = {'package':{'ecosystem':ecosystem,'name':'synthetic-package'},
              'ranges':[{'type':kind,'events':events}]}
    if versions is not None:
        result['versions'] = versions
    return result


class NativeOsvRangeTests(unittest.TestCase):
    def test_actual_cli_refuses_malformed_aliases_before_skipped_record_filters(self):
        for case in ('matched', 'withdrawn', 'unrelated', 'unaffected', 'accepted'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as database:
                fixtures._mirror(Path(database), 'PyPI', [fixtures.NativeAliasTests.record(case)])
                files = {'requirements.txt': 'jinja2==2.11.0\n'}
                if case == 'accepted':
                    files[KV.CONFIG_PATH] = json.dumps({'accept': [{'id': fixtures.JINJA['id'],
                        'reason': 'owned public fixture', 'expires': '2099-12-31'}]})
                context, root = fixtures._repo(files)
                with context:
                    (root/'.getzilla').mkdir(exist_ok=True)
                    result = subprocess.run(
                        [sys.executable, str(fixtures.ROOT/'scripts/getzilla_vulns.py'), '--json', '--db', database],
                        cwd=root, env={**os.environ, 'GETZILLA_OSV_DB': database, 'GETZILLA_OSV_ONLINE': '0'},
                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 2)
                self.assertIn('OSV aliases must be null or a list of valid identifiers', result.stderr)
                self.assertNotIn('CVE-2099-9999', result.stdout+result.stderr)

    def test_actual_cli_keeps_nullable_and_valid_alias_findings(self):
        for case, aliases in enumerate((None, [], ['CVE-2024-22195'])):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as database:
                fixtures._mirror(Path(database), 'PyPI', [fixtures.NativeAliasTests.record(aliases=aliases)])
                context, root = fixtures._repo({'requirements.txt': 'jinja2==2.11.0\n'})
                with context:
                    (root/'.getzilla').mkdir()
                    result = subprocess.run(
                        [sys.executable, str(fixtures.ROOT/'scripts/getzilla_vulns.py'), '--json', '--db', database],
                        cwd=root, env={**os.environ, 'GETZILLA_OSV_DB': database, 'GETZILLA_OSV_ONLINE': '0'},
                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 1, result.stderr)
                [finding] = json.loads(result.stdout)['findings']
                self.assertEqual(finding['aliases'], aliases or [])

    @staticmethod
    def _literal_manifest(ecosystem, version):
        if ecosystem == 'Maven':
            return 'public.synthetic:literal', {'gradle.lockfile':
                f'public.synthetic:literal:{version}=testRuntimeClasspath\n'}
        if ecosystem == 'npm':
            return 'synthetic-package', {'package-lock.json': json.dumps({
                'lockfileVersion': 3, 'packages': {
                    'node_modules/synthetic-package': {'version': version}}})}
        return 'example.invalid/literal', {'go.mod':
            f'module example.invalid/fixture\nrequire example.invalid/literal v{version}\n'}

    def test_complete_non_pypi_literal_lists_need_no_ordering_for_misses(self):
        for ecosystem, listed, absent in [('Maven', 'vendor-release.a', 'vendor-release.b'),
                                          ('npm', '1.0.0+build.a', '1.0.0+build.b'),
                                          ('Go', '1.0.0+build.a', '1.0.0+build.b')]:
            with self.subTest(ecosystem=ecosystem):
                scope = {'package': {'ecosystem': ecosystem}, 'versions': [listed]}
                self.assertTrue(KV._in_ranges(listed, scope))
                try:
                    missing = KV._in_ranges(absent, scope)
                except KV.VulnerabilityError:
                    self.fail('complete literal-list miss was refused')
                self.assertFalse(missing)
        with self.assertRaises(KV.VulnerabilityError):
            KV._in_ranges('vendor-release.b', {'package': {'ecosystem': 'Maven'}})

    def test_actual_native_non_pypi_literal_hit_and_miss(self):
        for ecosystem, listed, absent in [('Maven', 'vendor-release.a', 'vendor-release.b'),
                                          ('npm', '1.0.0+build.a', '1.0.0+build.b'),
                                          ('Go', '1.0.0+build.a', '1.0.0+build.b')]:
            with tempfile.TemporaryDirectory(dir=fixtures.ROOT/'.getzilla/runtime') as directory:
                name, _ = self._literal_manifest(ecosystem, listed)
                record = {'id': 'OSV-SYNTHETIC-LITERAL', 'aliases': [], 'affected': [
                    {'package': {'ecosystem': ecosystem, 'name': name}, 'versions': [listed]}]}
                fixtures._mirror(Path(directory), ecosystem, [record])
                for version, expected in [(listed, True), (absent, False)]:
                    with self.subTest(ecosystem=ecosystem, version=version):
                        _, files = self._literal_manifest(ecosystem, version)
                        context, root = fixtures._repo(files)
                        with context:
                            try:
                                report = KV.scan(root, environ={'GETZILLA_OSV_DB': directory})
                            except KV.VulnerabilityError:
                                self.fail('native complete literal-list miss was refused')
                        self.assertEqual(report['status'], 'fail' if expected else 'pass')
                        self.assertEqual([row['id'] for row in report['findings']],
                                         ['OSV-SYNTHETIC-LITERAL'] if expected else [])

    def test_actual_cli_non_pypi_literal_hit_and_miss(self):
        for ecosystem, listed, absent in [('Maven', 'vendor-release.a', 'vendor-release.b'),
                                          ('npm', '1.0.0+build.a', '1.0.0+build.b'),
                                          ('Go', '1.0.0+build.a', '1.0.0+build.b')]:
            with tempfile.TemporaryDirectory(dir=fixtures.ROOT/'.getzilla/runtime') as directory:
                name, _ = self._literal_manifest(ecosystem, listed)
                record = {'id': 'OSV-SYNTHETIC-LITERAL', 'aliases': [], 'affected': [
                    {'package': {'ecosystem': ecosystem, 'name': name}, 'versions': [listed]}]}
                fixtures._mirror(Path(directory), ecosystem, [record])
                for version, expected in [(listed, True), (absent, False)]:
                    with self.subTest(ecosystem=ecosystem, version=version):
                        _, files = self._literal_manifest(ecosystem, version)
                        context, root = fixtures._repo(files)
                        with context:
                            (root/'.getzilla').mkdir()
                            result = subprocess.run(
                                [sys.executable, str(fixtures.ROOT/'scripts/getzilla_vulns.py'),
                                 '--json', '--db', directory], cwd=root,
                                env={**os.environ, 'GETZILLA_OSV_ONLINE': '0'},
                                capture_output=True, text=True, timeout=10)
                        self.assertEqual(result.returncode, 1 if expected else 0, result.stderr)
                        report = json.loads(result.stdout)
                        self.assertEqual(report['status'], 'fail' if expected else 'pass')
                        self.assertEqual([row['id'] for row in report['findings']],
                                         ['OSV-SYNTHETIC-LITERAL'] if expected else [])

    @staticmethod
    def _enumeration_record():
        return {'id': 'OSV-SYNTHETIC-ENUMERATION', 'aliases': [], 'affected': [
            affected([{'introduced': '2.0.0'}, {'fixed': '3.0.0'}],
                     versions=['1.0.0+build.a'])]}

    def test_native_scan_keeps_semver_enumeration_literal_and_range_precedence_distinct(self):
        scope = affected([{'introduced': '1.0.0+build.a'}, {'fixed': '2.0.0'}])
        self.assertTrue(KV._in_ranges('1.0.0+build.a', scope))
        self.assertTrue(KV._in_ranges('1.0.0+build.b', scope))
        cases = [('1.0.0+build.a', True), ('1.0.0+build.b', False),
                 ('2.5.0', True), ('3.0.0', False)]
        with tempfile.TemporaryDirectory(dir=fixtures.ROOT/'.getzilla/runtime') as directory:
            fixtures._mirror(Path(directory), 'npm', [self._enumeration_record()])
            for version, expected in cases:
                with self.subTest(version=version):
                    lock = {'lockfileVersion': 3, 'packages': {
                        'node_modules/synthetic-package': {'version': version}}}
                    context, root = fixtures._repo({'package-lock.json': json.dumps(lock)})
                    with context:
                        report = KV.scan(root, environ={'GETZILLA_OSV_DB': directory})
                    self.assertEqual(report['status'], 'fail' if expected else 'pass')
                    self.assertEqual([row['id'] for row in report['findings']],
                                     ['OSV-SYNTHETIC-ENUMERATION'] if expected else [])
        literal = {'package': {'ecosystem': 'Maven'}, 'versions': ['vendor-release.a']}
        self.assertTrue(KV._in_ranges('vendor-release.a', literal))
        self.assertFalse(KV._in_ranges('vendor-release.b', literal))

    def test_actual_cli_keeps_semver_enumeration_literal_and_range_boundaries(self):
        cases = [('1.0.0+build.a', True), ('1.0.0+build.b', False),
                 ('2.5.0', True), ('3.0.0', False)]
        with tempfile.TemporaryDirectory(dir=fixtures.ROOT/'.getzilla/runtime') as directory:
            fixtures._mirror(Path(directory), 'npm', [self._enumeration_record()])
            for version, expected in cases:
                with self.subTest(version=version):
                    lock = {'lockfileVersion': 3, 'packages': {
                        'node_modules/synthetic-package': {'version': version}}}
                    context, root = fixtures._repo({'package-lock.json': json.dumps(lock)})
                    with context:
                        (root/'.getzilla').mkdir()
                        result = subprocess.run(
                            [sys.executable, str(fixtures.ROOT/'scripts/getzilla_vulns.py'),
                             '--json', '--db', directory], cwd=root,
                            env={**os.environ, 'GETZILLA_OSV_ONLINE': '0'},
                            capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 1 if expected else 0, result.stderr)
                    report = json.loads(result.stdout)
                    self.assertEqual(report['status'], 'fail' if expected else 'pass')
                    self.assertEqual([row['id'] for row in report['findings']],
                                     ['OSV-SYNTHETIC-ENUMERATION'] if expected else [])

    def test_exact_enumeration_and_dated_exception_do_not_hide_invalid_coverage(self):
        version = '1.0.0+build.a'
        for coverage in ([{'type': 'GIT', 'events': [{'introduced': '0'}]}], 'malformed'):
            with self.subTest(coverage_type=type(coverage).__name__):
                record = self._enumeration_record()
                record['affected'][0]['ranges'] = coverage
                lock = {'lockfileVersion': 3, 'packages': {
                    'node_modules/synthetic-package': {'version': version}}}
                context, root = fixtures._repo({'package-lock.json': json.dumps(lock)})
                with context, tempfile.TemporaryDirectory(dir=fixtures.ROOT/'.getzilla/runtime') as directory:
                    fixtures._mirror(Path(directory), 'npm', [record])
                    config = root/KV.CONFIG_PATH
                    config.parent.mkdir(parents=True)
                    config.write_text(json.dumps({'accept': [{
                        'id': record['id'], 'reason': 'Synthetic dated fixture only',
                        'expires': '2026-12-31'}]}))
                    with self.assertRaises(KV.VulnerabilityError):
                        KV.scan(root, environ={'GETZILLA_OSV_DB': directory},
                                today=date(2026, 11, 6))
                    result = subprocess.run(
                        [sys.executable, str(fixtures.ROOT/'scripts/getzilla_vulns.py'),
                         '--json', '--db', directory], cwd=root,
                        env={**os.environ, 'GETZILLA_OSV_ONLINE': '0'},
                        capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, '')

    def test_pypi_c_is_rc_without_rewriting_local_labels_or_other_phases(self):
        def qualified(version):
            try:
                return KV._pypi_key(version)
            except KV.VulnerabilityError:
                self.fail('valid qualified PyPI c/rc spelling was refused')
        for prefix,suffix in [('0.6','1'),('1!1.2.0','02.post3.dev4+local.c1')]:
            with self.subTest(prefix=prefix,suffix=suffix):
                self.assertEqual(qualified(prefix+'c'+suffix),qualified(prefix+'rc'+suffix))
                self.assertEqual(qualified(prefix+'C'+suffix),qualified(prefix+'RC'+suffix))
        self.assertLess(qualified('0.6b1'),qualified('0.6c1'))
        self.assertLess(qualified('0.6c1'),qualified('0.6'))
        self.assertNotEqual(qualified('0.6c1+local.c1'),qualified('0.6rc1+local.rc1'))

    def test_pypi_c_alias_keeps_native_range_boundaries_and_enumerated_versions(self):
        fixed = affected([{'introduced':'0'},{'fixed':'0.6c1'}],kind='ECOSYSTEM',ecosystem='PyPI')
        self.assertTrue(KV._in_ranges('0.6b2',fixed,ecosystem='PyPI'))
        self.assertFalse(KV._in_ranges('0.6rc1',fixed,ecosystem='PyPI'))
        inclusive = affected([{'introduced':'0.6c1'},{'last_affected':'0.6c2'}],kind='ECOSYSTEM',ecosystem='PyPI')
        self.assertTrue(KV._in_ranges('0.6rc1',inclusive,ecosystem='PyPI'))
        self.assertTrue(KV._in_ranges('0.6rc2',inclusive,ecosystem='PyPI'))
        self.assertFalse(KV._in_ranges('0.6rc3',inclusive,ecosystem='PyPI'))
        enumerated = {'versions':['0.6c1']}
        self.assertTrue(KV._in_ranges('0.6rc1',enumerated,ecosystem='PyPI'))
        for unsupported in ('0.6q1','0.6cc1','prefix0.6c1','0.6c1extra'):
            with self.subTest(unsupported=unsupported),self.assertRaises(KV.VulnerabilityError):
                KV._in_ranges(unsupported,fixed,ecosystem='PyPI')

    def test_actual_offline_pypi_c_advisory_retains_clean_and_finding_controls(self):
        record = {'id':'OSV-SYNTHETIC-PYPI-C','affected':[
            affected([{'introduced':'0'},{'fixed':'0.6c1'}],kind='ECOSYSTEM',ecosystem='PyPI')]}
        with tempfile.TemporaryDirectory(dir=fixtures.ROOT/'.getzilla/runtime') as directory:
            database = Path(directory)
            fixtures._mirror(database,'PyPI',[record])
            clean = KV.query_offline([KV.Dependency('PyPI','synthetic-package','84.1.0','requirements.txt')],database)
            findings = KV.query_offline([KV.Dependency('PyPI','synthetic-package','0.6b1','requirements.txt')],database)
        self.assertEqual(clean,[])
        self.assertEqual([finding.vuln_id for finding in findings],['OSV-SYNTHETIC-PYPI-C'])

    def test_osv_limit_containing_star_retains_infinity_semantics(self):
        scope = affected([{'introduced':'0'},{'limit':'any*infinity'}])
        self.assertTrue(KV._in_ranges('999.0.0',scope))

    def test_actual_native_cli_still_loads_after_comparator_repair(self):
        env = dict(os.environ)
        result = subprocess.run([sys.executable,str(fixtures.ROOT/'scripts/getzilla_vulns.py'),'--help'],
                                env=env,cwd=fixtures.ROOT,capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('Check pinned dependencies',result.stdout)

    def test_actual_native_cli_keeps_maintenance_line_fixes_instead_of_a_global_maximum(self):
        root_context,root = fixtures._repo({'requirements.txt':'synthetic-package==1.0rc1\n'})
        (root/'.getzilla').mkdir()  # Bind the CLI to this project inside the canonical fixture parent.
        with root_context,tempfile.TemporaryDirectory(dir=fixtures.ROOT/'.getzilla/runtime') as directory:
            database = Path(directory)
            records = [{'id':identifier,'affected':[affected([{'introduced':'0'},{'fixed':fixed}],
                        kind='ECOSYSTEM',ecosystem='PyPI')]} for identifier,fixed in
                       [('OSV-SYNTHETIC-LINE1','1.0'),('OSV-SYNTHETIC-LINE2','2.0')]]
            fixtures._mirror(database,'PyPI',records)
            env = {**os.environ,'GETZILLA_OSV_ONLINE':'0','GITHUB_ACTIONS':'true'}
            result = subprocess.run([sys.executable,str(fixtures.ROOT/'scripts/getzilla_vulns.py'),
                                     '--db',str(database)],cwd=root,env=env,capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,1,result.stderr)
        self.assertIn('OSV-SYNTHETIC-LINE1: fixed in 1.0',result.stdout)
        self.assertIn('OSV-SYNTHETIC-LINE2: fixed in 2.0',result.stdout)
        self.assertNotIn('upgrade to >=',result.stdout)

    def test_actual_native_offline_consumer_finds_prerelease_before_fixed_final(self):
        record = {'id':'OSV-SYNTHETIC-313','aliases':[],
                  'affected':[affected([{'introduced':'0'},{'fixed':'1.0.0'}])]}
        with tempfile.TemporaryDirectory(dir=fixtures.ROOT/'.getzilla/runtime') as directory:
            database = Path(directory)
            fixtures._mirror(database,'npm',[record])
            findings = KV.query_offline([KV.Dependency('npm','synthetic-package','1.0.0-rc.1','package-lock.json')],database)
        self.assertEqual([finding.vuln_id for finding in findings],['OSV-SYNTHETIC-313'])

    def test_semver_prerelease_numeric_alphanumeric_and_build_precedence(self):
        ordered = ['1.0.0-alpha','1.0.0-alpha.1','1.0.0-alpha.beta','1.0.0-beta',
                   '1.0.0-beta.2','1.0.0-beta.11','1.0.0-rc.1','1.0.0']
        for lower,upper in zip(ordered,ordered[1:]):
            with self.subTest(lower=lower,upper=upper):
                scope = affected([{'introduced':'0'},{'fixed':upper}])
                self.assertTrue(KV._in_ranges(lower,scope))
                self.assertFalse(KV._in_ranges(upper,scope))
        scope = affected([{'introduced':'1.0.0+build.9'},{'fixed':'2.0.0'}])
        self.assertTrue(KV._in_ranges('1.0.0+other.2',scope))

    def test_introduced_fixed_last_affected_disjoint_and_limit_boundaries(self):
        disjoint = affected([{'introduced':'1.0.0'},{'fixed':'1.2.0'},
                             {'introduced':'2.0.0'},{'fixed':'2.2.0'}])
        for version,expected in [('0.9.9',False),('1.0.0',True),('1.2.0',False),
                                 ('1.9.0',False),('2.0.0',True),('2.2.0',False)]:
            self.assertEqual(KV._in_ranges(version,disjoint),expected,version)
        inclusive = affected([{'introduced':'0'},{'last_affected':'1.0.0'}])
        self.assertTrue(KV._in_ranges('1.0.0',inclusive))
        self.assertFalse(KV._in_ranges('1.0.1',inclusive))
        limited = affected([{'introduced':'0'},{'limit':'2.0.0'}])
        self.assertTrue(KV._in_ranges('1.9.9',limited))
        self.assertFalse(KV._in_ranges('2.0.0',limited))
        self.assertTrue(KV._in_ranges('9.0.0',affected([{'introduced':'0'},{'limit':'*'}])))
        multiple = affected([{'introduced':'0'},{'limit':'2.0.0'},{'limit':'3.0.0'}])
        self.assertTrue(KV._in_ranges('2.5.0',multiple))
        self.assertFalse(KV._in_ranges('3.0.0',multiple))

    def test_unsupported_or_ambiguous_ranges_never_return_clean(self):
        cases = [
            affected([{'introduced':'0'}],kind='GIT'),
            affected([{'introduced':'0'},{'fixed':'2.0'}],ecosystem='Maven',kind='ECOSYSTEM'),
            affected([{'fixed':'1.0.0'},{'introduced':'0'}]),
            affected([{'introduced':'2.0.0'},{'fixed':'1.0.0'}]),
            affected([{'introduced':'1.0.0'},{'fixed':'1.0.0'}]),
            affected([{'introduced':'0'},{'fixed':'1.0.0','last_affected':'1.0.0'}]),
            affected([{'introduced':'0'},{'fixed':'1.0.0'},{'last_affected':'2.0.0'}]),
            affected([{'introduced':'0'},{'unsupported':'1.0.0'}]),
            affected([{'introduced':'0'},{'fixed':'1.0.0-01'}]),
        ]
        for scope in cases:
            with self.subTest(scope=scope),self.assertRaises(KV.VulnerabilityError):
                KV._in_ranges('3.0.0',scope)

    def test_qualified_pypi_ordering_and_exact_string_versions_are_preserved(self):
        for version,fixed in [('1.0rc1','1.0'),('1.0.dev2','1.0a1'),
                              ('1.0','1.0.post1'),('1.9','1!1.0')]:
            with self.subTest(version=version,fixed=fixed):
                scope = affected([{'introduced':'0'},{'fixed':fixed}],kind='ECOSYSTEM',ecosystem='PyPI')
                self.assertTrue(KV._in_ranges(version,scope))
                self.assertFalse(KV._in_ranges(fixed,scope))
        scope = affected([{'introduced':'0'},{'fixed':'1.0'}],kind='ECOSYSTEM',ecosystem='PyPI')
        self.assertFalse(KV._in_ranges('1.0.0',scope))
        self.assertTrue(KV._in_ranges('vendor-release',{'package':{'ecosystem':'Maven'},'versions':['vendor-release']}))

    def test_missing_range_coverage_cannot_hide_behind_an_exact_match(self):
        scope = affected([{'introduced':'0'}],kind='GIT',versions=['3.0.0'])
        with self.assertRaises(KV.VulnerabilityError):
            KV._in_ranges('3.0.0',scope)
        malformed = copy.deepcopy(scope)
        malformed['ranges'] = 'unsupported'
        with self.assertRaises(KV.VulnerabilityError):
            KV._in_ranges('3.0.0',malformed)

    def test_native_gate_does_not_hide_unsupported_data_behind_dated_exceptions(self):
        from getzilla import verification
        root_context,root = fixtures._repo({'requirements.txt':'synthetic-package==3.0.0\n'})
        with root_context,tempfile.TemporaryDirectory(dir=fixtures.ROOT/'.getzilla/runtime') as directory:
            database = Path(directory)
            records = [{'id':identifier,'affected':[scope]} for identifier,scope in [
                ('OSV-SYNTHETIC-KNOWN',affected([{'introduced':'0'},{'fixed':'4.0.0'}],
                                             kind='ECOSYSTEM',ecosystem='PyPI')),
                ('OSV-SYNTHETIC-UNKNOWN',affected([{'introduced':'0'}],kind='GIT',ecosystem='PyPI'))]]
            fixtures._mirror(database,'PyPI',records)
            path = root/KV.CONFIG_PATH
            path.parent.mkdir(parents=True,exist_ok=True)
            import json
            path.write_text(json.dumps({'accept':[{'id':record['id'],'reason':'Synthetic dated fixture',
                                                   'expires':'2026-12-31'} for record in records]}))
            def actual_scan(target):
                return KV.scan(target,environ={'GETZILLA_OSV_DB':str(database)},today=date(2026,11,5))
            with self.assertRaises(KV.VulnerabilityError):
                actual_scan(root)
            from getzilla.expanded_security import known_vulnerability_check
            def native_producer(target):
                return known_vulnerability_check(target, environ={'GETZILLA_OSV_DB': str(database)},
                                                  now=datetime(2026,11,5,tzinfo=timezone.utc))
            with patch.object(verification,'known_vulnerability_check',side_effect=native_producer):
                result = verification._known_vulnerabilities(root)
            self.assertEqual(result.status,'fail')
            structured = [row for row in result.details if row.get('kind') == 'security-result']
            self.assertEqual(len(structured),1)
            self.assertEqual(structured[0]['outcome'],'blocked')
            self.assertEqual(structured[0]['accepted'],[])
