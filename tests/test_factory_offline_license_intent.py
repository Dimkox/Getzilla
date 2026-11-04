"""Factory output scope never supplies a delivered-archive license receipt."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from getzilla import expanded_security, security_licenses as licenses


ROOT = Path(__file__).resolve().parents[1]
PATHS = ('factory/uv.lock', 'factory/runtime/build_offline_release.py',
         'factory/runtime/runtime-wheels-linux-x86_64-cpython312.json', '.getzilla/config/license-policy.json')


class FactoryLicenseScopeTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        for name in PATHS:
            dest = self.root / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, dest)
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        subprocess.run(['git', '-C', str(self.root), 'remote', 'add', 'origin',
                        'https://github.com/Dimkox/Getzilla.git'], check=True)
        self.policy = licenses.load_policy(self.root)

    def test_actual_validated_profile_has_exact_intent_not_delivery(self):
        info = licenses.factory_offline_intent(self.root, self.policy)
        source = json.loads((self.root / PATHS[2]).read_bytes())
        self.assertEqual(info['components'], source['wheels'])
        self.assertEqual(len(info['components']), 20)
        self.assertEqual(source['lock_sha256'], hashlib.sha256((self.root / PATHS[0]).read_bytes()).hexdigest())
        names = {x['name'] for x in info['components']}
        self.assertFalse({'attrs','jsonschema','jsonschema-specifications','referencing','rpds-py','tzdata'} & names)
        self.assertEqual(info['code'], 'license-factory-archive-delivery-unverified')
        self.assertEqual(info['distribution'], 'redistributed')

    def test_each_changed_input_and_foreign_project_refuse_the_selected_profile(self):
        for name in PATHS[:3]:
            with self.subTest(name=name):
                path = self.root / name
                before = path.read_bytes()
                path.write_bytes(before + b' ')
                refusal = licenses.factory_offline_intent(self.root, self.policy)
                self.assertEqual(refusal['code'], 'license-factory-profile-changed')
                self.assertFalse(refusal['components'])
                path.write_bytes(before)
        subprocess.run(['git', '-C', str(self.root), 'remote', 'set-url', 'origin',
                        'https://github.com/customer/app.git'], check=True)
        self.assertEqual(licenses.factory_offline_intent(self.root, self.policy)['code'],
                         'license-factory-project-mismatch')

    def test_output_declaration_does_not_mutate_flat_catalog_or_acceptance(self):
        info = licenses.factory_offline_intent(self.root, self.policy)
        for outcome, status in [('pass','pass'), ('blocked','fail')]:
            with self.subTest(outcome=outcome):
                gaps = [{'code':'license-scope-unknown','manifest':'factory/uv.lock'}]
                findings = [{'status':'pass','manifest':'trust-ci/requirements-test.txt'}]
                check = {'status':status,'summary':'existing verdict','details':[
                    {'outcome':outcome,'gaps':gaps,'findings':findings}]}
                licenses.attach_factory_offline_intent(check, info)
                self.assertEqual(check['status'], status)
                self.assertEqual(check['summary'],'existing verdict')
                self.assertEqual(check['details'][0]['outcome'],outcome)
                self.assertEqual(check['details'][0]['gaps'],gaps)
                self.assertEqual(check['details'][0]['findings'],findings)
                self.assertEqual(check['details'][0]['factory_offline_use']['assurance'],'declared-output-scope-only')
                self.assertEqual(check['details'][0]['factory_offline_use']['final_archive_evidence'],'not_evaluated')

    def test_actual_incomplete_gate_reports_known_scope_and_remains_blocked(self):
        inv = {'complete': False, 'digest':'a'*64,'gaps':[{'code':'unresolved-image'}],
               'dependencies':[], 'images':[], 'tools':[], 'files':[], 'manifests':[], 'excluded_fixture_paths':[]}
        result = expanded_security.run_checks(self.root, inventory=inv)
        check = next(x for x in result if x['name']=='security-licenses')
        self.assertEqual(check['status'], 'fail')
        self.assertEqual(check['details'][0]['outcome'], 'blocked')
        gaps = check['details'][0]['gaps']
        self.assertIn({'code':'unresolved-image'}, gaps)
        output = check['details'][0]['factory_offline_use']
        self.assertEqual(output['code'],'license-factory-archive-delivery-unverified')
        self.assertEqual(output['assurance'],'declared-output-scope-only')
        self.assertEqual(len(output['components']),20)
