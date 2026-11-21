"""Upstream custody and showcase checks; these inputs are not consumer payload."""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import subprocess
import unittest

from factory.tests._showcase_custody import validate_showcase


class FactorySourceHistoryTests(unittest.TestCase):
    def test_release_archive_fixture_uses_current_project_license(self):
        root = Path(__file__).resolve().parents[1]
        self.assertEqual((root / 'factory/tests/fixtures/project-license.txt').read_bytes(),
                         (root / 'LICENSE').read_bytes())

    def test_predecessor_contract_migration_showcase_and_published_release_record_are_frozen(self):
        def aggregate(paths):
            digest = hashlib.sha256()
            values = tuple(sorted(paths, key=lambda item: item.as_posix()))
            for path in values:
                name = path.as_posix().encode()
                body = path.read_bytes()
                digest.update(len(name).to_bytes(4, "big"))
                digest.update(name)
                digest.update(len(body).to_bytes(8, "big"))
                digest.update(body)
            return len(values), digest.hexdigest()

        migrations = (
            path
            for path in Path("factory/src/getzilla_factory/resources").glob(
                "[0-9][0-9][0-9]_*.sql"
            )
            if int(path.name[:3]) <= 18
        )
        predecessor_contracts = (
            path
            for path in Path("factory/contracts").rglob("*")
            if path.is_file()
            and "landing-" not in path.name
            and path.name != "static-landing-spec.v1.schema.json"
            and path.name != "context-manifest.v1.schema.json"
            and path.name != "decision-record.v1.schema.json"
            and path.name != "result-envelope.v1.schema.json"
            and path.name != "result-envelope.v2.schema.json"
            and path.name != "result-channel-qualification.v1.schema.json"
            and path.name != "result-channel-qualification.v2.schema.json"
            and path.name != "native-result-handoff.v1.schema.json"
            and path.name != "factory-result-admission.v1.json"
            and path.name != "factory-execution.v3.json"
            and path.name != "bb-backend-profile.v1.schema.json"
            and path.name != "bb-lifecycle-observation.v1.schema.json"
            and path.name != "prediction-explanation.v1.schema.json"
            and path.name != "prediction-observation.v1.schema.json"
            and path != Path("factory/contracts/jsonschema/owner-autonomy.v1.schema.json")
            # Only the explicitly versioned successor is outside predecessor bytes.
            and path != Path("factory/contracts/jsonschema/earned-autonomy.v2.schema.json")
            and path != Path("factory/contracts/jsonschema/context-manifest.v2.schema.json")
            and path != Path("factory/contracts/jsonschema/paid-execution-authority.v1.schema.json")
            and path != Path("factory/contracts/openapi/factory-access-workflow.v1.json")
        )
        self.assertEqual(
            # Re-anchored after the Getzilla rename (decisions.md 2026-10-08): the 18 files are
            # byte-identical; only their package path changed (the old digest reproduces
            # with the pre-rename package directory in the paths).
            (18, "910d106f6f99ef09a154dc2cd7c9fd848faeadf0e53df535e6beb9997113b59f"),
            aggregate(migrations),
        )
        self.assertEqual(
            # Rename 73d97c5 changed only the display "title" of 14 of these contracts.
            (23, "d0c2604ae4e052724e8ba99ba203183926591d2fb719439e795a85d98b0e914a"),
            aggregate(predecessor_contracts),
        )
        # Historical six-file metadata stays pinned separately from reviewed
        # current lab tools. Only Git-tracked source participates; interpreter
        # caches and browser output can never become frozen source authority.
        manifest = json.loads(Path('side-projects/seo-landing-showcase.source.json').read_text(encoding='utf-8'))
        tracked = subprocess.check_output(['git', 'ls-files', '--', 'side-projects/seo-landing-showcase/'],
                                          text=True).splitlines()
        validate_showcase(Path.cwd(), manifest, tracked)
        # Historic binary custody is external to the source tree. Bind its
        # retained immutable record without claiming fresh verification of ZIP bytes.
        state = json.loads(Path('PROJECT_STATE.json').read_text(encoding='utf-8'))
        published = next(record for record in state['prior_published_releases'] if record['tag'] == 'v2.0.13')
        self.assertEqual(
            "3d5179f589c507143f4b93a98d2518e37e470e8566a62f77b31c35743ed8240c",
            published['artifact']['sha256'],
        )
        self.assertEqual(published['artifact']['binding'], 'immutable_release_tag')
        self.assertEqual(published['merge_commit'], '8599d45f4f28285381b05a53feb3059de92eb2a8')
        self.assertEqual(published['tree'], '03e122a30fb2dbb59907f4c4c28e17f93cbf0751')

    def test_declared_sqlite_policy_retains_history_mirror_and_sql_safety(self):
        from getzilla.architecture_fitness import _MigrationAnalysis, _MigrationPlan, _migration_roots
        from getzilla_factory.landing_sqlite.migrations import discover_migrations
        root = Path(__file__).resolve().parents[1]
        history = 'factory/sqlite'
        runtime = 'factory/src/getzilla_factory/landing_sqlite/migrations'
        system = json.loads((root / 'architecture/system.yaml').read_bytes())
        rules = json.loads((root / 'architecture/rules.yaml').read_bytes())
        policy = next(rule for rule in rules['migration_policies'] if rule['id'] == 'FIT-FACTORY-SQLITE-HISTORY')
        self.assertTrue(policy['immutable_history'])
        self.assertEqual(policy['path_prefixes'], [history])
        roots = _migration_roots(SimpleNamespace(system=system), (history,))
        self.assertEqual(set(roots), {history, runtime})
        self.assertEqual(_migration_roots(SimpleNamespace(system=system),
                         ('factory/src/getzilla_factory/resources',)), ('factory/src/getzilla_factory/resources',))
        migrations = discover_migrations()
        for item in migrations:
            with self.subTest(version=item.version):
                self.assertEqual((root / history / item.name).read_bytes(), (root / runtime / item.name).read_bytes())
        primary = tuple(SimpleNamespace(path=history + '/' + item.name, status='added') for item in migrations)
        paths = tuple(item.path for item in primary)
        copies = {item.path: (runtime + '/' + item.path.rsplit('/', 1)[-1],) for item in primary}
        blobs = {path: (root / path).read_bytes() for path in (*paths, *(p[0] for p in copies.values()))}
        plan = _MigrationPlan(policy, roots, primary, primary, paths, copies)
        analysis = _MigrationAnalysis()
        analysis.check(plan, blobs)
        self.assertEqual(analysis.issues, [])
        for label, candidate, data in (
            ('mirror drift', plan, blobs | {copies[paths[2]][0]: b'changed'}),
            ('history gap', plan._replace(head_paths=paths[:2] + paths[3:]), blobs),
            ('destructive SQL', plan, blobs | {paths[2]: b'DROP TABLE paid_accounts;'}),
        ):
            with self.subTest(case=label):
                rejected = _MigrationAnalysis()
                rejected.check(candidate, data)
                self.assertTrue(rejected.issues)
