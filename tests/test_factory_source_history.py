"""Upstream custody and showcase checks; these inputs are not consumer payload."""
import hashlib
import json
from pathlib import Path
import unittest


class FactorySourceHistoryTests(unittest.TestCase):
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
        )
        showcase = (
            path for path in Path("side-projects/seo-landing-showcase").rglob("*") if path.is_file()
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
        self.assertEqual(
            # Rename 73d97c5 (footer text) and e07cfbe (cold Chrome start retries).
            (6, "b59b074fa907aeb63991a23ff072a04d4fbe3fd4bab14263447898e02994162c"),
            aggregate(showcase),
        )
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
