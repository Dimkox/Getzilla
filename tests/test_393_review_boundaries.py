"""New owned corrective fixtures; no default producer, process or network."""
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

W = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(W / '.getzilla'))
from getzilla import architecture_fitness as fitness
from getzilla import expanded_security as expanded
from getzilla import public_security_context
from getzilla import security_cli as cli
from getzilla import security_corresponding_source  # noqa: F401 preload before the I/O guard
from getzilla import security_inventory as inventory
from getzilla import security_tools as tools
from getzilla import verification_journal

ACTIVE = False
OWNED = None


def audit(event, args):
    if not ACTIVE:
        return
    if event.startswith(('socket.', 'subprocess.', 'shutil.')) or event in {'os.system', 'os.posix_spawn'}:
        raise AssertionError('owned fixture denies processes/network')
    if event == 'open' or event.startswith('os.'):
        if (OWNED is None or not args or not isinstance(args[0], (str, bytes, os.PathLike))
                or not Path(os.fsdecode(args[0])).absolute().is_relative_to(OWNED)):
            raise AssertionError('owned fixture denies outside I/O')


sys.addaudithook(audit)


@contextlib.contextmanager
def guarded(root=None):
    global ACTIVE, OWNED
    ACTIVE, OWNED = True, root
    try:
        with verification_journal.bind_sink(None, None):
            yield
    finally:
        ACTIVE, OWNED = False, None


class ReviewBoundaries(unittest.TestCase):
    def test_forged_optional_metadata_never_masks_or_expands_refusal(self):
        for sidecar in ({'private_owned_canary': 'x' * 6000}, object(), {'active': [object()]}):
            error = fitness.ArchitectureError('queue adapter depth limit exceeded', code='limit')
            error.queue_refusal = sidecar
            try:
                with guarded():
                    text = fitness._queue_limit_text(error)
            except Exception:
                self.fail('optional metadata masked the original refusal')
            self.assertEqual(text, str(error))

    def test_genuine_capture_survives_mutation_of_public_sidecar(self):
        budget = fitness._QueueBudget('head')
        budget.enter('private-owned-demand', module='owned.entry')
        with guarded():
            error = budget.refusal('queue adapter depth limit exceeded', 'depth', 8, 9,
                                   site='cached', cached=('owned.leaf',))
            error.queue_refusal['active'] = ['private_owned_canary' * 400]
            text = fitness._queue_limit_text(error)
        self.assertLessEqual(len(text.encode()), 2048)
        self.assertNotIn('private_owned_canary', text)
        detail = json.loads(text.split('; ', 1)[1])
        self.assertEqual(detail['active'], ['owned.entry'])
        self.assertEqual(detail['cached'], ['owned.leaf'])

    def test_native_consumption_validates_full_envelope_and_current_authority(self):
        parent = W / '.getzilla/runtime/scratch/new393-review-fixtures'
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            root = Path(directory)
            source_bytes = b'FROM --platform=linux/amd64 ${OWNED_IMAGE}\n'
            (root / 'Dockerfile').write_bytes(source_bytes)
            source = dict(head_sha='a'*40, tree_sha='b'*40, checker_sha='c'*40, checker_tree_sha='d'*40,
                          candidate_clean=True, checker_clean=True, same_project=True)
            run = dict(provider='github-actions', repository='owned/fixture', run_id='71',
                       run_attempt='2', head_sha=source['head_sha'])
            env = dict(GETZILLA_SECURITY_IMAGE_SELECTION=str(root/'selection.json'),
                       GITHUB_REPOSITORY=run['repository'], GITHUB_RUN_ID=run['run_id'],
                       GITHUB_RUN_ATTEMPT=run['run_attempt'], GITHUB_SHA=source['head_sha'])
            now = datetime(2026, 11, 16, 16, tzinfo=timezone.utc)
            row = dict(path='Dockerfile', line=1, source_sha256=hashlib.sha256(source_bytes).hexdigest(),
                       expression='${OWNED_IMAGE}', reference='example.invalid/owned@sha256:'+'a'*64,
                       platform='linux/amd64')
            valid = dict(schema_version=1, source=source, run=run, created_at=now.isoformat(), uses=[row])

            def consume(selection, environment=env):
                with patch.object(expanded, 'read_image_selection', return_value=selection), \
                        patch.object(public_security_context, 'source_binding', return_value=source), \
                        patch.object(expanded.tempfile, 'TemporaryDirectory', return_value=contextlib.nullcontext(str(root/'authority'))), \
                        patch.object(inventory, '_tracked_files', return_value=['Dockerfile']), \
                        patch.object(expanded, '_clock', return_value=now), \
                        patch.object(tools, 'pinned_tool', side_effect=AssertionError('scanner forbidden')):
                    with guarded(root):
                        value = expanded.current_inventory(root, environ=environment)
                        self.assertEqual(tools.scan_images(value, environ={})['outcome'], 'blocked')
                        return value

            first = consume(valid)
            self.assertTrue(first['complete'])
            self.assertEqual(first.get('image_selection_sha256'), inventory.canonical_digest(valid))
            roots = {name: str(root/name) for name in ('database', 'artifacts', 'tools')}
            with guarded(root):
                profile = cli.input_profile(source, first, roots, run, 'e'*64, now=now, image_selection=valid)
            self.assertEqual(profile['inventory_sha256'], first['digest'])
            self.assertEqual(profile['image_selection_sha256'], first['image_selection_sha256'])
            changed = dict(valid, created_at=(now-timedelta(seconds=1)).isoformat())
            second = consume(changed)
            self.assertNotEqual(first['digest'], second['digest'], 'full declaration identity must bind inventory')
            negatives = [dict(valid, created_at=(now-timedelta(seconds=259201)).isoformat()),
                         dict(valid, created_at='malformed'), dict(valid, source={}), dict(valid, run={}),
                         dict(valid, run=dict(run, run_attempt='3')),
                         dict(valid, source=dict(source, checker_sha='f'*40))]
            for declaration in negatives:
                with self.subTest(declaration_kind=list(declaration)), self.assertRaises((ValueError, RuntimeError)):
                    consume(declaration)
                with guarded(root), self.assertRaises((ValueError, RuntimeError)):
                    cli.input_profile(source, first, roots, run, 'e'*64, now=now, image_selection=declaration)
            with self.assertRaises((ValueError, RuntimeError)):
                consume(copy.deepcopy(valid), {'GETZILLA_SECURITY_IMAGE_SELECTION': env['GETZILLA_SECURITY_IMAGE_SELECTION']})


if __name__ == '__main__':
    unittest.main(verbosity=2)
