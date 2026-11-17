"""Fresh owned source-role/closed-download controls; no project producer runs."""
from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml
from getzilla import security_inventory as inventory

_OWNED = ContextVar('parent_inventory_source_fixture', default=None)
ARCHIVE = 'engineering/changes/20260824-the-user-sent-a-message-while-you-were-working-u-3e6166/evidence/compose.host-socket.yaml'
PROVENANCE = 'engineering/changes/20260824-m0-2-sha-change-invalidation-on-draft-pr-5-beee95/evidence/analysis-architect.md'


def _deny_effects(event, args):
    root = _OWNED.get()
    if root is None:
        return
    if event in {'subprocess.Popen', 'os.system', 'os.fork', 'os.posix_spawn', 'ctypes.dlopen', 'ctypes.dlsym'} or event.startswith('socket.'):
        raise AssertionError('unmocked native/process/network effect denied')
    if event in {'open', 'os.listdir', 'os.scandir'}:
        path = args[0]
        if not isinstance(path, (str, bytes, os.PathLike)):
            raise AssertionError('unowned descriptor denied')
        selected = Path(os.fsdecode(path)).resolve()
        directory = event == 'open' and len(args) > 2 and isinstance(args[2], int) and args[2] & os.O_DIRECTORY
        if not selected.is_relative_to(root) and not (directory and root.is_relative_to(selected)):
            raise AssertionError('outside-fixture I/O denied')


sys.addaudithook(_deny_effects)


@contextmanager
def _owned(root):
    token = _OWNED.set(root.resolve())
    try:
        yield
    finally:
        _OWNED.reset(token)


class ParentInventorySourceJoinTests(unittest.TestCase):
    def test_exact_archival_copy_retains_source_coverage_and_active_neighbor(self):
        scratch = Path(__file__).resolve().parents[1] / '.getzilla/runtime/scratch'
        scratch.mkdir(parents=True, exist_ok=True)
        self.assertTrue(callable(yaml.parse))
        with tempfile.TemporaryDirectory(prefix='owned-parent-archive-', dir=scratch) as name:
            root = Path(name)
            archive = b'services:\n  old:\n    volumes: !owned-archive []\n'
            provenance = b'Owned inert provenance: this copy is documentation only.\n'
            neighbor = str(Path(ARCHIVE).with_name('compose.active.yaml'))
            bodies = {ARCHIVE: archive, PROVENANCE: provenance,
                      neighbor: ('services:\n  active:\n    image: owned/active@sha256:' + '2' * 64 + '\n').encode()}
            for path, raw in bodies.items():
                target = root / path
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                target.write_bytes(raw)
            row = dict(bytes=len(archive), sha256=hashlib.sha256(archive).hexdigest(),
                       provenance_path=PROVENANCE, provenance_bytes=len(provenance),
                       provenance_sha256=hashlib.sha256(provenance).hexdigest())

            def tracked(selected):
                self.assertEqual(selected, root)
                return sorted(bodies)

            with _owned(root), patch.object(inventory, '_tracked_files', side_effect=tracked), patch.object(
                    inventory, '_ARCHIVAL_DOCUMENTS', {ARCHIVE: row}, create=True), patch.object(
                    yaml.constructor.BaseConstructor, 'construct_object', side_effect=AssertionError('YAML constructor forbidden')):
                current = inventory.collect_inventory(root)
                self.assertTrue(current['complete'], current['gaps'])
                self.assertIn(ARCHIVE, current['files'])
                self.assertNotIn(ARCHIVE, [item['path'] for item in current['manifests']])
                self.assertEqual([image['manifest'] for image in current['images']], [neighbor])
                disclosure = current['excluded_archival_evidence'][0]
                self.assertEqual(disclosure['path'], ARCHIVE)
                self.assertEqual(disclosure['sha256'], row['sha256'])
                self.assertEqual(disclosure['bytes'], len(archive))
                self.assertEqual(disclosure['provenance']['sha256'], row['provenance_sha256'])
                for path in (ARCHIVE, PROVENANCE):
                    original = bodies[path]
                    (root / path).write_bytes(b'x' + original[1:])
                    refused = inventory.collect_inventory(root)
                    self.assertFalse(refused['complete'], path)
                    self.assertIn('archival-evidence-unverified', {gap['code'] for gap in refused['gaps']})
                    self.assertFalse(refused.get('excluded_archival_evidence'))
                    (root / path).write_bytes(original)
                (root / neighbor).write_bytes(archive)
                tagged = inventory.collect_inventory(root)
                self.assertFalse(tagged['complete'])
                self.assertIn('unsupported-yaml', {gap['code'] for gap in tagged['gaps']})

    def test_closed_checked_download_tail_requires_separate_use_step(self):
        scratch = Path(__file__).resolve().parents[1] / '.getzilla/runtime/scratch'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='owned-parent-download-', dir=scratch) as name:
            root = Path(name)
            pins = b'ARG OWNED_VERSION=1.2.3\nARG OWNED_DIGEST=' + b'3' * 64 + b'\n'
            source = b'owned workflow source bytes'
            command = ('set -euo pipefail\n'
                "version=$(sed -n 's/^ARG OWNED_VERSION=//p' owned/Dockerfile)\n"
                "digest=$(sed -n 's/^ARG OWNED_DIGEST=//p' owned/Dockerfile)\n"
                'mkdir -p "$RUNNER_TEMP/owned"\n'
                'curl -fsSL -o "$RUNNER_TEMP/owned/tool" "https://github.com/owned/tool/releases/download/v${version}/tool"\n'
                'echo "${digest}  $RUNNER_TEMP/owned/tool" | sha256sum -c -\n'
                'chmod 0755 "$RUNNER_TEMP/owned/tool"\n')

            def read_pin(path):
                self.assertEqual(path, 'owned/Dockerfile')
                return pins

            with _owned(root):
                declared, gaps = inventory.workflow_downloads(command, '.github/workflows/owned.yml', 1,
                    source, read_pin, platform='linux/amd64')
                self.assertEqual(gaps, [])
                self.assertEqual(declared[0]['artifact_sha256'], '3' * 64)
                self.assertEqual(declared[0]['source_sha256'], hashlib.sha256(source).hexdigest())
                for tail in ('export PATH="$RUNNER_TEMP/owned:$PATH"\n', 'printf owned-use\n'):
                    _, refused = inventory.workflow_downloads(command + tail, '.github/workflows/owned.yml', 1,
                        source, read_pin, platform='linux/amd64')
                    self.assertEqual([gap['code'] for gap in refused], ['unresolved-ci-tool'])
                self.assertNotIn('trusted', json.dumps(declared))
