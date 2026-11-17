"""Retained #393 image contract regressions, source-reused from ba392782.

Not author NEW-control execution evidence. No analyzer/depth test imported.
"""
import ast
import contextlib
import hashlib
import json
import os
import tempfile
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import yaml

W = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(W / '.getzilla'))
from getzilla import security_inventory as inventory
from getzilla import security_cli as cli
from getzilla import security_tools as tools
from getzilla import expanded_security as expanded

ACTIVE = False
OWNED_ROOT = None


def guard(event, args):
    if not ACTIVE:
        return
    if event.startswith(('socket.', 'subprocess.', 'shutil.')) or event in {'os.system', 'os.posix_spawn'}:
        raise AssertionError('owned fixture forbids process/network')
    if event == 'open' or event.startswith('os.'):
        if OWNED_ROOT is None or not args or not isinstance(args[0], (str, bytes, os.PathLike)):
            raise AssertionError('pure fixture forbids filesystem')
        if not Path(os.fsdecode(args[0])).absolute().is_relative_to(OWNED_ROOT):
            raise AssertionError('Root/outside file read forbidden')


sys.addaudithook(guard)


class Reused393ImageContracts(unittest.TestCase):
    def owned(self, function):
        global ACTIVE
        ACTIVE = True
        try:
            return function()
        finally:
            ACTIVE = False


    def test_image_selection_binds_current_use_and_keeps_literal_platform(self):
        select = getattr(inventory, 'selected_image_use', None)
        self.assertTrue(callable(select), 'missing explicit current source-use selector')
        source = b'FROM --platform=linux/amd64 ${OWNED_IMAGE}\n'
        ast.parse('OWNED = 1\n')  # new inert source, not a Root analysis
        row = dict(path='Dockerfile', line=1, source_sha256=hashlib.sha256(source).hexdigest(),
                   expression='${OWNED_IMAGE}', reference='example.invalid/owned@sha256:'+'a'*64,
                   platform='linux/amd64')
        kwargs = dict(path='Dockerfile', line=1, source_sha256=row['source_sha256'],
                      expression='${OWNED_IMAGE}', platform='linux/amd64')
        result = self.owned(lambda: select([row], **kwargs))
        self.assertEqual(result, row)
        for field, value in [('source_sha256', 'b'*64), ('line', 2), ('platform', 'linux/arm64')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.owned(lambda: select([row], **{**kwargs, field:value}))
        with self.assertRaises(ValueError):
            self.owned(lambda: select([row, row], **kwargs))
        self.assertEqual(json.loads(json.dumps(row)), row)


    def test_new_owned_compose_profile_and_early_unqualified_transport_refusal(self):
        self.assertTrue(callable(yaml.safe_load))  # preload parser before the I/O boundary
        parent = W / '.getzilla/runtime/scratch/new393-fixtures'
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as name:
            root = Path(name)
            source = ('services:\n  api:\n    image: ${OWNED_API_IMAGE}\n    platform: linux/amd64\n'
                      '    environment:\n      TRUST_CI_RUNNER_IMAGE: ${OWNED_RUNNER_IMAGE}\n')
            (root/'compose.yaml').write_text(source, encoding='utf-8')
            digest = hashlib.sha256(source.encode()).hexdigest()
            rows = [dict(path='compose.yaml', line=line, source_sha256=digest, expression=expression,
                         reference='example.invalid/' + label + '@sha256:' + char*64, platform='linux/amd64')
                    for line,expression,label,char in [(3,'${OWNED_API_IMAGE}','api','a'),
                                                       (6,'${OWNED_RUNNER_IMAGE}','runner','b')]]
            source_binding = dict(head_sha='a'*40, tree_sha='b'*40, checker_sha='c'*40, checker_tree_sha='d'*40,
                                  candidate_clean=True, checker_clean=True, same_project=True)
            run = dict(provider='github-actions', repository='owned/fixture', run_id='17', run_attempt='1', head_sha='a'*40)
            now = datetime(2026,11,16,tzinfo=timezone.utc)
            selection = dict(schema_version=1, source=source_binding, run=run, created_at=now.isoformat(), uses=rows)
            path = root/'selection.json'
            path.write_text(json.dumps(selection),encoding='utf-8')

            def read_owned(value):
                self.assertEqual(value, path)
                return json.loads(path.read_bytes())

            global OWNED_ROOT
            OWNED_ROOT = root
            try:
                with patch.object(inventory,'_tracked_files',return_value=['compose.yaml']), \
                        patch.object(cli,'read_image_selection',side_effect=read_owned), \
                        patch.object(cli,'source_binding',return_value=source_binding), \
                        patch.object(cli,'_policy_digest',return_value='e'*64), \
                        patch.object(cli.tempfile,'TemporaryDirectory',
                                     return_value=contextlib.nullcontext(str(root/'owned-scratch'))), \
                        patch.object(cli,'refresh_feeds',side_effect=AssertionError('acquisition forbidden')), \
                        patch.object(cli,'provision_tools',side_effect=AssertionError('process forbidden')):
                    parsed = self.owned(lambda: inventory.collect_inventory(root,image_bindings=rows))
                    self.assertTrue(parsed['complete'],parsed['gaps'])
                    self.assertEqual(len(parsed['images']),2,'runner input must remain required')
                    roots = [root/name for name in ('database','artifacts','tools')]
                    if os.name != 'posix':
                        with self.assertRaisesRegex(cli.SecurityDataError, 'qualified POSIX reader'):
                            self.owned(lambda: cli.prepare_inputs(root,*roots,write_profile=True,run=run,
                                                                  image_selection=path,now=now))
                        return  # actual unsupported-platform refusal, not scan qualification
                    profile = self.owned(lambda: cli.prepare_inputs(root,*roots,write_profile=True,run=run,
                                                                  image_selection=path,now=now))
                    self.assertEqual(profile.get('image_selection_sha256'),inventory.canonical_digest(selection))
                    with self.assertRaisesRegex(cli.SecurityDataError,'acquisition unavailable'):
                        self.owned(lambda: cli.prepare_inputs(root,*roots,profile=profile,run=run,refresh=True,
                                                              provision=True,image_selection=path,now=now))
                    changed = dict(selection,run=dict(run,run_attempt='2'))
                    path.write_text(json.dumps(changed),encoding='utf-8')
                    with self.assertRaises(cli.SecurityDataError):
                        self.owned(lambda: cli.prepare_inputs(root,*roots,profile=profile,run=run,
                                                              image_selection=path,now=now))
            finally:
                OWNED_ROOT = None


    def test_evaluation_dispatch_forwards_explicit_selection(self):
        args = types.SimpleNamespace(refresh=False,provision_tools=False,input_profile=Path('/owned/profile'),
                                     image_selection=Path('/owned/selection'))
        options = self.owned(lambda: cli._evaluation_kwargs(args,{'kind':'owned'}, {'kind':'owned-run'}))
        self.assertEqual(options.get('image_selection'), args.image_selection)


    def test_selection_age_is_checked_at_consumption_not_only_profile_creation(self):
        now = datetime(2026,11,16,tzinfo=timezone.utc)
        source = dict(head_sha='a'*40,tree_sha='b'*40,checker_sha='c'*40,checker_tree_sha='d'*40,
                      candidate_clean=True,checker_clean=True,same_project=True)
        run = dict(provider='github-actions',repository='owned/fixture',run_id='17',run_attempt='1',head_sha='a'*40)
        reference = 'example.invalid/owned@sha256:'+'a'*64
        value = dict(complete=True,gaps=[],digest='e'*64,
                     images=[dict(reference=reference,platform='linux/amd64')],dependencies=[],tools=[])
        roots = dict(database='/owned/database',artifacts='/owned/artifacts',tools='/owned/tools')
        selection = dict(schema_version=1,source=source,run=run,
                         uses=[dict(path='compose.yaml',line=1,source_sha256='e'*64,expression='${OWNED_IMAGE}',
                                    reference=reference,platform='linux/amd64')],
                         created_at=(now-timedelta(hours=71)).isoformat())
        profile = self.owned(lambda: cli.input_profile(source,value,roots,run,'f'*64,now=now,image_selection=selection))
        with self.assertRaises(cli.SecurityDataError):
            self.owned(lambda: cli.validate_input_profile(profile,source,value,roots,run,'f'*64,
                now=now+timedelta(hours=2),image_selection=selection))


    def test_unqualified_selection_cannot_start_scanner_or_get_credit(self):
        value = dict(images=[dict(reference='example.invalid/owned@sha256:'+'a'*64,
                                  platform='linux/amd64',selection_assurance='declaration-only-unverified')])
        with patch.object(tools,'tools_directory',return_value=Path('/owned/tools')), \
                patch.object(tools,'pinned_tool',return_value=Path('/owned/UNEXECUTED')) as pin, \
                patch.object(tools,'trivy_database_source',side_effect=cli.SecurityDataError('owned unavailable DB')):
            result = self.owned(lambda: tools.scan_images(value,environ={}))
        self.assertEqual(result['outcome'],'blocked')
        self.assertEqual(result['gaps'][0]['code'],'unqualified-image-selection')
        self.assertEqual(pin.call_count,0)


    def test_native_consumers_forward_choices_before_any_producer(self):
        uses = [dict(path='compose.yaml',line=1,source_sha256='a'*64,expression='${OWNED_IMAGE}',
                     reference='example.invalid/owned@sha256:'+'b'*64,platform='linux/amd64')]
        env = dict(GETZILLA_SECURITY_IMAGE_SELECTION='/owned/selection.json')
        source = dict(head_sha='a'*40, tree_sha='b'*40, checker_sha='c'*40, checker_tree_sha='d'*40,
                      candidate_clean=True, checker_clean=True, same_project=True)
        run = dict(provider='github-actions', repository='owned/fixture', run_id='17', run_attempt='1', head_sha='a'*40)
        selection = dict(schema_version=1, uses=uses, source=source, run=run,
                         created_at=datetime.now(timezone.utc).isoformat())
        calls = []

        class BeforeProducer(Exception):
            pass

        def collect(root, **kwargs):
            calls.append(kwargs.get('image_bindings'))
            raise BeforeProducer

        binding = dict(database='owned',source_id='artifact-license-catalog',source_url='owned',
                       content_sha256='c'*64,payload_size=1,acquisition={},coverage={})
        with patch.object(expanded,'read_image_selection',return_value=selection), \
                patch.object(expanded,'_selection_authority',return_value=(source,run)), \
                patch.object(inventory,'collect_inventory',side_effect=collect):
            for function in (expanded.security_obligations,expanded.known_vulnerability_report,
                             expanded.known_vulnerability_check,expanded.run_checks):
                with self.subTest(consumer=function.__name__), self.assertRaises(BeforeProducer):
                    self.owned(lambda: function(Path('/owned'),environ=env))
                self.assertEqual(calls[-1],uses)
            with self.assertRaises(BeforeProducer):
                self.owned(lambda: expanded.validate_data_source(binding,root=Path('/owned'),environ=env))
            self.assertEqual(calls[-1],uses)


    def test_invalid_selection_field_types_have_closed_refusal(self):
        row = dict(path='compose.yaml',line=1,source_sha256='a'*64,expression='${OWNED_IMAGE}',
                   reference='example.invalid/owned@sha256:'+'b'*64,platform=[])
        def observed_kind():
            try:
                inventory.selected_image_use([row],path=row['path'],line=1,source_sha256=row['source_sha256'],
                                             expression=row['expression'])
            except Exception as error:
                return type(error).__name__
            return 'accepted'
        self.assertEqual(self.owned(observed_kind),'ValueError')
        document = dict(schema_version=1,source={},run={},created_at=[],uses=[row])
        with patch('getzilla.security_artifacts.read_file',return_value=json.dumps(document).encode()):
            with self.assertRaises(ValueError):
                self.owned(lambda: inventory.read_image_selection(Path('/owned/selection.json')))



if __name__ == "__main__":
    unittest.main()
