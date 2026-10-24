"""Exercise adapter behavior in Python and Node without a real C2PA service."""
import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from tests.test_eu_ai_act import ROOT

PYTHON = ROOT / '.getzilla/templates/eu-ai-act/transparency/python/ai_transparency.py'
TYPESCRIPT = ROOT / '.getzilla/templates/eu-ai-act/transparency/typescript/aiTransparency.ts'


class TransparencyTests(unittest.TestCase):
    def module(self):
        spec = importlib.util.spec_from_file_location('transparency_fixture', PYTHON)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_python_fallback_and_public_labels(self):
        mod = self.module()
        with mock.patch.object(mod.shutil, 'which', return_value=None):
            result = mod.mark_generated_content('hello', generator='public app', model='public model',
                                                media_type='text/plain', path='unused')
        self.assertEqual(result['content'], 'hello')
        self.assertIsNone(result['c2pa'])
        self.assertEqual(result['c2pa_error'], 'c2patool not found')
        self.assertEqual(result['provenance']['digitalSourceType'], mod.IPTC_GENERATED)
        self.assertEqual(result['provenance']['generator'], 'public app')
        self.assertEqual(result['provenance']['model'], 'public model')
        self.assertEqual(mod.label_published_content(mod.label_published_content('hello')),
                         mod.label_published_content('hello'))

    def test_python_failure_timeout_and_success_preserve_original(self):
        mod = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'image.png'
            source.write_bytes(b'original')
            for outcome in ('fail', 'timeout', 'success'):
                def run(argv, **kwargs):
                    self.assertEqual(kwargs['timeout'], 30)
                    self.assertNotEqual(Path(argv[1]), source)
                    output = Path(argv[argv.index('-o') + 1])
                    self.assertNotEqual(output, source)
                    self.assertNotEqual(output, Path(argv[1]))
                    self.assertEqual(Path(argv[1]).read_bytes(), b'original')
                    if outcome == 'timeout':
                        raise subprocess.TimeoutExpired(argv, 30)
                    if outcome == 'success':
                        output.write_bytes(b'marked')
                    return subprocess.CompletedProcess(argv, int(outcome == 'fail'))
                with mock.patch.object(mod.shutil, 'which', return_value='/trusted/c2patool'), \
                        mock.patch.object(mod.subprocess, 'run', side_effect=run):
                    result = mod.mark_generated_content(b'original', generator='app', model='model',
                                                        media_type='image/png', path=str(source))
                self.assertEqual(source.read_bytes(), b'original')
                self.assertEqual(result['content'], b'original')
                if outcome == 'success':
                    self.assertEqual(result['c2pa'], b'marked')
                    self.assertIsNone(result['c2pa_error'])
                else:
                    self.assertIsNone(result['c2pa'])
                    self.assertTrue(result['c2pa_error'])

    @unittest.skipUnless(shutil.which('node'), 'Node is required for the Node TypeScript adapter')
    def test_node_success_failure_and_timeout_preserve_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copyfile(TYPESCRIPT, Path(tmp) / 'adapter.mjs')
            source = Path(tmp) / 'input.png'
            source.write_bytes(b'original')
            runner = Path(tmp) / 'run.mjs'
            runner.write_text('''
import {createRequire, syncBuiltinESMExports} from 'node:module';
import {readFileSync, writeFileSync} from 'node:fs';
const cp = createRequire(import.meta.url)('node:child_process');
let outcome = 'success';
cp.spawnSync = (tool, argv, options) => {
  if (tool !== 'c2patool' || options.timeout !== 30000 || options.shell !== false) throw Error('invocation');
  if (argv[0] === process.argv[2] || argv[4] === process.argv[2] || argv[0] === argv[4]) throw Error('input replaced');
  if (readFileSync(argv[0], 'utf8') !== 'original') throw Error('wrong input');
  if (outcome === 'success') { writeFileSync(argv[4], 'marked'); return {status:0}; }
  if (outcome === 'timeout') return {status:null, error:{code:'ETIMEDOUT'}};
  return {status:1};
};
syncBuiltinESMExports();
const {markGeneratedContent} = await import('./adapter.mjs');
for (outcome of ['success', 'failure', 'timeout']) {
  const result = markGeneratedContent('original', {generator:'app', model:'model', media_type:'image/png', path:process.argv[2]});
  if (result.content !== 'original' || readFileSync(process.argv[2], 'utf8') !== 'original') throw Error('changed content');
  if (outcome === 'success' && (result.c2pa?.toString() !== 'marked' || result.c2pa_error !== null)) throw Error('lost output');
  if (outcome !== 'success' && (result.c2pa !== null || !result.c2pa_error)) throw Error('false success');
}
''', encoding='utf-8')
            # Behavior, not speed: leave room for Node startup on a loaded CI runner (#187).
            proc = subprocess.run([shutil.which('node'), str(runner), str(source)], cwd=tmp,
                                  capture_output=True, text=True, timeout=60, check=False)
            self.assertEqual(proc.returncode, 0, proc.stderr)

    @unittest.skipUnless(shutil.which('node'), 'Node is required for the Node TypeScript adapter')
    @unittest.skipIf(os.name == 'nt', 'POSIX fixture ignores SIGTERM')
    def test_node_real_stubborn_child_is_killed_at_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            shutil.copyfile(TYPESCRIPT, directory / 'adapter.mjs')
            tool = directory / 'c2patool'
            tool.write_text('#!' + sys.executable + '\nimport signal, time\n'
                            'signal.signal(signal.SIGTERM, signal.SIG_IGN)\ntime.sleep(120)\n', encoding='utf-8')
            tool.chmod(0o700)
            source = directory / 'input.png'
            source.write_bytes(b'original')
            runner = directory / 'run.mjs'
            runner.write_text("import {markGeneratedContent} from './adapter.mjs';\n"
                              "console.log(JSON.stringify(markGeneratedContent('original', {generator:'fixture', "
                              "model:'fixture', media_type:'image/png', path:process.argv[2]})));\n", encoding='utf-8')
            started = time.monotonic()
            process = subprocess.Popen([shutil.which('node'), str(runner), str(source)], cwd=directory,
                                       env={**os.environ, 'PATH': str(directory) + os.pathsep + os.defpath},
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                       start_new_session=True)
            try:
                # The tool deadline is 30 s. Allow Node startup and loaded CI scheduling outside it.
                stdout, stderr = process.communicate(timeout=45)
            finally:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate(timeout=3)
            self.assertEqual(process.returncode, 0, stderr)
            self.assertLess(time.monotonic() - started, 44)
            result = json.loads(stdout)
            self.assertEqual(result['c2pa_error'], 'c2patool timeout')
            self.assertIsNone(result['c2pa'])
            self.assertEqual(source.read_bytes(), b'original')

    @unittest.skipUnless(shutil.which('node'), 'Node is required for the Node TypeScript adapter')
    def test_node_adapter_behavior(self):
        with tempfile.TemporaryDirectory() as tmp:
            # The template uses syntax shared by TypeScript and modern JavaScript.
            adapter = Path(tmp) / 'adapter.mjs'
            shutil.copyfile(TYPESCRIPT, adapter)
            source = Path(tmp) / 'input.png'
            source.write_bytes(b'original')
            program = """
import {markGeneratedContent, labelPublishedContent, IPTC_GENERATED} from './adapter.mjs';
const result = markGeneratedContent('original', {generator:'public app', model:'public model',
 media_type:'image/png', path:process.argv[2]});
if (result.content !== 'original' || result.c2pa !== null || !result.c2pa_error) process.exit(4);
if (labelPublishedContent(labelPublishedContent('x')) !== labelPublishedContent('x')) process.exit(5);
console.log(JSON.stringify({type:result.provenance.digitalSourceType, generator:result.provenance.generator}));
"""
            runner = Path(tmp) / 'run.mjs'
            runner.write_text(program, encoding='utf-8')
            proc = subprocess.run([shutil.which('node'), str(runner), str(source)], cwd=tmp,
                                  env={'PATH': ''}, capture_output=True, text=True, timeout=60, check=False)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(json.loads(proc.stdout)['generator'], 'public app')
            self.assertIn('trainedAlgorithmicMedia', json.loads(proc.stdout)['type'])
            self.assertEqual(source.read_bytes(), b'original')
