"""Exact source comment projections have custody separate from text recognition."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
BSD = json.loads((ROOT / 'tests/fixtures/security-license-texts.json').read_text())['BSD-3-Clause']['text'].encode()


def sha(body):
    return hashlib.sha256(body).hexdigest()


class SourceCommentTests(unittest.TestCase):
    def world(self):
        self.assertIsNotNone(importlib.util.find_spec('getzilla.security_action_npm_comments'), 'missing exact source comment codec')
        from getzilla import security_action_npm_comments as codec
        comment = b''.join(b'// ' + line for line in BSD.splitlines(keepends=True))
        body = b'/* owned source preface */\n' + comment + b'const inert = 1;\n'
        source = dict(sha256='a' * 64, path='owned.tgz')
        path = 'package/src/owned.js'
        recipe = dict(container_path=path, container_sha256=sha(body), container_bytes=len(body),
                      start_line=2, end_line_exclusive=2 + len(BSD.splitlines(keepends=True)),
                      decoded_sha256=sha(BSD), decoded_bytes=len(BSD))
        return codec, source, {path: body}, recipe

    def test_full_original_container_selector_and_decoded_bytes_all_bind(self):
        codec, source, files, recipe = self.world()
        with patch.dict(codec.RECIPES, {source['sha256']: [recipe]}, clear=True):
            result = codec.project(source, files)
        self.assertEqual(result['terms'][0][1], BSD)
        proof = result['proofs'][0]
        self.assertEqual(proof['sha256'], recipe['container_sha256'])
        self.assertEqual(proof['decoded_sha256'], sha(BSD))
        self.assertEqual(proof['physical_bytes'], 0)
        self.assertEqual(proof['artifact_sha256'], source['sha256'])
        self.assertTrue(result['terms'][0][0].startswith('derived/'))

    def test_altered_container_selector_or_decoded_hash_cannot_gain_text_credit(self):
        codec, source, files, recipe = self.world()
        for variant in ('container', 'selector', 'decoded', 'namespace', 'prefix'):
            changed, data = copy.deepcopy(recipe), dict(files)
            if variant == 'container':
                data[recipe['container_path']] += b'/* added restrictions */'
            elif variant == 'selector':
                changed['start_line'] += 1
            elif variant == 'decoded':
                changed['decoded_sha256'] = '0' * 64
            elif variant == 'namespace':
                changed['container_path'] = 'package/foreign.js'
            else:
                data[recipe['container_path']] = data[recipe['container_path']].replace(b'// ', b'# ', 1)
                changed['container_sha256'] = sha(data[recipe['container_path']])
            with self.subTest(variant=variant), patch.dict(codec.RECIPES, {source['sha256']: [changed]}, clear=True), self.assertRaises(ValueError):
                codec.project(source, data)

    def test_unlisted_artifact_gets_no_comment_namespace_from_recognized_text(self):
        codec, source, files, recipe = self.world()
        self.assertEqual(codec.project(dict(source, sha256='b' * 64), files), {'terms': [], 'proofs': []})
