"""Record complete actual Trust CI discovery. Required database skips refuse."""
from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'.getzilla'), str(ROOT/'trust-ci/src'), str(ROOT/'trust-ci/tests'), str(ROOT/'trust-ci')]
from getzilla.live_acceptance import record_suite, accepted_suite, read_document, _held_bytes, _write

produce = record_suite


class _PrivateOutput:
    def write(self, content):
        return len(content)

    def flush(self):
        pass


def source_snapshot(root):
    content = {}
    total = 0
    entries = 0
    for directory in ('trust-ci/src', 'trust-ci/tests', 'trust-ci/migrations', 'trust-ci/postgres/init'):
        for path in (root/directory).rglob('*'):
            entries += 1
            if entries > 10000 or len(path.relative_to(root).parts) > 64:
                raise ValueError('Trust source inventory exceeds entry/depth bound')
            if path.is_symlink():
                raise ValueError('Linked Trust live source input')
            if '__pycache__' in path.parts or path.suffix in {'.pyc', '.pyo'}:
                continue
            if path.is_dir():
                continue
            if len(content) >= 10000 or path.name == '.env':
                raise ValueError('Unsafe Trust source inventory')
            raw = _held_bytes(path)
            total += len(raw)
            if total > 32 * 1024 * 1024:
                raise ValueError('Trust source inventory exceeds bound')
            content[path.relative_to(root).as_posix()] = raw
    return content


def declared_ids(contents):
    result = []
    for path, raw in contents.items():
        if not path.startswith('trust-ci/tests/test_') or not path.endswith('.py'):
            continue
        module = 'tests.' + Path(path).stem
        for node in ast.parse(raw, filename=path).body:
            if isinstance(node, ast.ClassDef):
                result.extend(module+'.'+node.name+'.'+method.name for method in node.body
                              if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)) and method.name.startswith('test_'))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith('test_'):
                result.append(module+'.'+node.name)
    return sorted(result)


def main():
    names = ('TRUST_CI_TEST_DATABASE_URL', 'TRUST_CI_TEST_API_DATABASE_URL',
             'TRUST_CI_TEST_WORKER_DATABASE_URL', 'TRUST_CI_TEST_BACKUP_DATABASE_URL')
    if not all(os.environ.get(name) for name in names):
        raise ValueError('All required owned Trust database roles are required')
    binding = read_document(Path(os.environ['GETZILLA_LIVE_BINDING']))
    if binding.get('cell') != 'trust-ci':
        raise ValueError('Trust live suite invocation mismatch')
    before = source_snapshot(ROOT)
    loader = unittest.TestLoader()
    suite = loader.discover(str(ROOT/'trust-ci/tests'), pattern='test_*.py', top_level_dir=str(ROOT/'trust-ci'))
    expected = declared_ids(before)
    document = produce(suite, expected_ids=expected, required_ids=expected, loader_errors=loader.errors,
        binding=binding, source_stable=lambda: source_snapshot(ROOT) == before,
        source_root=ROOT, source_paths=before, stream=_PrivateOutput())
    document['source_inventory'] = {name: hashlib.sha256(raw).hexdigest() for name, raw in before.items()}
    if sys.argv[1:] == ['--stdout']:
        print(json.dumps(document, sort_keys=True))
    elif sys.argv[1:]:
        raise ValueError('Unsupported live suite arguments')
    else:
        _write(Path(os.environ['GETZILLA_LIVE_ARTIFACTS'])/'trust-ci-suite.json', document)
    return 0 if accepted_suite(document, binding) else 1


if __name__ == '__main__':
    raise SystemExit(main())
