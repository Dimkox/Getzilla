"""Complete source-bound Factory discovery with live database obligations."""
from __future__ import annotations

import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / 'factory/src'), str(ROOT / '.getzilla')]
from getzilla import factory_tests
from getzilla.live_acceptance import record_suite, accepted_suite, read_document, _write

produce = record_suite


class _PrivateOutput:
    def write(self, content):
        return len(content)

    def flush(self):
        pass


def accepted(result, executed):
    """Compatibility predicate refuses missing native recorder completeness."""
    return bool(getattr(result, 'started', None) and not result.skipped and result.wasSuccessful()
                and result.testsRun == len(result.started) and set(executed) == set(result.started)
                and any('FreshClusterArtifactAttestorMigrationTests.' in name for name in executed)
                and any('test_postgres_integration.' in name for name in executed))


def main():
    if not os.environ.get('FACTORY_TEST_DATABASE_URL') or not os.environ.get('FACTORY_FRESH_CLUSTER_DATABASE_URL'):
        raise ValueError('Both owned disposable databases are required')
    binding = read_document(Path(os.environ['GETZILLA_LIVE_BINDING']))
    if binding.get('cell') != 'factory':
        raise ValueError('Factory suite invocation mismatch')
    contents, identities = factory_tests._source_snapshot(ROOT)
    expected = factory_tests.declared_ids(ROOT, contents=contents)
    loader = unittest.TestLoader()
    suite = loader.discover(str(ROOT/'factory/tests'), pattern='test_*.py', top_level_dir=str(ROOT))
    def stable():
        return factory_tests._source_snapshot(ROOT) == (contents, identities)
    document = produce(suite, expected_ids=expected, required_ids=expected, loader_errors=loader.errors,
        binding=binding, source_stable=stable, source_root=ROOT, source_paths=contents,
        stream=_PrivateOutput())
    if not (any('FreshClusterArtifactAttestorMigrationTests.' in name for name in document['executed'])
            and any('test_postgres_integration.' in name for name in document['executed'])):
        document['status'] = 'fail'
    import hashlib
    document['source_inventory'] = {name: hashlib.sha256(content).hexdigest() for name, content in contents.items()}
    _write(Path(os.environ['GETZILLA_LIVE_ARTIFACTS'])/'factory-suite.json', document)
    return 0 if accepted_suite(document, binding) else 1


if __name__ == '__main__':
    raise SystemExit(main())
