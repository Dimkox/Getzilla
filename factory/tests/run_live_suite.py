"""Complete source-bound Factory discovery with live database obligations."""
from __future__ import annotations

import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / 'factory/src'), str(ROOT / '.getzilla')]
from getzilla import factory_tests
from getzilla.live_acceptance import record_suite, accepted_suite, valid_binding, read_document, _write

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


def guard_databases(binding):
    from factory.tests import postgres_restart_probe as probe
    names = ('FACTORY_TEST_DATABASE_URL','FACTORY_FRESH_CLUSTER_DATABASE_URL',
             'FACTORY_TEST_POSTGRES_CONTAINER','FACTORY_TEST_POSTGRES_CONTAINER_ID',
             'FACTORY_FRESH_POSTGRES_CONTAINER','FACTORY_FRESH_POSTGRES_CONTAINER_ID',
             'FACTORY_TEST_POSTGRES_JOURNAL','FACTORY_TEST_POSTGRES_NAMESPACE',
             'FACTORY_TEST_POSTGRES_NETWORK_ID','FACTORY_TEST_POSTGRES_NONCE')
    if not all(os.environ.get(name) for name in names):
        raise ValueError('Complete owned primary and fresh database bindings are required')
    environment = os.environ
    if environment['FACTORY_TEST_POSTGRES_NAMESPACE'] != binding['namespace']:
        raise ValueError('Live database namespace differs from invocation')
    targets = [(environment['FACTORY_TEST_DATABASE_URL'],environment['FACTORY_TEST_POSTGRES_CONTAINER'],environment['FACTORY_TEST_POSTGRES_CONTAINER_ID']),
               (environment['FACTORY_FRESH_CLUSTER_DATABASE_URL'],environment['FACTORY_FRESH_POSTGRES_CONTAINER'],environment['FACTORY_FRESH_POSTGRES_CONTAINER_ID'])]
    if targets[0][2] == targets[1][2] or targets[0][1] == targets[1][1]:
        raise ValueError('Fresh cluster must have a distinct original container')
    nonce = environment['FACTORY_TEST_POSTGRES_NONCE']
    for url, name, identifier in targets:
        if not name.startswith(binding['namespace']+'-'):
            raise ValueError('Live suite refuses a legacy or foreign PostgreSQL target')
        probe._assert_owned_endpoint(url,name,identifier,nonce)
    # This is the same preflight entry used by postgres_restart_probe --preflight-only.
    # Both endpoints have already passed birth/DSN validation before identity SQL.
    clusters = [probe._assert_disposable_target(url,name,identifier,nonce) for url,name,identifier in targets]
    if (any(not isinstance(cluster,str) or not cluster.isdigit() for cluster in clusters)
            or clusters[0] == clusters[1]):
        raise ValueError('Fresh PostgreSQL cluster must have a distinct system identifier')


def main():
    binding = read_document(Path(os.environ['GETZILLA_LIVE_BINDING']))
    if not valid_binding(binding) or binding['cell'] != 'factory':
        raise ValueError('Factory suite invocation mismatch')
    guard_databases(binding)
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
