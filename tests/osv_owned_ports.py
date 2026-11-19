"""Content-bound in-memory snapshot ports for matcher unit tests only.

These fixtures do not qualify native acquisition or filesystem custody.
"""
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from unittest.mock import patch

from getzilla import security_data as data
from getzilla import security_osv_snapshot as snapshot

NOW = datetime(2026, 11, 17, tzinfo=timezone.utc)


def snapshot_ports(stack, module, payload):
    manifest = dict(schema_version=1, source_id='osv:PyPI',
                    source_url=data.SOURCE_URLS['osv:PyPI'],
                    content_sha256=hashlib.sha256(payload).hexdigest(), payload_size=len(payload),
                    acquisition={'last_verified_sync_utc': NOW.isoformat(), 'retrieval_kind': 'download'},
                    coverage=data.osv_coverage(payload, 'PyPI'))
    proof = data._validate(manifest, payload, 'osv:PyPI', now=NOW, required_scope={'PyPI'})
    proof['manifest_sha256'] = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()

    def read_owned(database, source, *, now=None, required_scope=None):
        if database != Path('/owned-db') or source != 'osv:PyPI' or required_scope != {'PyPI'}:
            raise AssertionError('outside owned snapshot selection')
        if data._validate(manifest, payload, source, now=NOW, required_scope=required_scope) != {
                key: value for key, value in proof.items() if key != 'manifest_sha256'}:
            raise AssertionError('owned snapshot content changed')
        return payload, copy.deepcopy(proof)

    def confirm_owned(database, evidence, *, now=None):
        if database != Path('/owned-db') or evidence != [proof]:
            raise AssertionError('outside owned snapshot confirmation')
        read_owned(database, 'osv:PyPI', required_scope={'PyPI'})

    owner = snapshot if module is snapshot else data
    stack.enter_context(patch.object(owner, 'read_snapshot', side_effect=read_owned))
    stack.enter_context(patch.object(data, 'confirm_snapshots', side_effect=confirm_owned))
    return proof
