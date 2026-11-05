"""Tagged Git/Gitless context provenance; validation creates no access permit."""
import re

from .context_contracts import ContextManifestV1
from .contracts import ContractError
from .v15_contracts import closed, digest


class ContextManifestV2(ContextManifestV1):
    @staticmethod
    def _version(data):
        if type(data.get('schema_version')) is not int or data['schema_version'] != 2:
            raise ContractError('unsupported_schema_version')

    @staticmethod
    def _snapshot(snapshot):
        if not isinstance(snapshot, dict):
            raise ContractError('invalid_source_snapshot')
        if snapshot.get('kind') == 'gitless':
            closed(snapshot, ('kind', 'snapshot_digest'))
            digest(snapshot['snapshot_digest'])
        elif snapshot.get('kind') == 'git':
            closed(snapshot, ('kind', 'base_sha', 'head_sha', 'dirty_fingerprint'))
            for key in ('base_sha', 'head_sha'):
                value = snapshot[key]
                if not isinstance(value, str) or not re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', value):
                    raise ContractError('invalid_sha')
            if snapshot['dirty_fingerprint'] is not None:
                digest(snapshot['dirty_fingerprint'])
        else:
            raise ContractError('unsupported_source_snapshot')
