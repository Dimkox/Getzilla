import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla import security_osv_snapshot as snapshot


class SnapshotIdentityTests(unittest.TestCase):
    dependency = snapshot.Dependency('PyPI', 'sample', '1.0', 'requirements.txt')

    def test_decision_identifiers_retain_provider_evidence(self):
        aliases = ['MAL-2025-123', 'CVE-2025-12345', 'provider annotation']
        finding = snapshot._describe({'id': 'OSV-123', 'aliases': aliases}, self.dependency)
        self.assertEqual(finding.aliases, sorted(aliases[:2]))
        self.assertEqual(finding.raw_aliases, aliases)

    def test_malformed_cve_prevents_finding_construction(self):
        with self.assertRaisesRegex(snapshot.VulnerabilityError, 'identifier is malformed'):
            snapshot._describe({'id': 'OSV-123', 'aliases': ['CVE-2025-1']}, self.dependency)
