from __future__ import annotations

import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import skill_inventory  # noqa: E402
from tests.test_installer import MODULE as installer  # noqa: E402
from tests import test_harnesses as harness_tests  # noqa: E402


class ShippedInventoryTests(unittest.TestCase):
    def test_actual_shipped_installer_bytes_keep_their_existing_contract(self):
        payload = installer.build_payload(installer.ROOT)
        result = skill_inventory.inspect_payload([(entry.path, entry.content) for entry in payload])
        self.assertGreater(result['skill_count'], 10)
        self.assertEqual(result['semantic_safety'], 'unqualified')
        self.assertFalse(result['permissions_granted'])

    def test_inconsistent_alias_skill_bytes_are_refused(self):
        with self.assertRaisesRegex(ValueError, 'SHIPPED_SKILL_ALIAS_CONFLICT'):
            skill_inventory.inspect_payload([('.agents/skills/example/SKILL.md', b'original'),
                                             ('.grok/skills/example/SKILL.md', b'changed')])

    def test_same_alias_path_cannot_be_listed_twice_and_identity_is_source_bound(self):
        one = [('.agents/skills/example/SKILL.md', b'original')]
        with self.assertRaises(ValueError):
            skill_inventory.inspect_payload(one + one)
        first = skill_inventory.inspect_payload(one)
        changed = skill_inventory.inspect_payload([('.agents/skills/example/SKILL.md', b'changed')])
        self.assertNotEqual(first['inventory_digest'], changed['inventory_digest'])

    def test_harness_generation_consumes_bounded_canonical_skill_inventory(self):
        fixture = harness_tests.SelectedHarnessTests()
        try:
            root = fixture.qwen()
            skill = root / '.agents/skills/example/SKILL.md'
            skill.write_bytes(b'x' * (skill_inventory.MAX_FILE_BYTES + 1))
            from getzilla import harnesses
            with self.assertRaisesRegex(ValueError, 'skill'):
                harnesses.write(root)
            self.assertFalse((root / '.qwen').exists())
        finally:
            fixture.doCleanups()

    def test_installed_payload_keeps_the_complete_whitespace_proof_closure(self):
        payload = installer.build_payload(installer.ROOT)
        paths = {entry.path for entry in payload}
        self.assertTrue({'.getzilla/config/vendored-source-catalog.json',
                         'engineering/verification-dispositions.json',
                         'engineering/vendor-custody/bmad-whitespace.json',
                         'engineering/vendor-custody/bmad-whitespace.md'} <= paths)
