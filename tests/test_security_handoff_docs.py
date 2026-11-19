"""Check operator handoff links and source-bound limits."""
import configparser
import unittest
from tests._support import PROJECT


class SecurityHandoffDocsTests(unittest.TestCase):
    def test_reference_links_to_operator_handoff(self):
        reference = (PROJECT / 'docs/REFERENCE.md').read_text()
        self.assertIn('security-handoff.md', reference)
        self.assertNotIn('local reviews → `ready` → pull request', reference)

    def test_handoff_binds_coverage_scope_and_canonical_paths(self):
        guide = (PROJECT / 'engineering/runbooks/security-handoff.md').read_text()
        config = configparser.ConfigParser()
        config.read(PROJECT / '.coveragerc')
        self.assertIn('`' + config['report']['fail_under'] + '%`', guide)
        for path in ('.grok', '.agents/skills', '.getzilla/getzilla', '.claude',
                     '.codex', '.gemini', 'architecture/system.yaml'):
            self.assertTrue((PROJECT / path).exists(), path)
            self.assertIn('`' + path + '`', guide)
        self.assertIn('NOT_RUN', guide)
        self.assertIn('same model', guide)
