"""#63: the security model page and the README file map stay true to the repository."""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class SecurityDocTests(unittest.TestCase):
    def test_security_page_covers_the_review_items(self) -> None:
        text = (ROOT / 'docs/SECURITY.md').read_text(encoding='utf-8')
        for heading in ('## What Getzilla defends against', '## Keys', '## When a check fails', '## Reviewer independence',
                        '## Tests and dependencies', '## Glossary: levels and milestones'):
            self.assertIn(heading, text)
        # The page never tells anyone to update a digest to make a failing check pass.
        self.assertIn('never update the digest or the trust store to make the check pass', text)
        self.assertNotRegex(text.lower(), r'verification failed[^.]*\bupdate\b[^.]*digest')

    def test_security_page_quotes_the_real_coverage_gate(self) -> None:
        gate = re.search(r'^fail_under\s*=\s*(\d+)', (ROOT / '.coveragerc').read_text(encoding='utf-8'), re.M).group(1)
        self.assertIn(f'`fail_under = {gate}`', (ROOT / 'docs/SECURITY.md').read_text(encoding='utf-8'))

    def test_readme_file_map_names_only_existing_paths(self) -> None:
        readme = (ROOT / 'README.md').read_text(encoding='utf-8')
        section = readme.split('## What is inside', 1)[1].split('\n## ', 1)[0]
        paths = set(re.findall(r'`([.A-Za-z][\w./-]*/)`', section))
        self.assertIn('.getzilla/', paths)
        for path in sorted(paths):
            with self.subTest(path=path):
                self.assertTrue((ROOT / path).is_dir(), path)


if __name__ == '__main__':
    unittest.main()
