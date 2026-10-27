"""Historical incident relocation conserves exact original byte ranges."""
from __future__ import annotations
import hashlib
import json
import re
import subprocess
import tempfile
import unittest
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

from tests._support import missing_history  # noqa: E402
BASE = '01f67873ea17949208f92c83d34d0af38a586779'
ASSOCIATIONS = {('2026-10-09-root-1967.md', b'74'): 'https://github.com/Dimkox/Getzilla/pull/74'}


@lru_cache(maxsize=2)
def _original(source: str) -> bytes:
    if source not in {'mistakes.md', 'engineering/mistakes.md'}:
        raise ValueError('unknown historical source')
    shown = subprocess.run(['git', 'show', f'{BASE}:{source}'], cwd=ROOT, capture_output=True, check=False)
    if shown.returncode != 0:
        missing_history(f'historical commit {BASE}')
    return shown.stdout


def historical_incident(relative: str, root: Path = ROOT) -> bool:
    try:
        manifest = json.loads((root / 'engineering/incidents/provenance.json').read_bytes())
        rows = [row for row in manifest['segments'] if row.get('destination') == relative]
        if len(rows) != 1 or manifest['base'] != BASE:
            return False
        row = rows[0]
        if row['kind'] != 'incident' or not re.fullmatch(r'engineering/incidents/(?:\d{4}-\d{2}-\d{2}|undated)-(?:root|engineering)-\d+\.md', relative):
            return False
        original = _original(row['source'])
        start, end = row['start_byte'], row['end_byte']
        if not 0 <= start < end <= len(original):
            return False
        piece = original[start:end]
        sha = hashlib.sha256(piece).hexdigest()
        if sha != row['sha256'] or row['start_line'] != original[:start].count(b'\n') + 1 or row['end_line'] != original[:end].count(b'\n'):
            return False
        prefix = f'<!-- Historical source: {BASE}:{row["source"]}; bytes {start}:{end}; sha256 {sha}. -->\n\n'.encode()
        numbers = sorted(set(re.findall(rb'\bPR\s*#?(\d+)', piece)))
        references = ''.join(f'- [PR {number.decode()}]({ASSOCIATIONS[(Path(relative).name, number)]})\n'
                             if (Path(relative).name, number) in ASSOCIATIONS
                             else f'- Recorded PR number {number.decode()}; repository association is not asserted.\n' for number in numbers)
        suffix = (f'\n\nSource: [{row["source"]}:{row["start_line"]}-{row["end_line"]}](https://github.com/Dimkox/getzilla/blob/{BASE}/{row["source"]}#L{row["start_line"]}-L{row["end_line"]}).\n'
                  + ('\nRecorded PR references:\n\n' + references if numbers else '\nNo pull request association is asserted by this archive.\n')).encode()
        expected = prefix + piece + suffix
        return ((root / relative).read_bytes() == expected and hashlib.sha256(expected).hexdigest() == row['file_sha256']
                and (row['payload_start'], row['payload_end']) == (len(prefix), len(prefix) + len(piece)))
    except (OSError, ValueError, KeyError, TypeError):
        return False


class IncidentHistoryTests(unittest.TestCase):
    def test_every_original_byte_is_conserved_and_projection_is_exact(self):
        manifest = json.loads((ROOT / 'engineering/incidents/provenance.json').read_bytes())
        self.assertEqual(manifest['base'], BASE)
        for source in ('mistakes.md', 'engineering/mistakes.md'):
            original = _original(source)
            rows = sorted((row for row in manifest['segments'] if row['source'] == source), key=lambda row: row['start_byte'])
            recovered = b''
            for row in rows:
                self.assertEqual(row['start_byte'], len(recovered))
                piece = original[row['start_byte']:row['end_byte']]
                self.assertEqual(hashlib.sha256(piece).hexdigest(), row['sha256'])
                destination = (ROOT / row['destination']).read_bytes()
                if row['kind'] == 'incident':
                    self.assertTrue(historical_incident(row['destination']))
                    self.assertEqual(destination[row['payload_start']:row['payload_end']], piece)
                else:
                    self.assertIn(piece, destination)
                recovered += piece
            self.assertEqual(recovered, original)

    def test_identity_exception_is_exact_and_does_not_admit_arbitrary_archives(self):
        self.assertFalse(historical_incident('engineering/incidents/2026-01-01-invented.md'))
        rows = json.loads((ROOT / 'engineering/incidents/provenance.json').read_bytes())['segments']
        self.assertTrue(any(historical_incident(row['destination']) for row in rows if row['kind'] == 'incident'))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = json.loads((ROOT / 'engineering/incidents/provenance.json').read_bytes())
            row = next(row for row in manifest['segments'] if row['kind'] == 'incident')
            path = root / row['destination']
            path.parent.mkdir(parents=True)
            forged = (ROOT / row['destination']).read_bytes() + b'\nnew unauthorized historical-looking prose\n'
            path.write_bytes(forged)
            row['file_sha256'] = hashlib.sha256(forged).hexdigest()
            (root / 'engineering/incidents/provenance.json').write_text(json.dumps(manifest))
            self.assertFalse(historical_incident(row['destination'], root))

    def test_recurring_lessons_link_distinct_original_occurrences(self):
        manifest = json.loads((ROOT / 'engineering/incidents/provenance.json').read_bytes())
        lessons = (ROOT / 'engineering/mistakes.md').read_text()
        for key, count in [('invented_sha', 2), ('shell_substitution', 5)]:
            references = manifest['recurring'][key]
            self.assertEqual(len(set(references)), count)
            for relative in references:
                self.assertTrue(historical_incident(relative))
                self.assertIn(relative.removeprefix('engineering/'), lessons)
