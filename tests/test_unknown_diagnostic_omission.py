"""NEW paired strict-schema diagnostic observation; no source or process runs."""
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

W = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(W / '.getzilla'))
from getzilla import verification_progress_evidence as evidence

ACTIVE = False


def guard(event, args):
    if ACTIVE and (event == 'open' or event.startswith(('os.', 'subprocess.', 'socket.', 'shutil.'))):
        raise AssertionError('all filesystem/native/network activity denied in pure fixture')


sys.addaudithook(guard)


class UnknownDiagnosticOmissionTests(unittest.TestCase):
    def observe(self, diagnostic, resolved):
        path = 'tests/test_owned_paired.py'
        identity = path + '::test_owned'
        key = hashlib.sha256(identity.encode()).hexdigest()
        event = dict(ordinal=1, phase='call', path=path, key=key, diagnostic=diagnostic)
        row = dict(worker=0, sequence=1, overflow=False, dropped=False, partial_tail=False, events=[event])
        progress = dict(selected_workers=1, status='observed', slots=[],
                        failure_events=dict(version=1, status='observed', workers=[row]))

        def owned_source(root, paths, **kwargs):
            self.assertEqual(root, Path('/owned-unread-source'))
            kwargs['observation'].update(status='observed' if resolved else 'unavailable',
                                         reason='complete' if resolved else 'deadline',
                                         head='a' * 40 if resolved else None,
                                         currentness='verified' if resolved else 'unknown')
            return {path: (4, {'test_owned'})} if resolved else {}

        global ACTIVE
        with patch.object(evidence, '_trusted_progress_metadata', side_effect=owned_source):
            ACTIVE = True
            try:
                result = evidence._core_progress_details(Path('/owned-unread-source'), progress)
            finally:
                ACTIVE = False
        self.assertLessEqual(len(json.dumps(result).encode()), 16000)
        self.assertLessEqual(len(json.dumps(result['failure_events']).encode()), 8192)
        return result, identity, dict(path=path, key=key)

    def test_same_validated_refusal_retained_or_explicitly_omitted(self):
        diagnostic = dict(decision='deny', reason='budget')
        unknown, _, source = self.observe(diagnostic, False)
        failure = unknown['failure_events']
        self.assertEqual(len(failure['events']), 1, 'strict schema must accept this closed refusal')
        event = failure['events'][0]
        self.assertIsNone(event['identity'])
        self.assertEqual(event['source'], source)
        self.assertNotIn('diagnostic', event, 'unknown source gets no trusted diagnostic projection')
        self.assertIs(event.get('diagnostic_omitted'), True)
        self.assertIs(failure.get('diagnostics_omitted'), True)
        self.assertEqual(failure['omitted_events'], 0)
        self.assertEqual(failure['status'], 'partial')
        resolved, identity, _ = self.observe(diagnostic, True)
        known = resolved['failure_events']['events'][0]
        self.assertEqual(known['identity'], identity)
        self.assertEqual(known['diagnostic'], diagnostic)
        self.assertNotIn('diagnostic_omitted', known)
        self.assertNotIn('diagnostics_omitted', resolved['failure_events'])

    def test_invalid_diagnostic_never_enters_the_closed_channel(self):
        for resolved in (False, True):
            with self.subTest(resolved=resolved):
                result, _, _ = self.observe(dict(decision='deny', reason='unrecognized-owned-value'), resolved)
                self.assertEqual(result['failure_events']['events'], [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
