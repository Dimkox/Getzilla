"""Owned-object snapshot bytes have one strict, bounded interpretation."""
import hashlib
import base64
import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'.getzilla'))


class SnapshotContractTests(unittest.TestCase):
    def contract(self):
        from getzilla import native_state_snapshot as snapshots
        return snapshots

    def test_original_bytes_and_two_updates_have_exact_logical_snapshots(self):
        s = self.contract()
        original = b'{"fixture": 0}\n  '
        first = b'{"fixture":1}\n'
        second = b'{"fixture":2}\n'
        physical = s.extend(original,first,limit=4096)
        self.assertTrue(physical.startswith(original))
        self.assertEqual(s.decode(physical,limit=4096),first)
        physical2 = s.extend(physical,second,limit=4096)
        self.assertTrue(physical2.startswith(physical))
        self.assertEqual(s.decode(physical2,limit=4096),second)
        self.assertNotEqual(hashlib.sha256(physical2).digest(),hashlib.sha256(second).digest())

    def test_corruption_uncommitted_tail_and_non_json_payload_never_select_old_state(self):
        s = self.contract()
        original = b'{"fixture":0}\n'
        complete = s.extend(original,b'{"fixture":1}\n',limit=4096)
        for damaged in (complete[:-1],complete[:-20],complete+b'{}\n',
                        complete.replace(b'"sequence":1',b'"sequence":2',1),
                        complete.replace(b'fixture',b'changed',1),
                        complete.replace(base64.b64encode(b'{"fixture":1}\n'),
                                         base64.b64encode(b'{"fixture":2}\n'),1)):
            with self.subTest(damaged=hashlib.sha256(damaged).hexdigest()):
                with self.assertRaisesRegex(ValueError,'native_state_snapshot_invalid'):
                    s.decode(damaged,limit=4096)
        for payload in (b'[]',b'{"a":1,"a":2}',b'{"a":NaN}',b'{"a":1e999}',b'not-json'):
            with self.assertRaises(ValueError):
                s.extend(original,payload,limit=4096)

    def test_prospective_physical_and_frame_caps_do_not_discard_history(self):
        s = self.contract()
        original = b'{}\n'
        first = s.extend(original,b'{"fixture":1}',limit=4096)
        with self.assertRaisesRegex(ValueError,'native_state_snapshot_limit'):
            s.extend(original,b'{"fixture":1}',limit=len(first)-1)
        current = original
        for _ in range(s.MAX_FRAMES):
            current = s.extend(current,b'{}',limit=1_048_576)
        with self.assertRaisesRegex(ValueError,'native_state_snapshot_limit'):
            s.extend(current,b'{}',limit=1_048_576)

    def test_decoder_is_allocated_only_to_closed_native_metadata_paths(self):
        s = self.contract()
        self.assertEqual(s.metadata_limit('.getzilla/runtime/routes/'+'a'*12+'.json'),1_048_576)
        self.assertEqual(s.metadata_limit('.getzilla/runtime/sessions/session-1.json'),4096)
        self.assertEqual(s.metadata_limit('.getzilla/runtime/active-change.json'),4096)
        for path in ('.getzilla/runtime/metrics.jsonl','other.json',
                     '.getzilla/runtime/routes/../active-route.json',
                     '.getzilla/runtime/routes/arbitrary.json'):
            self.assertIsNone(s.metadata_limit(path))
