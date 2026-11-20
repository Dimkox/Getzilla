import importlib
import io
import os
import unittest
from unittest.mock import patch


class StudyControllerTests(unittest.TestCase):
    def owner(self):
        try:
            return importlib.import_module('getzilla.retrieval.study_waiter_process')
        except ModuleNotFoundError:
            self.fail('independent stdlib native-child controller missing')

    def test_frame_reader_preserves_following_heartbeat_without_read_ahead_loss(self):
        owner = self.owner()
        raw = b'{"op":"tiny"}\n{"heartbeat":1}\n'
        reader = owner.FrameInput(io.BytesIO(raw))
        self.assertEqual(reader.next(10**20), {'op': 'tiny'})
        self.assertEqual(reader.next(10**20), {'heartbeat': 1})

    def test_real_inert_pipe_accepts_parent_supervised_indefinite_child_wait(self):
        owner = self.owner()
        reader, writer = os.pipe()
        try:
            os.write(writer, b'{"tiny":true}\n')
            with os.fdopen(reader, 'rb', buffering=0) as stream:
                self.assertEqual(owner.FrameInput(stream).next(float('inf')), {'tiny': True})
        finally:
            os.close(writer)

    def test_duplicate_keys_oversized_or_nonfinite_frames_refuse(self):
        owner = self.owner()
        for raw in (b'{"a":1,"a":2}\n', b'{"x":NaN}\n', b'x' * (1048576 + 1)):
            with self.subTest(prefix=raw[:16]), self.assertRaises(ValueError):
                owner.FrameInput(io.BytesIO(raw)).next(10**20)

    def test_heartbeat_cannot_renew_original_stage_or_global_deadline(self):
        owner = self.owner()
        request = {'op': 'encode', 'absolute_deadline': 900.0}
        self.assertEqual(owner.stage_deadline(request, global_deadline=1000, now=10), 12)
        request['absolute_deadline'] = 11.0
        self.assertEqual(owner.stage_deadline(request, global_deadline=1000, now=10), 11)
        self.assertEqual(owner.stage_deadline(request, global_deadline=10.5, now=10), 10.5)
        for value in (float('nan'), True):
            with self.assertRaises(ValueError):
                owner.stage_deadline({**request, 'absolute_deadline': value},
                                     global_deadline=1000, now=10)

    def test_heartbeat_is_only_liveness_on_the_owned_sequence_channel(self):
        owner = self.owner()
        nonce = 'a' * 64
        self.assertTrue(owner.heartbeat({'nonce': nonce, 'heartbeat': 3}, nonce, 3))
        for request in ({'nonce': 'b' * 64, 'heartbeat': 3},
                        {'nonce': nonce, 'heartbeat': 2},
                        {'nonce': nonce, 'heartbeat': 3, 'allow_execution': True}):
            self.assertFalse(owner.heartbeat(request, nonce, 3))

    def test_expired_deadline_cannot_create_even_a_waiting_child(self):
        owner = self.owner()
        native = owner.NativeProcess('a' * 64, 0)
        with patch.object(native, '_start', side_effect=AssertionError('spawn after expiry')) as start:
            with self.assertRaisesRegex(ValueError, 'native deadline'):
                native.request({'op': 'encode', 'sequence': 1, 'absolute_deadline': 0},
                               owner.FrameInput(io.BytesIO()))
            start.assert_not_called()
