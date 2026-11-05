"""Trusted producer/reader diagnostics never grant publication authority."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.publication_metadata import metadata_snapshot, mark_publication_unknown  # noqa: E402


class PublicationMetadataTests(unittest.TestCase):
    def test_native_storage_install_bypasses_supported_subclass_descriptors(self):
        hooks = []

        class Hostile(BaseException):
            __slots__ = ('user_slot',)

            @property
            def __dict__(self):
                hooks.append('dictionary')
                raise AssertionError('PRIVATE_DICT')

            @property
            def publication_state(self):
                hooks.append('flag')
                raise AssertionError('PRIVATE_FLAG')

            @property
            def __notes__(self):
                hooks.append('notes')
                raise AssertionError('PRIVATE_NOTES')

            def __setattr__(self, name, value):
                hooks.append('setter')
                raise AssertionError('PRIVATE_SETTER')

        for error in (Hostile('PRIVATE_ORIGINAL'), SystemExit(37), KeyboardInterrupt('PRIVATE_INTERRUPT')):
            with self.subTest(kind=type(error).__name__):
                cause, context, userdata = ValueError('cause'), ValueError('context'), object()
                BaseException.__dict__['__cause__'].__set__(error, cause)
                BaseException.__dict__['__context__'].__set__(error, context)
                BaseException.__dict__['__dict__'].__set__(error, {'user_data': userdata, '__notes__': ['existing']})
                if type(error) is Hostile:
                    Hostile.__dict__['user_slot'].__set__(error, userdata)
                args = BaseException.__dict__['args'].__get__(error, BaseException)
                try:
                    mark_publication_unknown(error)
                except BaseException:
                    self.fail('native annotation invoked a subtype hook or failed')
                actual = dict(metadata_snapshot(error))
                self.assertIn('publication_state', actual)
                self.assertEqual(actual['publication_state'], 'unknown')
                self.assertIs(actual['user_data'], userdata)
                self.assertEqual(actual['__notes__'][0], 'existing')
                self.assertIn('PUBLICATION_CUSTODY_UNKNOWN', actual['__notes__'][-1])
                self.assertIs(BaseException.__dict__['__cause__'].__get__(error, BaseException), cause)
                self.assertIs(BaseException.__dict__['__context__'].__get__(error, BaseException), context)
                self.assertEqual(BaseException.__dict__['args'].__get__(error, BaseException), args)
                if type(error) is Hostile:
                    self.assertIs(Hostile.__dict__['user_slot'].__get__(error, Hostile), userdata)
                if type(error) is SystemExit:
                    self.assertEqual(SystemExit.__dict__['code'].__get__(error, SystemExit), 37)
        self.assertEqual(hooks, [])

    def test_owned_tuple_does_not_follow_live_dictionary_replacement(self):
        error = ValueError('PRIVATE_ORIGINAL')
        error.user_data = object()
        shared = error.__dict__
        snapshot = metadata_snapshot(error)
        self.assertIs(type(snapshot), tuple)
        shared.clear()
        shared['foreign'] = 'new value'
        self.assertEqual(tuple(key for key, value in snapshot), ('user_data',))
        self.assertNotEqual(snapshot, metadata_snapshot(error))

    def test_snapshot_bound_and_builtin_dictionary_operations(self):
        hooks = []

        class Map(dict):
            def items(self):
                hooks.append('items')
                raise AssertionError('PRIVATE_ITEMS')

            def __iter__(self):
                hooks.append('iterator')
                raise AssertionError('PRIVATE_ITERATOR')

            def __len__(self):
                hooks.append('length')
                raise AssertionError('PRIVATE_LENGTH')

        error = ValueError('PRIVATE_ORIGINAL')
        error.__dict__ = Map({str(i): None for i in range(10000)})
        snapshot = metadata_snapshot(error)
        self.assertIsNotNone(snapshot)
        self.assertEqual(len(snapshot), 65)
        self.assertEqual(hooks, [])
        mark_publication_unknown(error)
        self.assertEqual(set(dict(metadata_snapshot(error))), {'publication_state', '__notes__'})

    def test_malformed_namespace_annotation_avoids_foreign_hash_and_equality(self):
        hooks = []

        class Key(str):
            armed = False

            def __hash__(self):
                if self.armed:
                    hooks.append('hash')
                    raise AssertionError('PRIVATE_HASH')
                return str.__hash__(self)

            def __eq__(self, other):
                hooks.append('equality')
                raise AssertionError('PRIVATE_EQUALITY')

        key = Key('publication_state')
        error = ValueError('PRIVATE_ORIGINAL')
        error.__dict__ = {key: 'ordinary'}
        key.armed = True
        mark_publication_unknown(error)
        self.assertEqual(dict(metadata_snapshot(error))['publication_state'], 'unknown')
        self.assertEqual(hooks, [])

    def test_notes_copy_is_bounded_and_never_formats_foreign_values(self):
        class PrivateValue:
            def __str__(self):
                raise AssertionError('PRIVATE_STRING')

        error = ValueError('PRIVATE_ORIGINAL')
        error.__notes__ = ['safe', PrivateValue()] + ['extra'] * 10000
        mark_publication_unknown(error)
        notes = dict(metadata_snapshot(error))['__notes__']
        self.assertEqual(notes[0], 'safe')
        self.assertLessEqual(len(notes), 65)
        self.assertTrue(all(type(note) is str for note in notes))

    def test_actual_installer_payloads_ship_the_shared_helper(self):
        from tests.test_installer import MODULE as installer
        relative = '.getzilla/getzilla/publication_metadata.py'
        for selection in (None, installer.PayloadSelection(('codex',))):
            payload = installer.build_payload(ROOT, selection=selection)
            entries = {entry.path: entry for entry in payload}
            self.assertEqual(entries[relative].content, (ROOT / relative).read_bytes())
            self.assertEqual(entries[relative].mode, 0o644)
            self.assertFalse(any('/runtime/skill-intake/' in name for name in entries))
