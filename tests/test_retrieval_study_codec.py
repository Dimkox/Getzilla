import importlib
from types import SimpleNamespace
import unittest
from unittest.mock import Mock


class StudyCodecTests(unittest.TestCase):
    def owner(self):
        try:
            return importlib.import_module('getzilla.retrieval.study_codec')
        except ModuleNotFoundError:
            self.fail('fixed local codec adapter missing')

    def test_tiny_parser_decodes_bytes_without_provider_or_native_import(self):
        self.assertEqual(self.owner().parse_ranks(b'YQ== 0\nYg== 1\n'), {b'a': 0, b'b': 1})

    def test_duplicate_rank_token_invalid_base64_and_gap_refuse(self):
        owner = self.owner()
        for raw in (b'YQ== 0\nYQ== 1\n', b'YQ== 0\nYg== 0\n', b'@@ 0\n',
                    b'YQ== 1\n', b'YQ== 00\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                owner.parse_ranks(raw)

    def test_source_pattern_and_special_defaults_are_preserved(self):
        owner = self.owner()
        encoder = Mock()
        encoder.encode.return_value = [1, 2]
        constructor = Mock(return_value=encoder)
        counter = owner.CodecCounter(SimpleNamespace(Encoding=constructor), {b'a': 0})
        self.assertEqual(counter.count('complete citation'), 2)
        encoder.encode.assert_called_once_with('complete citation')
        kwargs = constructor.call_args.kwargs
        self.assertEqual(set(kwargs), {'name', 'pat_str', 'mergeable_ranks', 'special_tokens'})
        self.assertEqual(kwargs['special_tokens'], {'<|endoftext|>': 199999, '<|endofprompt|>': 200018})
        self.assertEqual(owner.PATTERN_SHA256, '2d1b8dc11e89af71459b36004f698ab3693f59fd84f63e8ec2b49564ab857420')
