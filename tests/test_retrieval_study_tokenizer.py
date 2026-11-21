import importlib
from types import SimpleNamespace
import unittest


class TinyTokenizer:
    def __init__(self):
        self.padding_disabled = False
        self.truncation_disabled = False

    def no_padding(self):
        self.padding_disabled = True

    def no_truncation(self):
        self.truncation_disabled = True

    def encode(self, text, *, add_special_tokens):
        assert add_special_tokens is True
        return SimpleNamespace(ids=[101] + [3] * len(text) + [102])


class StudyTokenizerTests(unittest.TestCase):
    def owner(self):
        try:
            return importlib.import_module('getzilla.retrieval.study_tokenizer')
        except ModuleNotFoundError:
            self.fail('fixed tokenizer data-plane adapter is missing')

    def test_specials_are_counted_and_actual_final_special_is_preserved(self):
        native = TinyTokenizer()
        counter = self.owner().TokenizerCounter(native, 'a' * 64, end_token_id=102)
        self.assertTrue(native.padding_disabled and native.truncation_disabled)
        self.assertEqual(counter.count('x' * 254), 256)
        self.assertEqual(counter.count('x' * 255), 257)
        encoded = counter.encode_one('x' * 255)
        self.assertEqual(len(encoded.ids), 256)
        self.assertEqual(encoded.ids[-1], 102)
        self.assertTrue(encoded.truncated)
        self.assertEqual(encoded.raw_tokens, 257)

    def test_no_truncation_at_exact_256_and_no_batch_padding(self):
        counter = self.owner().TokenizerCounter(TinyTokenizer(), 'a' * 64, end_token_id=102)
        row = counter.encode_one('x' * 254)
        self.assertEqual(row.ids, (101,) + (3,) * 254 + (102,))
        self.assertFalse(row.truncated)

    def test_unknown_id_special_or_error_is_unavailable_without_fallback(self):
        owner = self.owner()
        class Bad(TinyTokenizer):
            def encode(self, text, *, add_special_tokens):
                return SimpleNamespace(ids=[1, True, 2])
        with self.assertRaisesRegex(ValueError, 'tokenizer_contract_mismatch'):
            owner.TokenizerCounter(Bad(), 'a' * 64, end_token_id=2).encode_one('tiny')

    def test_bad_text_or_unbounded_worker_input_refuses_before_tokenizer(self):
        owner = self.owner()
        counter = owner.TokenizerCounter(TinyTokenizer(), 'a' * 64, end_token_id=102)
        for text in (b'bytes', 'x' * 65537, '\ud800'):
            with self.subTest(text_type=type(text)), self.assertRaises(ValueError):
                counter.encode_one(text)
