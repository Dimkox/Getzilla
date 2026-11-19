"""Fixed batch-one tokenizer data plane, instantiated only in an owned worker.

No optional imports or model loading occur here. The tokenizer/digest/end-ID are
inspected data, never execution consent or resource authority. Caller admission,
artifact custody and absolute cancellation deadlines belong to the supervisor.
"""
from __future__ import annotations

from concurrent.futures import CancelledError
from dataclasses import dataclass, field

from .budget import RetrievalError
from .contracts import hex_digest


@dataclass(frozen=True)
class EncodedOne:
    ids: tuple[int, ...] = field(repr=False)
    raw_tokens: int
    truncated: bool


class TokenizerCounter:
    def __init__(self, tokenizer, identity, *, end_token_id):
        if (not hex_digest(identity) or type(end_token_id) is not int
                or not 0 <= end_token_id < 2**31):
            raise RetrievalError('tokenizer_contract_mismatch')
        self.identity = identity
        self._tokenizer = tokenizer
        self._end = end_token_id
        try:
            tokenizer.no_padding()
            tokenizer.no_truncation()
        except CancelledError:
            raise
        except Exception:
            raise RetrievalError('tokenizer_unavailable') from None

    def _ids(self, text):
        if type(text) is not str:
            raise RetrievalError('invalid_encoder_text')
        try:
            size = len(text.encode('utf-8'))
        except UnicodeError:
            raise RetrievalError('invalid_encoder_text') from None
        if size > 65536:
            raise RetrievalError('invalid_encoder_text')
        try:
            ids = self._tokenizer.encode(text, add_special_tokens=True).ids
        except CancelledError:
            raise
        except Exception:
            raise RetrievalError('tokenizer_unavailable') from None
        if (type(ids) not in {tuple, list} or not 1 <= len(ids) <= 1048576
                or any(type(item) is not int or not 0 <= item < 2**31 for item in ids)
                or ids[-1] != self._end):
            raise RetrievalError('tokenizer_contract_mismatch')
        return ids

    def count(self, text):
        return len(self._ids(text))

    def encode_one(self, text):
        ids = self._ids(text)
        bounded = list(ids[:256])
        truncated = len(ids) > 256
        if truncated:
            bounded[-1] = self._end
        return EncodedOne(tuple(bounded), len(ids), truncated)
