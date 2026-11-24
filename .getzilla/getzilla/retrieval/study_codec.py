"""Local o200k data adapter, called only after owned INSPECT/native admission.

Pattern/specials are literal facts from tiktoken0.12.0 openai_public.py
SHA954392738e60d0fb6dca1dad80872efc47c8e2733babecbbf0a23970ed66c2cb.
No name provider, publisher loader, cache, network or optional import occurs here.
"""
from __future__ import annotations

import base64
import binascii
from concurrent.futures import CancelledError
import re

from .budget import RetrievalError
from .contracts import sha

PATTERN = '|'.join((
    r"[^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}]*[\p{Ll}\p{Lm}\p{Lo}\p{M}]+(?i:'s|'t|'re|'ve|'m|'ll|'d)?",
    r"[^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}]+[\p{Ll}\p{Lm}\p{Lo}\p{M}]*(?i:'s|'t|'re|'ve|'m|'ll|'d)?",
    r'\p{N}{1,3}', r' ?[^\s\p{L}\p{N}]+[\r\n/]*', r'\s*[\r\n]+', r'\s+(?!\S)', r'\s+'))
PATTERN_SHA256 = sha(PATTERN.encode())
CODEC_SHA256 = '446a9538cb6c348e3516120d7c08b09f57c36495e2acfffe59a5bf8b0cfb1a2d'
CODEC_BYTES = 3613922


def parse_ranks(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= CODEC_BYTES:
        raise RetrievalError('codec_data_unavailable')
    ranks, used = {}, set()
    for line in raw.splitlines():
        if not line:  # Publisher loader ignores empty lines too.
            continue
        parts = line.split()
        if len(parts) != 2 or not re.fullmatch(b'0|[1-9][0-9]{0,5}', parts[1]):
            raise RetrievalError('codec_data_unavailable')
        try:
            token = base64.b64decode(parts[0], validate=True)
        except binascii.Error:
            raise RetrievalError('codec_data_unavailable') from None
        rank = int(parts[1])
        if (not 0 < len(token) <= 4096 or token in ranks or rank in used
                or rank >= 200000 or len(ranks) >= 200000):
            raise RetrievalError('codec_data_unavailable')
        ranks[token] = rank
        used.add(rank)
    if not ranks or used != set(range(len(ranks))):
        raise RetrievalError('codec_data_unavailable')
    return ranks


class CodecCounter:
    identity = CODEC_SHA256

    def __init__(self, module, ranks):
        if PATTERN_SHA256 != '2d1b8dc11e89af71459b36004f698ab3693f59fd84f63e8ec2b49564ab857420':
            raise RetrievalError('codec_source_mismatch')
        try:
            self._encoder = module.Encoding(name='o200k_base', pat_str=PATTERN,
                mergeable_ranks=ranks, special_tokens={'<|endoftext|>': 199999, '<|endofprompt|>': 200018})
        except Exception:
            raise RetrievalError('codec_unavailable') from None

    def count(self, text):
        if type(text) is not str or len(text.encode()) > 1048576:
            raise RetrievalError('codec_input_unavailable')
        try:
            # Preserve published encode defaults, including forbidden specials.
            return len(self._encoder.encode(text))
        except CancelledError:
            raise
        except Exception:
            raise RetrievalError('codec_unavailable') from None
