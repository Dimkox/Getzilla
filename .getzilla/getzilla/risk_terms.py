"""Risk vocabulary: an English base plus language packs that agents translate from it.

`.getzilla/config/risk-terms/en.json` is the base: term ids, their category (high or medium) and
English terms. Every other `<lang>.json` maps the same ids to terms in its language. Packs are
plain data, so an agent adds a language with `getzilla risk-terms scaffold --lang <code>` and
`getzilla risk-terms check`. Prompts written mostly in a script no pack covers are reported, so
the router never calls a prompt it cannot read "low risk".
"""
from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping

SCHEMA = 'risk-terms-v1'
DEFAULT_DIR = Path(__file__).resolve().parents[1] / 'config' / 'risk-terms'
CATEGORIES = ('high', 'medium')
TOKEN = re.compile(r'^[^\s*]+\*?$')
UNCOVERED_SHARE = 0.3
MIN_LETTERS = 3


class RiskTermsError(ValueError):
    pass


@dataclass(frozen=True)
class RiskVocabulary:
    high: tuple[str, ...]
    medium: tuple[str, ...]
    scripts: frozenset[str]
    languages: tuple[str, ...]
    term_ids: Mapping[str, str]  # term -> id, for rationale


def _check_term(term: Any, where: str) -> str:
    if not isinstance(term, str) or not term.strip() or term != term.strip():
        raise RiskTermsError(f'{where}: empty or padded term')
    if not all(TOKEN.fullmatch(token) for token in term.split()):
        raise RiskTermsError(f'{where}: "*" is allowed only at the end of a word: {term!r}')
    return term


def load_pack(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding='utf-8'))
    if data.get('schema_version') != SCHEMA or not isinstance(data.get('terms'), dict):
        raise RiskTermsError(f'{path.name}: not a {SCHEMA} pack')
    if not isinstance(data.get('lang'), str) or not isinstance(data.get('script'), str):
        raise RiskTermsError(f'{path.name}: lang and script are required')
    return data


def check_packs(directory: Path = DEFAULT_DIR) -> list[str]:
    """Problems with the base and every pack; an empty list means the vocabulary is complete."""
    problems: list[str] = []
    try:
        base = load_pack(directory / 'en.json')
    except (OSError, ValueError) as error:
        return [f'en.json: {error}']
    if not base.get('base'):
        problems.append('en.json: must be the base pack')
    required = set()
    for term_id, entry in base['terms'].items():
        if not isinstance(entry, dict) or entry.get('category') not in CATEGORIES:
            problems.append(f'en.json:{term_id}: category must be high or medium')
            continue
        try:
            for term in entry.get('terms') or []:
                _check_term(term, f'en.json:{term_id}')
        except RiskTermsError as error:
            problems.append(str(error))
        if not entry.get('terms'):
            problems.append(f'en.json:{term_id}: no terms')
        if not entry.get('neutral'):
            required.add(term_id)
    for path in sorted(directory.glob('*.json')):
        if path.name == 'en.json':
            continue
        try:
            pack = load_pack(path)
        except (OSError, ValueError) as error:
            problems.append(f'{path.name}: {error}')
            continue
        if pack.get('lang') != path.stem:
            problems.append(f'{path.name}: lang must equal the file name')
        unknown = set(pack['terms']) - set(base['terms'])
        problems.extend(f'{path.name}:{term_id}: not a base term id' for term_id in sorted(unknown))
        for term_id in sorted(required):
            terms = pack['terms'].get(term_id)
            if not terms:
                problems.append(f'{path.name}:{term_id}: missing translation')
                continue
            for term in terms:
                try:
                    _check_term(term, f'{path.name}:{term_id}')
                except RiskTermsError as error:
                    problems.append(str(error))
    return problems


@lru_cache(maxsize=8)
def load_vocabulary(directory: Path = DEFAULT_DIR) -> RiskVocabulary:
    problems = check_packs(directory)
    if problems:
        raise RiskTermsError('; '.join(problems[:5]))
    base = load_pack(directory / 'en.json')
    high: list[str] = []
    medium: list[str] = []
    term_ids: dict[str, str] = {}
    scripts = {base['script']}
    languages = ['en']

    def add(term_id: str, terms: list[str]) -> None:
        target = high if base['terms'][term_id]['category'] == 'high' else medium
        for term in terms:
            if term not in term_ids:
                term_ids[term] = term_id
                target.append(term)

    for term_id, entry in base['terms'].items():
        add(term_id, entry['terms'])
    for path in sorted(directory.glob('*.json')):
        if path.name == 'en.json':
            continue
        pack = load_pack(path)
        scripts.add(pack['script'])
        languages.append(pack['lang'])
        for term_id, terms in pack['terms'].items():
            add(term_id, terms)
    return RiskVocabulary(tuple(high), tuple(medium), frozenset(scripts), tuple(languages), term_ids)


def letter_scripts(text: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for char in text:
        if char.isalpha():
            name = unicodedata.name(char, '')
            script = name.split(' ')[0] if name else 'UNKNOWN'
            counts[script] = counts.get(script, 0) + 1
    return counts


def uncovered_script(text: str, vocabulary: RiskVocabulary) -> str | None:
    """The dominant letter script of `text` when no pack covers it, else None.

    Only the script is detectable without a language model: a Latin-script prompt in a language
    without a pack is not flagged here; the exact-head diff risk covers it.
    """
    counts = letter_scripts(text)
    total = sum(counts.values())
    if total < MIN_LETTERS:
        return None
    for script, count in sorted(counts.items(), key=lambda item: -item[1]):
        if script not in vocabulary.scripts and count / total >= UNCOVERED_SHARE:
            return script
    return None


def scaffold(lang: str, script: str, directory: Path = DEFAULT_DIR) -> dict[str, Any]:
    """A pack skeleton for an agent to translate: every non-neutral id with English hints."""
    if not re.fullmatch(r'[a-z]{2,3}(-[A-Za-z0-9]{2,8})?', lang) or lang == 'en':
        raise RiskTermsError('lang must be a language code other than en (for example de, zh, pt-BR)')
    base = load_pack(directory / 'en.json')
    return {'schema_version': SCHEMA, 'lang': lang, 'script': script.upper(), 'base': False, 'translated_from': 'en',
            'instructions': ('Translate every hint into the terms a user of this language would write. Use a trailing '
                             '"*" for word stems. Keep the meaning, not the literal words. Then remove "hints" and run '
                             'getzilla risk-terms check.'),
            'hints': {term_id: entry['terms'] for term_id, entry in base['terms'].items() if not entry.get('neutral')},
            'terms': {term_id: [] for term_id, entry in base['terms'].items() if not entry.get('neutral')}}
