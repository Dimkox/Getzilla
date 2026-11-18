"""Conservative recognition of six complete standard license texts.

These fingerprints qualify a narrow text format; they do not authenticate a
publisher or decide legal compatibility. Full terms (including disclaimers)
must match. Only whitespace/case, BSD list markers and introductory title/copyright
lines vary. Unknown variants and additional terms require human review.

Reference texts: https://github.com/spdx/license-list-data/tree/main/text
Retained source hashes and positive fixtures live in
tests/fixtures/security-license-texts.json. Updating this table needs review.
Four complete observed file variants are qualified by exact UTF-8 bytes only;
their full attribution, terms and artifact provenance are retained in
tests/fixtures/security-license-observed-variants.json.
"""
from __future__ import annotations

import hashlib
import re

_TERMS = {
    '56959050891f7b737ac4e803051170c7197f02df73d80bd9a78d968e305bf558': 'MIT',
    '948703bcf1cb4a2dafd21676dd01e40a58fe21bd9b425c000b9070eccb441092': 'Apache-2.0',
    '11cf92b65eda2f9cd73e18d3066283da5c37dd1f10edf0e3ac9889ac7634fe65': 'BSD-2-Clause',
    'f7737e83d7d22d6fcf82026dec12bd6d8a182362b207e402117edff1f58bcad4': 'BSD-3-Clause',
    'a2a686418bbdbf37f28aaf01ff3aef45cfe077a641470465923c8c23fcbe08f9': 'ISC',
    '08e6cbaeaf49ec3bb90e15e4f5a18c018eae23c7a1431f60f6a2f32306cdb707': '0BSD',
}
_TITLES = {'mit license', 'the mit license (mit)', 'isc license', 'bsd 2-clause license',
           'bsd 3-clause license', 'bsd zero clause license', 'zero-clause bsd', '0bsd'}
_REVIEWED_FILES = {
    '37db5bb85926db28a427a25867f10b1232003aea1be69ccb851138adb8e6f361': 'MIT',
    'a97ac230e5f33ef10a5367a850eb01f91f1a0b064e34742c7794d2294557f524': 'BSD-3-Clause',
    '804b59b25f2c31bd278f9202a19ae49a3945aa2664387e2d0a128c7cacc61ec3': 'MIT',
    'efe1acf3e62fb99c288b0ec73e5a773b7268ef4320fe757ea994214e4b63c371': 'BSD-3-Clause',
}


def recognized_license(text: str) -> str | None:
    """Return one qualified standard ID, or None for unknown/incomplete terms."""
    exact = _REVIEWED_FILES.get(hashlib.sha256(text.encode('utf-8')).hexdigest())
    if exact is not None:
        return exact
    lines = [line.strip() for line in text.splitlines()
             if re.fullmatch(r'\s*SPDX-License-Identifier:\s*[A-Za-z0-9][A-Za-z0-9.+:\- ()]*\s*', line) is None]
    copyrighted = False
    while lines:
        first = lines[0]
        if not first or first.casefold() in _TITLES or first.casefold() == 'all rights reserved.':
            lines.pop(0)
        elif re.fullmatch(r'(?i)copyright\s+(?:\(c\)\s*|©\s*)?[0-9]{4}(?:[0-9 ,\-]*[0-9])?,?\s+[^<>\n]{1,240}', first):
            # Copyright attribution is retained verbatim in the evidence hash.
            # A sentence introducing additional rights is not an owner field.
            if re.search(r'(?i)\b(?:license|permission|redistribution|prohibited|restriction|except)\b', first):
                return None
            copyrighted = True
            lines.pop(0)
        else:
            break
    body = re.sub(r'(?m)^\s*(?:[1-3]\.|[*-])\s+(?=(?:Redistributions|Neither)\b)', '', '\n'.join(lines))
    digest = hashlib.sha256(' '.join(body.split()).casefold().encode()).hexdigest()
    identifier = _TERMS.get(digest)
    if identifier in {'MIT', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC'} and not copyrighted:
        return None
    return identifier
