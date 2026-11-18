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
Six further exact complete files and four ancillary files are retained in the
security-license-frontier fixtures. Ancillary matches grant no full-term credit;
the consumer must bind their expression and independently verify every named
sibling's exact bytes and complete terms.
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
    '09e8a9bcec8067104652c168685ab0931e7868f9c8284b66f5ae6edae5f1130b': 'Apache-2.0',
    '0d542e0c8804e39aa7f37eb00da5a762149dc682d7829451287e11b938e94594': 'Apache-2.0',
    'aac73b3148f6d1d7111dbca32099f68d26c644c6813ae1e4f05f6579aa2663fe': 'Apache-2.0',
    '602c4c7482de6479dd2e9793cda275e5e63d773dacd1eca689232ab7008fb4fb': 'BSD-3-Clause',
    '0a9e78156ae8b96caf1b4f11ac2df424b83de29736f9e757630548a6272fdf90': 'BSD-3-Clause',
    '835586ae156766a24e3c103fbc55d9af6b1a16df57ca932c97482a2737fd83d5': 'MIT',
}
_ANCILLARY_FILES = {
    '3e0c7c091a948b82533ba98fd7cbb40432d6f1a9acbf85f5922d2f99a93ae6bb': (
        'license-declaration', 'Apache-2.0 OR BSD-3-Clause', (
            ('LICENSE.APACHE', 'aac73b3148f6d1d7111dbca32099f68d26c644c6813ae1e4f05f6579aa2663fe'),
            ('LICENSE.BSD', '602c4c7482de6479dd2e9793cda275e5e63d773dacd1eca689232ab7008fb4fb'))),
    '80e177ab397d5f332954693a52abc1b34b06c5792dd57297608b6d68a2f6af11': (
        'attribution', 'Apache-2.0', (
            ('LICENSE.txt', '0d542e0c8804e39aa7f37eb00da5a762149dc682d7829451287e11b938e94594'),)),
    'd7390c793c73c36265497ffac90a886a235c8b50948454c9af98f1aef2a00d2a': (
        'attribution', 'MIT', (
            ('LICENSE', '835586ae156766a24e3c103fbc55d9af6b1a16df57ca932c97482a2737fd83d5'),)),
    'df58f69ea88683035d720b5375bcef0cf5aeaa98a1d098d572e0992c378deb46': (
        'attribution', 'Apache-2.0', (
            ('licenses/LICENSE_APACHE', 'c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4'),)),
}


def reviewed_ancillary(text: str) -> dict | None:
    """Return exact-file retention requirements, never complete license credit.

    Resolve required_files relative to this file's parent. The consumer must
    match the current expression and verify each exact sibling's complete terms.
    """
    value = _ANCILLARY_FILES.get(hashlib.sha256(text.encode('utf-8')).hexdigest())
    if value is None:
        return None
    kind, expression, required = value
    return {'kind': kind, 'expression': expression, 'required_files': dict(required)}


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
