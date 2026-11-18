"""Conservative recognition of six complete standard license texts.

These fingerprints qualify a narrow text format; they do not authenticate a
publisher or decide legal compatibility. Full terms (including disclaimers)
must match. Only whitespace/case, BSD list markers and introductory title/copyright
lines vary. Unknown variants and additional terms require human review.

Reference texts: https://github.com/spdx/license-list-data/tree/main/text
Retained source hashes and positive fixtures live in
tests/fixtures/security-license-texts.json. Updating this table needs review.
Complete observed file variants are qualified by exact UTF-8 bytes only;
their full attribution, terms and artifact provenance are retained in
tests/fixtures/security-license-observed-variants.json.
Six further exact complete files and four ancillary files are retained in the
security-license-frontier fixtures. Ancillary matches grant no full-term credit;
the consumer must bind their expression and independently verify every named
sibling's exact bytes and complete terms.
The finite NPM complete-file table, source attribution and review-required gaps
are retained in tests/fixtures/security-license-npm-complete-files.json.
Its README container entry matches only that entire reviewed file.
Exact multi-grant bundles and two complete ownerless MIT files are retained in
tests/fixtures/security-license-npm-bundles.json. Identification does not
authenticate a publisher or supply missing copyright attribution.
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
    'a338a09e00418402e779e3ff372a2bca3be66259d6192e0a9fe2949969d648f3': 'MIT',
    '4ec3d4c66cd87f5c8d8ad911b10f99bf27cb00cdfcff82621956e379186b016b': 'ISC',
    '304e4a73f6212adaf242c78fcbe1dfcebd78d8bab53b007fe69b39fc968292b7': 'MIT',
    '511ea01f49c4e15572d1a0dbef3c10f3e26425be79df7ef599c3b65f9bf55281': 'MIT',
    '1a66adbb5a45806b7fe0b5ff3e78008b57e660f30e688286c0f16a6991f10fd1': 'MIT',
    '8cd41c03a45ebf957a00d335d9dfab638b7ddba797a7d2f23bc1c4157a50db72': 'MIT',
    'ea5a8caa168f387ef2ccac8d7eea12d3be7e2e70a8b7125b68dbc8d1e7fa1998': 'Apache-2.0',
    '257aed98914108e91a337912727b6a802eef218248507f74b76faffaff517a38': 'MIT',
    'a6db8096b2707bc0102d256917d4d33f298ba36d8c3f25de067a2b5bb379db27': 'MIT',
    'b9b3eeac9f4ae8ae50773f318ac29f2052bbf08ee33fb6bb024d90d86c7492d2': 'ISC',
    'da16ddb65f8ca390998fb99223d0112498b56b45784d00afd77ff8ce1ac4de8b': '0BSD',
    '210b19e543130388c68654b7497e967119ce17145f66ab7d85688fbd70f08751': '0BSD',
    'd06b5d27bbbbe22c36b1fd88406b1208876e2d37d795f5b8eaed951a459a3111': 'MIT',
    '5c932d88256b4ab958f64a856fa48e8bd1f55bc1d96b8149c65689e0c61789d3': 'MIT',
    '91fd2d025ca697f02becd68acaabc6373fa853a04c4f7543b306e830d3ed6b36': 'MIT',
    '5e3400b93bbb099e83e52bab885e7441750673c21f97988ca3f1240639b63283': 'Apache-2.0',
    'a7d00bfd54525bc694b6e32f64c7ebcf5e6b7ae3657be5cc12767bce74654a47': 'Apache-2.0',
    'dea9265341829002e2c23a7372393eb2ed6e26085fb623f38a4ba0af833f30a6': 'MIT',
    'c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383': 'MIT',
    '48da2f39e100d4085767e94966b43f4fa95ff6a0698fba57ed460914e35f94a0': 'MIT',
    'cdbc258d13806538e727964c2436a8806e6e2496ccd616224aace6f7bf98dbc1': 'ISC',
    'a1bd5deadb6a06dd74efa852c1b8b23f63b67f2214fbe9c8bd591da51da69268': 'MIT',
    '68f12f6e2c33688699249c01d8f9623c534da20aa71989c57b061b7bc1676d14': 'MIT',
    '06bafa45fdad2579ba0e43b0c9b2c6290287c99c4203c300254a462b38a307f6': 'MIT',
    'ddc9158fa20e427bc12fa8e1e6d07c642ed4d2c618607df768b30ae2986b3b7c': 'MIT',
    '47eb8ca82c798246774946d1be0f9aa08f025fa8325ced0947aeeb4c05fe5547': 'MIT',
    '33b734d60042d0fe0c92dd1fc1e874193a1c899ec3e276a2eb935d2d0bf5b710': 'MIT',
    'c542ba7851b5d39a5face477e47a27cb7c00a9759e321b66824e79718bffe1ac': 'Apache-2.0',
    'aaa78451b6fecd1b9c4594c796c133c0e90cad100372ff8bc6de615e9ef9adf1': 'MIT',
    'bfa751427053e9f0e4f2af1e62862681cdd45000db8d8db753baf7d462cb1a08': 'ISC',
    '483acb265f182907d1caf6cff9c16c96f31325ed23792832cc5d8b12d5f88c8a': 'MIT',
    '631987b7616a325a5b97566c232418481ddf7dbb5ecadefb991e791876cc2599': 'MIT',
    '93f5d82a8d59442fe3275383453a255fef761647fb28265644010ba799806148': 'ISC',
    'b173e19b9a78df305577ace0e52ef45a4bcc915ea28b47b256dc3b68dcb1f7e7': 'ISC',
    'f65c5d9f22a317b2a10803bd1868461ce6499c2ed7217bc80c0cc772a748789c': 'ISC',
    '5ffe28e7ade7d8f10d85d5337a73fd793dac5c462fb9a28fbf8c5046c7fbca3b': 'ISC',
    '2144eb6894cb440fde6b2b3aaae3b617c8f1dc9bb19813079dcf62ec6c517042': 'MIT',
    'c7cc929b57080f4b9d0c6cf57669f0463fc5b39906344dfc8d3bc43426b30eac': 'MIT',
    'cc1dfd4dafa27271e8212cd3b274eeb3f262e40a6fdab36ddc3f9696f706f58b': 'MIT',
    '71f83c4c0621102a56d9853812777b85751bce7e9726f686f5b056c1f8a4b0e6': 'MIT',
    'd11323827fa4edeaafc437cc5b91b6971b335f0127efeeb42bf5122fe8657e8f': 'ISC',
    '833faa18ac4b83a6372c05b3643d0d44ecd27d6627b8cd19b0f48fe74260cf39': 'ISC',
    '05991c2e8f070b69ec5b656c2c12fd07cd0153dd157d39b050b82af59b319a01': 'MIT',
    '451ec07eeb9c4e1b86de9abdaa426462a8be48f887ec7421cf0bbb9c769555ab': 'ISC',
    '59a400d04c5078579acc27ddd6452c1bdf763f9506e01364700935fbb1a7c91b': 'MIT',
    'ecdccbcf39024f624ded480c01c0b25458e1eca8f26ecf040933865ce56d9a4f': 'MIT',
    '8cd23e2d76d2791765f7dd1025a9df99d81db91da9e2701f283987a1c0435aa3': 'Apache-2.0',
    '69dee148a2cc470554dfa7142e830662062394d0fe67cddd379aba90dc60d6b3': 'MIT',
    '309dff61c243e706fac25101a9bdb585f7e2db45e32915b08cf47518d2075863': 'MIT',
    'b7ad8777cf2eaca832498a2bd34fca0a5bde02d74158fa6c24ab4596d4f73a25': 'ISC',
    '0154425673db15cdfa80ecba2c9b1f1a867f7197a006764712849bfc3a93cbb7': 'MIT',
    'a889cc4dbee2ae172c179856b25d75b0b7a5a136e1b97109b9b590b2ff1a879c': 'BSD-2-Clause',
    '6b7a1792144374d84dc5ed3655b8bbe2754d06f4f1f64a9fb8b9de2d6f448b85': 'MIT',
    '693866fc419c6f61c8570438ec00659d156ec2b4d4a4d04091711f5f11a365d4': 'MIT',
    '7c77a44a8acd9b41fdc209864a8016b3d430b5d0e09309818d5b7444336df744': 'MIT',
    'd408f38ffa3355c5faec517153295338892eb0f1ea43f57874bb23c6075979b5': 'MIT',
    '9c63a23124d68cd30cd316a94a1a0bca34f032786df6df69fc4b5f136bac8d2e': 'MIT',
    '3a61c6c96caf5c1d9b623fb9b04c822b783dfcb78aa7e49c76a3f643e6ed7f95': 'MIT',
    'd49ce1d45d3503ffb27bcec6f8b15499065cb306553b3f1db39611f200e6f471': 'MIT',
    'fa5659948374d4f555594f47f6da073b40dc503e921aeeece30df4362b3051a5': 'BSD-3-Clause',
    'd4dc58571be1260e45f2fb8ab174e0a838c9ca361720e1b0e2ca020c037988b2': 'ISC',
    '0cec06e0e55fbc3dc5cee4fca9b607f66cb8f4e4dbcf3b3c013594dd156732e9': 'Apache-2.0',
    'b70e7e9b742f1cc6f948b34c16aa39ffece94196364bc88ff0d2180f0028fac5': 'BSD-2-Clause',
    'ff138e683771b187f3629c383db72ee7d632009010a36d08e18e8d2a34222ec7': 'MIT',
    '435a6722c786b0a56fbe7387028f1d9d3f3a2d0fb615bb8fee118727c3f59b7b': 'MIT',
    '75486ea0af9309140ca6e2c401d7e67bea8f4892344e5707f6394dc5e83dfc44': 'MIT',
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


# Each tuple identifies all complete grants in one retained whole-file body.
# IDs are deduplicated; the original file retains every attribution and grant.
_REVIEWED_BUNDLES = {
    'ec62dc96da0099b87f4511736c87309335527fb7031639493e06c95728dc8c54': ('MIT',),
    '11f2aafb37d06b3ee5bdaf06e9811141d0da05263c316f3d627f45c20d43261b': ('MIT',),
    '12b06934bd437fee7b52583c0b1062181957363f4f520dd7a5305362f3c9e6e6': ('ISC', 'MIT'),
}


def recognized_license_bundle(text: str) -> tuple[str, ...] | None:
    """Identify an exact reviewed multi-grant file, never infer an SPDX branch.

    Return every distinct existing license ID present in the complete file.
    The caller must retain all original bytes and separately check its SPDX
    expression and policy. Unknown or altered containers return None.
    Single-license files use recognized_license; that API remains unchanged.
    """
    return _REVIEWED_BUNDLES.get(hashlib.sha256(text.encode('utf-8')).hexdigest())


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
