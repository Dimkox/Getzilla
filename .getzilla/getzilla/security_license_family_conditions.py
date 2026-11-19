"""Finite internal-CI component conditions, separate from the six global IDs.

Caller must first verify immutable family/source bytes and actual selected use.
These profiles discharge only the extra-ID policy condition. Completeness,
native/source requirements, age, notices and retained custody remain mandatory.
"""
from __future__ import annotations

# Complete original bytes and immutable source identities are retained in
# tests/fixtures/security-license-internal-family-conditions.json.
TEXTS = {'26be8a79415737dfe8edf1be62e71afeb8c770ed5a5605a06270d5701830f47c': ('BSD-3-Clause',),
 '28ca54ff46a27183631aa262673d13e3c829d909059f5c861da835fe1783fbec': ('MPL-2.0',),
 '2ba4d89aab98b9f2fb760a8fe7d05ed1c7d06be44c79f1ceb02cf9ce6e61c9a8': ('MPL-2.0',),
 '3325702108f9d65db464595854e509f2a1be9ffdc1ae82a7e99fa63c92c404c9': ('MIT',),
 '3f3d9e0024b1921b067d6f7f88deb4a60cbe7a78e76c64e3f1d7fc3b779b9d04': ('MPL-2.0',),
 '60222c28c1a7f6a92c7df98e5c5f4459e624e6e285e0b9b94467af5f6ab3343d': ('MPL-2.0',),
 '6c7088eb877b5d7e6e0e9d27e822ea25fcda2e83f9eba59bb5f1418a656796e0': ('MPL-2.0',),
 '6d462371baa8649492b06f51f154dba9b25d2ac9548369b8b4fdbbbb85f2f75d': ('BSD-3-Clause',),
 '83e36e42b3dacc3d447eca3049848b3e2ff66b6e1768a6a3cf3f27a57079bda4': ('BSD-3-Clause', 'MPL-2.0'),
 '87b250b11ffadc5f872cb676caa219e2871e454ddd562d9e532d52d5c9b7520d': ('MPL-2.0',),
 '8b7975e73de4ffd999102c9d599070b02e8b3146f14184ab66588fb27c660bd8': ('X11',),
 '91b6643919df970f0968799615888a2620300dc32bb515d7bd3764ad72c282ca': ('MPL-2.0',),
 'a830016911a348a54e89bd54f2f8b0d8fffdeac20aecfba8e36ebbf38a03f5ff': ('MPL-2.0',),
 'b31266a0a4ade23e6c0cb5a6ae1c7933b390f30b80550a715579989639b4f55e': ('MPL-2.0',),
 'bef1747eda88b9ed46e94830b0d978c3499dad5dfe38d364971760881901dadd': ('MPL-2.0',),
 'd6b1a865f1c8c697d343bd4e0ce61025f91898486a1f00d727f32e8644af77d3': ('MPL-2.0',)}

PROFILES = [{'artifact_sha256': '2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a',
  'component_id': 'go-module:github.com/cyphar/filepath-securejoin@v0.6.1',
  'expression': 'BSD-3-Clause AND MPL-2.0',
  'terms': {'COPYING.md': '83e36e42b3dacc3d447eca3049848b3e2ff66b6e1768a6a3cf3f27a57079bda4',
            'LICENSE.BSD': '26be8a79415737dfe8edf1be62e71afeb8c770ed5a5605a06270d5701830f47c',
            'LICENSE.MPL-2.0': '3f3d9e0024b1921b067d6f7f88deb4a60cbe7a78e76c64e3f1d7fc3b779b9d04'},
  'source_h1': 'h1:5CeZ1jPXEiYt3+Z6zqprSAgSWiggmpVyciv8syjIpVE='},
 {'artifact_sha256': '2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a',
  'component_id': 'go-module:github.com/hashicorp/aws-sdk-go-base/v2@v2.0.0-beta.72',
  'expression': 'MPL-2.0',
  'terms': {'LICENSE': '2ba4d89aab98b9f2fb760a8fe7d05ed1c7d06be44c79f1ceb02cf9ce6e61c9a8'},
  'source_h1': 'h1:vTCWu1wbdYo7PEZFem/rlr01+Un+wwVmI7wiegFdRLk='},
 {'artifact_sha256': '2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a',
  'component_id': 'go-module:github.com/hashicorp/errwrap@v1.1.0',
  'expression': 'MPL-2.0',
  'terms': {'LICENSE': 'bef1747eda88b9ed46e94830b0d978c3499dad5dfe38d364971760881901dadd'},
  'source_h1': 'h1:OxrOeh75EUXMY8TBjag2fzXGZ40LB6IKw45YeGUDY2I='},
 {'artifact_sha256': '37b3befbed28fb72a44d72bf42362c268610386c42feafa27cb45ee0b531369c',
  'component_id': 'go-module:github.com/hashicorp/go-cleanhttp@v0.5.2',
  'expression': 'MPL-2.0',
  'terms': {'LICENSE': '60222c28c1a7f6a92c7df98e5c5f4459e624e6e285e0b9b94467af5f6ab3343d'},
  'source_h1': 'h1:035FKYIWjmULyFRBKPs8TBQoi0x6d9G4xc9neXJWAZQ='},
 {'artifact_sha256': '2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a',
  'component_id': 'go-module:github.com/hashicorp/go-cleanhttp@v0.5.2',
  'expression': 'MPL-2.0',
  'terms': {'LICENSE': '60222c28c1a7f6a92c7df98e5c5f4459e624e6e285e0b9b94467af5f6ab3343d'},
  'source_h1': 'h1:035FKYIWjmULyFRBKPs8TBQoi0x6d9G4xc9neXJWAZQ='},
 {'artifact_sha256': '2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a',
  'component_id': 'go-module:github.com/hashicorp/go-getter@v1.8.6',
  'expression': 'MPL-2.0',
  'terms': {'LICENSE': '91b6643919df970f0968799615888a2620300dc32bb515d7bd3764ad72c282ca'},
  'source_h1': 'h1:9sQboWULaydVphxc4S64oAI4YqpuCk7nPmvbk131ebY='},
 {'artifact_sha256': '2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a',
  'component_id': 'go-module:github.com/hashicorp/go-multierror@v1.1.1',
  'expression': 'MPL-2.0',
  'terms': {'LICENSE': 'a830016911a348a54e89bd54f2f8b0d8fffdeac20aecfba8e36ebbf38a03f5ff'},
  'source_h1': 'h1:H5DkEtf6CXdFp0N0Em5UCwQpXMWke8IA0+lD48awMYo='},
 {'artifact_sha256': '37b3befbed28fb72a44d72bf42362c268610386c42feafa27cb45ee0b531369c',
  'component_id': 'go-module:github.com/hashicorp/go-retryablehttp@v0.7.8',
  'expression': 'MPL-2.0',
  'terms': {'LICENSE': 'd6b1a865f1c8c697d343bd4e0ce61025f91898486a1f00d727f32e8644af77d3'},
  'source_h1': 'h1:ylXZWnqa7Lhqpk0L1P1LzDtGcCR0rPVUrx/c8Unxc48='},
 {'artifact_sha256': '2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a',
  'component_id': 'go-module:github.com/hashicorp/go-retryablehttp@v0.7.8',
  'expression': 'MPL-2.0',
  'terms': {'LICENSE': 'd6b1a865f1c8c697d343bd4e0ce61025f91898486a1f00d727f32e8644af77d3'},
  'source_h1': 'h1:ylXZWnqa7Lhqpk0L1P1LzDtGcCR0rPVUrx/c8Unxc48='},
 {'artifact_sha256': '2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a',
  'component_id': 'go-module:github.com/hashicorp/go-uuid@v1.0.3',
  'expression': 'MPL-2.0',
  'terms': {'LICENSE': '87b250b11ffadc5f872cb676caa219e2871e454ddd562d9e532d52d5c9b7520d'},
  'source_h1': 'h1:2gKiV6YVmrJ1i2CKKa9obLvRieoRGviZFL26PcT/Co8='},
 {'artifact_sha256': '2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a',
  'component_id': 'go-module:github.com/hashicorp/go-version@v1.9.0',
  'expression': 'MPL-2.0',
  'terms': {'LICENSE': 'b31266a0a4ade23e6c0cb5a6ae1c7933b390f30b80550a715579989639b4f55e'},
  'source_h1': 'h1:CeOIz6k+LoN3qX9Z0tyQrPtiB1DFYRPfCIBtaXPSCnA='},
 {'artifact_sha256': '37b3befbed28fb72a44d72bf42362c268610386c42feafa27cb45ee0b531369c',
  'component_id': 'go-module:github.com/hashicorp/golang-lru/v2@v2.0.7',
  'expression': 'BSD-3-Clause AND MPL-2.0',
  'terms': {'LICENSE': '6c7088eb877b5d7e6e0e9d27e822ea25fcda2e83f9eba59bb5f1418a656796e0',
            'simplelru/LICENSE_list': '6d462371baa8649492b06f51f154dba9b25d2ac9548369b8b4fdbbbb85f2f75d'},
  'source_h1': 'h1:a+bsQ5rvGLjzHuww6tVxozPZFVghXaHOwFs4luLUK2k='},
 {'artifact_sha256': '2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a',
  'component_id': 'go-module:github.com/hashicorp/golang-lru/v2@v2.0.7',
  'expression': 'BSD-3-Clause AND MPL-2.0',
  'terms': {'LICENSE': '6c7088eb877b5d7e6e0e9d27e822ea25fcda2e83f9eba59bb5f1418a656796e0',
            'simplelru/LICENSE_list': '6d462371baa8649492b06f51f154dba9b25d2ac9548369b8b4fdbbbb85f2f75d'},
  'source_h1': 'h1:a+bsQ5rvGLjzHuww6tVxozPZFVghXaHOwFs4luLUK2k='},
 {'artifact_sha256': '2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a',
  'component_id': 'go-module:github.com/hashicorp/hcl/v2@v2.24.0',
  'expression': 'MPL-2.0',
  'terms': {'LICENSE': '28ca54ff46a27183631aa262673d13e3c829d909059f5c861da835fe1783fbec'},
  'source_h1': 'h1:2QJdZ454DSsYGoaE6QheQZjtKZSUs9Nh2izTWiwQxvE='},
 {'artifact_sha256': '37b3befbed28fb72a44d72bf42362c268610386c42feafa27cb45ee0b531369c',
  'component_id': 'go-module:github.com/cyphar/filepath-securejoin@v0.7.0',
  'expression': 'BSD-3-Clause AND MPL-2.0',
  'terms': {'COPYING.md': '83e36e42b3dacc3d447eca3049848b3e2ff66b6e1768a6a3cf3f27a57079bda4',
            'LICENSE.BSD': '26be8a79415737dfe8edf1be62e71afeb8c770ed5a5605a06270d5701830f47c',
            'LICENSE.MPL-2.0': '3f3d9e0024b1921b067d6f7f88deb4a60cbe7a78e76c64e3f1d7fc3b779b9d04'},
  'source_h1': 'h1:s0Y3ITPy6sQn5xt54DuYvTF8hu134ooYLUb58DX/HjE='},
 {'artifact_sha256': '37b3befbed28fb72a44d72bf42362c268610386c42feafa27cb45ee0b531369c',
  'component_id': 'go-module:github.com/hashicorp/go-immutable-radix/v2@v2.1.0',
  'expression': 'MPL-2.0',
  'terms': {'LICENSE': 'd6b1a865f1c8c697d343bd4e0ce61025f91898486a1f00d727f32e8644af77d3'},
  'source_h1': 'h1:CUW5RYIcysz+D3B+l1mDeXrQ7fUvGGCwJfdASSzbrfo='}]

def allowed_for(record, component, allowed, *, selected_internal, source_modules=()):
    """Add only one exact component's reviewed IDs for proved internal use."""
    result=list(allowed)
    if selected_internal is not True or record.get('kind') != 'tool' or record.get('origin',{}).get('kind') != 'go-checker-release/v1':
        return result
    for profile in PROFILES:
        if (record.get('sha256') != profile['artifact_sha256']
                or component.get('id') != profile['component_id']
                or component.get('expression') != profile['expression']
                or [item.get('h1') for item in source_modules
                    if isinstance(item, dict) and item.get('module') == profile['component_id'].removeprefix('go-module:')]
                    != [profile['source_h1']]):
            continue
        import hashlib
        prefix='go-terms/'+hashlib.sha256(profile['component_id'].encode()).hexdigest()+'/'
        expected={prefix+name:sha for name,sha in profile['terms'].items()}
        rows=component.get('files',[])
        actual={row.get('path'):row.get('sha256') for row in rows if isinstance(row,dict)}
        if (len(actual)!=len(rows) or actual!=expected
                or set(component.get('license_paths',[]))!=set(expected)
                or len(component.get('license_paths',[]))!=len(expected)
                or component.get('notice_paths')!=[]):
            continue
        for sha in expected.values():
            for identifier in TEXTS[sha]:
                if identifier not in result:result.append(identifier)
    return result
