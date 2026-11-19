"""Closed projections of twelve original protobuf source comment containers.

Text recognition is separate. Only these exact npm artifacts, full original JS
members, fixed selectors and decoded full-block hashes obtain a namespace here.
"""
from __future__ import annotations

import hashlib
from .security_artifacts import ArtifactError

RECIPES = {'3b0d9fa38925795ce7b1b4673a75261810bb1779f60a7dc7dca6940f9840de9b': [{'container_path': 'package/build/commonjs/google/protobuf/compiler/plugin.js',
                                                                       'container_sha256': '2ea2454c97c9db33670eda13caf2e90903ec967e7a797cfdd4690b242fbb844d',
                                                                       'container_bytes': 6456,
                                                                       'start_line': 9,
                                                                       'end_line_exclusive': 55,
                                                                       'decoded_sha256': '32ae9a06ce10bb95444eaef5a0a6fe171c2b088a0ace3a03daaf5ff5dd60a8f7',
                                                                       'decoded_bytes': 2150},
                                                                      {'container_path': 'package/build/commonjs/google/protobuf/descriptor.js',
                                                                       'container_sha256': 'a37ba611c3168b1542f972e3f9973b409487329db5504071299a08460a4bbeda',
                                                                       'container_bytes': 34772,
                                                                       'start_line': 9,
                                                                       'end_line_exclusive': 47,
                                                                       'decoded_sha256': 'bd773be0928aebf73959b15de6edd7abf4e78014bc9e8be3b96142ca251a018f',
                                                                       'decoded_bytes': 1867},
                                                                      {'container_path': 'package/build/es2015/google/protobuf/compiler/plugin.js',
                                                                       'container_sha256': '33e76d6f78c2e8b317ba81b1c264a8a279a4b50edb1577b02c19460f6ac28404',
                                                                       'container_bytes': 5990,
                                                                       'start_line': 6,
                                                                       'end_line_exclusive': 52,
                                                                       'decoded_sha256': '32ae9a06ce10bb95444eaef5a0a6fe171c2b088a0ace3a03daaf5ff5dd60a8f7',
                                                                       'decoded_bytes': 2150},
                                                                      {'container_path': 'package/build/es2015/google/protobuf/descriptor.js',
                                                                       'container_sha256': '49d6e7e05d51aaeeb9f33aeeac5b7c77cac03c1273c84d7d053041e1b94a2770',
                                                                       'container_bytes': 31832,
                                                                       'start_line': 6,
                                                                       'end_line_exclusive': 44,
                                                                       'decoded_sha256': 'bd773be0928aebf73959b15de6edd7abf4e78014bc9e8be3b96142ca251a018f',
                                                                       'decoded_bytes': 1867}],
 '3bb18cb373565b5c95e466c1db76e4b1d8166b62276a15e3547c36f9e25b502b': [{'container_path': 'package/build/commonjs/goog-varint.js',
                                                                       'container_sha256': '8c5adc276a587ac290d1bf77648a992b025ea2bf02b3966bdb3f682a24f90f9a',
                                                                       'container_bytes': 10090,
                                                                       'start_line': 2,
                                                                       'end_line_exclusive': 34,
                                                                       'decoded_sha256': '182a1bc8985a586e8e0ca3b5a3af1ff3c28bd3475833a07f50b42b53dd7ac889',
                                                                       'decoded_bytes': 1720},
                                                                      {'container_path': 'package/build/commonjs/protobufjs-utf8.js',
                                                                       'container_sha256': 'd2379d310a79047ab69a52110640897bc1d2541fd1e3363ad985e480d3ced1fc',
                                                                       'container_bytes': 3310,
                                                                       'start_line': 2,
                                                                       'end_line_exclusive': 28,
                                                                       'decoded_sha256': '1033ec013241782ef9264400da6635b26b7a14674d9601c6c767be84ad778af4',
                                                                       'decoded_bytes': 1479},
                                                                      {'container_path': 'package/build/es2015/goog-varint.js',
                                                                       'container_sha256': '1d177e89d752c2721e05dfaf17cfc2f9d4bea613a52c2b62ada0d64d22c408ea',
                                                                       'container_bytes': 9669,
                                                                       'start_line': 1,
                                                                       'end_line_exclusive': 33,
                                                                       'decoded_sha256': '182a1bc8985a586e8e0ca3b5a3af1ff3c28bd3475833a07f50b42b53dd7ac889',
                                                                       'decoded_bytes': 1720},
                                                                      {'container_path': 'package/build/es2015/protobufjs-utf8.js',
                                                                       'container_sha256': 'cefc299b891bf38ea3220ed5607a6ca285caf9a71d9c8dfc35dafa3237720b06',
                                                                       'container_bytes': 3184,
                                                                       'start_line': 1,
                                                                       'end_line_exclusive': 27,
                                                                       'decoded_sha256': '1033ec013241782ef9264400da6635b26b7a14674d9601c6c767be84ad778af4',
                                                                       'decoded_bytes': 1479}],
 'c82354b7e1596d66233f32b70038511c4473aedb4fd41aff10a8cc342c415e41': [{'container_path': 'package/build/commonjs/goog-varint.js',
                                                                       'container_sha256': '8c5adc276a587ac290d1bf77648a992b025ea2bf02b3966bdb3f682a24f90f9a',
                                                                       'container_bytes': 10090,
                                                                       'start_line': 2,
                                                                       'end_line_exclusive': 34,
                                                                       'decoded_sha256': '182a1bc8985a586e8e0ca3b5a3af1ff3c28bd3475833a07f50b42b53dd7ac889',
                                                                       'decoded_bytes': 1720},
                                                                      {'container_path': 'package/build/commonjs/protobufjs-utf8.js',
                                                                       'container_sha256': 'd2379d310a79047ab69a52110640897bc1d2541fd1e3363ad985e480d3ced1fc',
                                                                       'container_bytes': 3310,
                                                                       'start_line': 2,
                                                                       'end_line_exclusive': 28,
                                                                       'decoded_sha256': '1033ec013241782ef9264400da6635b26b7a14674d9601c6c767be84ad778af4',
                                                                       'decoded_bytes': 1479},
                                                                      {'container_path': 'package/build/es2015/goog-varint.js',
                                                                       'container_sha256': '1d177e89d752c2721e05dfaf17cfc2f9d4bea613a52c2b62ada0d64d22c408ea',
                                                                       'container_bytes': 9669,
                                                                       'start_line': 1,
                                                                       'end_line_exclusive': 33,
                                                                       'decoded_sha256': '182a1bc8985a586e8e0ca3b5a3af1ff3c28bd3475833a07f50b42b53dd7ac889',
                                                                       'decoded_bytes': 1720},
                                                                      {'container_path': 'package/build/es2015/protobufjs-utf8.js',
                                                                       'container_sha256': 'cefc299b891bf38ea3220ed5607a6ca285caf9a71d9c8dfc35dafa3237720b06',
                                                                       'container_bytes': 3184,
                                                                       'start_line': 1,
                                                                       'end_line_exclusive': 27,
                                                                       'decoded_sha256': '1033ec013241782ef9264400da6635b26b7a14674d9601c6c767be84ad778af4',
                                                                       'decoded_bytes': 1479}]}

def project(source, files):
    """Return explicit derived terms; their original archive is counted once."""
    recipes = RECIPES.get(source.get('sha256'), ())
    terms, proofs = [], []
    for index, recipe in enumerate(recipes):
        path = recipe['container_path']
        raw = files.get(path)
        if (not isinstance(raw, bytes) or len(raw) != recipe['container_bytes']
                or hashlib.sha256(raw).hexdigest() != recipe['container_sha256']):
            raise ArtifactError('license-source-projection', 'original source comment container is missing or changed')
        lines = raw.splitlines(keepends=True)
        first, end = recipe['start_line'], recipe['end_line_exclusive']
        if not 1 <= first < end <= len(lines) + 1:
            raise ArtifactError('license-source-projection', 'fixed source comment selector is unavailable')
        selected = lines[first - 1:end - 1]
        if not all(line.startswith(b'//') for line in selected):
            raise ArtifactError('license-source-projection', 'fixed comment codec does not match original source syntax')
        decoded = b''.join(line[3:] if line.startswith(b'// ') else line[2:] for line in selected)
        if (len(decoded) != recipe['decoded_bytes']
                or hashlib.sha256(decoded).hexdigest() != recipe['decoded_sha256']):
            raise ArtifactError('license-source-projection', 'complete decoded source term body differs')
        derived = f'derived/npm/{source["sha256"]}/source-comments/{index}/LICENSE'
        terms.append((derived, decoded))
        proofs.append({'path': path, 'sha256': recipe['container_sha256'], 'bytes': len(raw),
            'container_kind': 'npm-source-comment-projection', 'artifact_path': source['path'],
            'artifact_sha256': source['sha256'], 'selector': {'kind': 'exact-line-comment-block-v1',
                'start_line': first, 'end_line_exclusive': end}, 'decoded_sha256': recipe['decoded_sha256'],
            'decoded_bytes': len(decoded), 'derived_path': derived, 'physical_bytes': 0})
    return {'terms': terms, 'proofs': proofs}
