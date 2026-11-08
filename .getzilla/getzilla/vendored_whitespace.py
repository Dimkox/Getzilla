"""Exact pinned Git-blob whitespace custody; no approval or path exemption.

The caller still runs every check and requires independent review. These source
records classify exact diagnostics only; they authenticate no reviewer identity.
"""
from __future__ import annotations

import hashlib
import json
import re

CATALOG_PATH = '.getzilla/config/vendored-source-catalog.json'
KINDS = {'trailing-whitespace', 'space-before-tab', 'trailing-whitespace-and-space-before-tab',
         'new-blank-line-at-eof'}


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate custody key')
        result[key] = value
    return result


def document(raw):
    return json.loads(raw.decode('utf-8'), object_pairs_hook=_object)


def fields(value, names):
    if type(value) is not dict or set(value) != set(names.split()):
        raise ValueError('invalid custody fields')
    return value


def hash_value(value, length=64):
    if type(value) is not str or not re.fullmatch('[0-9a-f]{' + str(length) + '}', value):
        raise ValueError('invalid custody hash')
    return value


def git_hash(kind, raw):
    return hashlib.sha1(kind.encode() + b' ' + str(len(raw)).encode() + b'\0' + raw,
                        usedforsecurity=False).hexdigest()


def eligible(raw, line, rule):
    if (type(line) is not int or not 1 <= line <= 2_000_000 or rule not in KINDS
            or b'\0' in raw):
        return False
    raw.decode('utf-8')
    if rule == 'new-blank-line-at-eof':
        if not raw.endswith(b'\n'):
            return False
        lines = raw.split(b'\n')[:-1]
        end = len(lines)
        while end and not lines[end - 1].strip(b' \t\r'):
            end -= 1
        return 0 < end < len(lines) and line == end + 1
    lines = raw.split(b'\n')
    if line > len(lines):
        return False
    value = lines[line - 1]
    trailing = bool(value and value[-1:] in (b' ', b'\t', b'\r'))
    indentation = re.match(rb'[ \t]*', value).group()
    before_tab = b' \t' in indentation
    return {'trailing-whitespace': trailing and not before_tab,
            'space-before-tab': before_tab and not trailing,
            'trailing-whitespace-and-space-before-tab': trailing and before_tab}[rule]


def _owner(owner, canonical_path):
    fields(owner, 'id root inventory repository revision commit trees')
    canonical_path(owner['root'])
    if (type(owner['id']) is not str or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', owner['id'])
            or type(owner['repository']) is not str
            or not re.fullmatch(r'https://[A-Za-z0-9.-]+/[A-Za-z0-9_./-]+', owner['repository'])):
        raise ValueError('invalid custody owner')
    hash_value(owner['revision'], 40)
    commit = owner['commit']
    if type(commit) is not str or len(commit.encode()) > 131072 or git_hash('commit', commit.encode()) != owner['revision']:
        raise ValueError('pinned commit proof mismatch')
    root = re.match(r'tree ([0-9a-f]{40})\n', commit)
    if not root or type(owner['trees']) is not list or not 1 <= len(owner['trees']) <= 32:
        raise ValueError('invalid custody tree proof')
    trees, count = {}, 0
    for tree in owner['trees']:
        fields(tree, 'oid entries')
        hash_value(tree['oid'], 40)
        if tree['oid'] in trees or type(tree['entries']) is not list or len(tree['entries']) > 2048:
            raise ValueError('invalid custody tree entries')
        raw, names = b'', set()
        for entry in tree['entries']:
            fields(entry, 'mode name oid')
            hash_value(entry['oid'], 40)
            name = entry['name']
            if (type(name) is not str or '/' in name or canonical_path(name) != name or name in names
                    or entry['mode'] not in {'40000', '100644', '100755', '120000', '160000'}):
                raise ValueError('invalid custody tree entry')
            names.add(name)
            count += 1
            raw += entry['mode'].encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(entry['oid'])
        if count > 8192 or git_hash('tree', raw) != tree['oid']:
            raise ValueError('tree identity mismatch')
        trees[tree['oid']] = {entry['name']: entry for entry in tree['entries']}
    return root[1], trees


def validate(entry, raw, read, canonical_path):
    """Validate independent source/catalog/evidence bindings for one exact finding."""
    catalog_ref = fields(entry['catalog'], 'path sha256')
    if catalog_ref['path'] != CATALOG_PATH:
        raise ValueError('foreign custody catalog')
    catalog_raw = read(CATALOG_PATH)
    if hashlib.sha256(catalog_raw).hexdigest() != hash_value(catalog_ref['sha256']):
        raise ValueError('stale custody catalog')
    catalog = fields(document(catalog_raw), 'schema_version owners files')
    if type(catalog['schema_version']) is not int or catalog['schema_version'] != 1:
        raise ValueError('invalid custody schema')
    if (type(catalog['owners']) is not list or not 1 <= len(catalog['owners']) <= 16
            or type(catalog['files']) is not list or not 1 <= len(catalog['files']) <= 128):
        raise ValueError('custody catalog bounds')
    owners = {}
    for owner in catalog['owners']:
        root, trees = _owner(owner, canonical_path)
        if owner['id'] in owners or any(owner['root'] == known[0]['root']
                                       or owner['root'].startswith(known[0]['root'] + '/')
                                       or known[0]['root'].startswith(owner['root'] + '/')
                                       for known in owners.values()):
            raise ValueError('duplicate or overlapping custody owner')
        inventory = fields(owner['inventory'], 'path sha256')
        inventory_path = canonical_path(inventory['path'])
        if inventory_path.startswith(owner['root'] + '/'):
            raise ValueError('custody inventory cannot own itself')
        inventory_raw = read(inventory_path)
        if hashlib.sha256(inventory_raw).hexdigest() != hash_value(inventory['sha256']):
            raise ValueError('stale custody inventory')
        inventory_doc = document(inventory_raw)
        if (type(inventory_doc) is not dict or type(inventory_doc.get('binding')) is not dict
                or inventory_doc['binding'].get('source_commit') != owner['revision']
                or type(inventory_doc.get('files')) is not list or len(inventory_doc['files']) > 4096):
            raise ValueError('custody inventory source mismatch')
        owners[owner['id']] = (owner, root, trees, inventory_doc['files'])
    sources = {}
    for record in catalog['files']:
        fields(record, 'path sha256 mode owner target_path upstream_path upstream_blob')
        path = canonical_path(record['path'])
        canonical_path(record['target_path'])
        canonical_path(record['upstream_path'])
        hash_value(record['sha256'])
        hash_value(record['upstream_blob'], 40)
        if path in sources or record['mode'] != '100644' or record['owner'] not in owners:
            raise ValueError('invalid custody path ownership')
        owner, root, trees, inventory = owners[record['owner']]
        if not path.startswith(owner['root'] + '/') or path.rsplit('/', 1)[-1].split('.')[0] != record['sha256']:
            raise ValueError('foreign custody path')
        matches = [item for item in inventory if type(item) is dict and item.get('path') == record['target_path']]
        if (len(matches) != 1 or matches[0].get('sha256') != record['sha256']
                or type(matches[0].get('mode')) is not int or matches[0]['mode'] != 0o644):
            raise ValueError('custody inventory file mismatch')
        oid = root
        parts = record['upstream_path'].split('/')
        for index, part in enumerate(parts):
            tree_entry = trees.get(oid, {}).get(part)
            if tree_entry is None or tree_entry['mode'] != ('100644' if index == len(parts) - 1 else '40000'):
                raise ValueError('upstream path proof mismatch')
            oid = tree_entry['oid']
        if oid != record['upstream_blob']:
            raise ValueError('upstream blob proof mismatch')
        sources[path] = record
    source = sources.get(entry['path'])
    if (source is None or source['sha256'] != entry['sha256'] or source['mode'] != entry['mode']
            or git_hash('blob', raw) != source['upstream_blob'] or not eligible(raw, entry['line'], entry['rule'])):
        raise ValueError('exact upstream finding mismatch')
    evidence_ref = fields(entry['evidence'], 'path sha256')
    evidence_path = canonical_path(evidence_ref['path'])
    if evidence_path in {entry['path'], CATALOG_PATH} or not evidence_path.endswith('.json'):
        raise ValueError('separate custody evidence required')
    evidence_raw = read(evidence_path)
    if hashlib.sha256(evidence_raw).hexdigest() != hash_value(evidence_ref['sha256']):
        raise ValueError('stale custody evidence')
    evidence = fields(document(evidence_raw), 'schema_version kind catalog_sha256 review files')
    if (type(evidence['schema_version']) is not int or evidence['schema_version'] != 1
            or evidence['kind'] != 'immutable-vendored-whitespace-custody'
            or evidence['catalog_sha256'] != catalog_ref['sha256']
            or type(evidence['files']) is not list or not 1 <= len(evidence['files']) <= 128):
        raise ValueError('invalid custody evidence')
    review = fields(evidence['review'], 'path sha256')
    review_path = canonical_path(review['path'])
    if review_path in {entry['path'], CATALOG_PATH, evidence_path} or not review_path.endswith('.md'):
        raise ValueError('separate review facts required')
    if hashlib.sha256(read(review_path)).hexdigest() != hash_value(review['sha256']):
        raise ValueError('stale review facts')
    seen, matched = set(), False
    for item in evidence['files']:
        fields(item, 'path sha256 mode diagnostics')
        if item['path'] in seen or item['path'] not in sources or item['mode'] != '100644':
            raise ValueError('invalid evidence file')
        seen.add(item['path'])
        if item['sha256'] != sources[item['path']]['sha256'] or type(item['diagnostics']) is not list or not 1 <= len(item['diagnostics']) <= 128:
            raise ValueError('invalid evidence diagnostics')
        positions = set()
        for finding in item['diagnostics']:
            fields(finding, 'line rule')
            identity = (finding['line'], finding['rule'])
            if (type(finding['line']) is not int or not 1 <= finding['line'] <= 2_000_000
                    or finding['rule'] not in KINDS or identity in positions):
                raise ValueError('invalid evidence finding')
            positions.add(identity)
        if item['path'] == entry['path']:
            matched = item['sha256'] == entry['sha256'] and (entry['line'], entry['rule']) in positions
    if not matched:
        raise ValueError('finding not covered by separate evidence')
