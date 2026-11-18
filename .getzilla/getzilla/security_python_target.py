"""Observed current-interpreter artifact scope; never package execution or all-target coverage."""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import re
import sys
import sysconfig
import tomllib
from email.parser import BytesParser

from .security_artifacts import ArtifactError, archive_files, package_key, artifact_context, read_file


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def _refuse():
    raise ArtifactError('artifact-target-unknown', 'current Python artifact target is missing, changed or unqualified')


def _facts():
    # This is trusted interpreter tooling, never an import from candidate source.
    try:
        from pip._vendor.packaging.tags import sys_tags
        from pip._vendor.packaging.markers import default_environment
        tags = tuple(str(tag) for tag in sys_tags())
        if not 1 <= len(tags) <= 4096 or len(set(tags)) != len(tags):
            _refuse()
        markers = default_environment()
        target = dict(schema_version=1, implementation=sys.implementation.name,
            python_version='.'.join(map(str, sys.version_info[:3])), platform=sysconfig.get_platform(),
            abi=sysconfig.get_config_var('SOABI'), tags_sha256=digest(list(tags)),
            tag_count=len(tags), marker_environment=markers)
        _descriptor(target)
        return target, tags
    except (ImportError, AttributeError, TypeError, ValueError):
        _refuse()


def _descriptor(value):
    fields = {'schema_version','implementation','python_version','platform','abi','tags_sha256','tag_count','marker_environment'}
    if (type(value) is not dict or set(value) != fields or type(value['schema_version']) is not int
            or value['schema_version'] != 1 or type(value['tag_count']) is not int or not 1 <= value['tag_count'] <= 4096
            or any(type(value[k]) is not str or not 1 <= len(value[k]) <= 256
                   or re.fullmatch(r'[A-Za-z0-9_.-]+',value[k]) is None
                   for k in ('implementation','python_version','platform','abi'))
            or type(value['tags_sha256']) is not str or not re.fullmatch('[a-f0-9]{64}',value['tags_sha256'])
            or type(value['marker_environment']) is not dict or not 1 <= len(value['marker_environment']) <= 16
            or any(type(k) is not str or not re.fullmatch('[a-z_]{1,40}',k) or type(v) is not str
                   or len(v) > 512 or any(ord(c) < 32 for c in v) for k,v in value['marker_environment'].items())):
        _refuse()
    return json.loads(json.dumps(value))


def observe_target():
    return _facts()[0]


def validate_target(value):
    target = _descriptor(value)
    actual, _ = _facts()
    if target != actual:
        _refuse()
    return target


def binding(profile):
    if 'python_target' not in profile:
        return None
    value = dict(target=validate_target(profile['python_target']), source=profile['source'], run=profile['run'],
        inventory_sha256=profile['inventory_sha256'], profile_sha256=profile['profile_sha256'])
    if 'python_source_pins' in profile:
        value['source_pins'] = profile['python_source_pins']
    if 'factory_inputs' in profile:
        value['factory_inputs'] = profile['factory_inputs']
    return _binding(value)


def _binding(value):
    if (type(value) is not dict or set(value)-{'source_pins','factory_inputs'} != {'target','source','run','inventory_sha256','profile_sha256'}):
        _refuse()
    if 'source_pins' in value:
        validate_source_pins(value['source_pins'])
    if 'factory_inputs' in value:
        from .security_factory_inputs import validate_declaration
        declared=validate_declaration(value['factory_inputs'])
        if declared['inventory_sha256']!=value['inventory_sha256']:
            _refuse()
    validate_target(value['target'])
    source, run = value['source'], value['run']
    hashes = ('head_sha','tree_sha','checker_sha','checker_tree_sha')
    if (type(source) is not dict or set(source) != set(hashes)|{'candidate_clean','checker_clean','same_project'}
            or any(type(source[k]) is not str or not re.fullmatch('[a-f0-9]{40}',source[k]) for k in hashes)
            or source['candidate_clean'] is not True or source['checker_clean'] is not True
            or type(source['same_project']) is not bool
            or type(run) is not dict or set(run) != {'provider','repository','run_id','run_attempt','head_sha'}
            or run['provider'] != 'github-actions' or type(run['repository']) is not str
            or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',run['repository'])
            or any(type(run[k]) is not str or not re.fullmatch('[1-9][0-9]*',run[k]) for k in ('run_id','run_attempt'))
            or type(run['head_sha']) is not str or not re.fullmatch('[a-f0-9]{40}',run['head_sha'])
            or any(type(value[k]) is not str or not re.fullmatch('[a-f0-9]{64}',value[k]) for k in ('inventory_sha256','profile_sha256'))):
        _refuse()
    return json.loads(json.dumps(value))


def _subject(dep):
    return {key:dep[key] for key in ('ecosystem','name','version','manifest','usage','extras')}


def _context_key(dep):
    return digest(dict(ecosystem=dep['ecosystem'],name=dep['name'],version=dep['version'],context=artifact_context(dep)))


def validate_source_pins(value):
    if type(value) is not dict or len(value)>512:
        _refuse()
    for key,row in value.items():
        if (type(key) is not str or not re.fullmatch('[a-f0-9]{64}',key) or type(row) is not dict
                or set(row) != {'context_sha256','manifest_sha256','hashes','files','marker_active'}
                or type(row['marker_active']) is not bool
                or any(type(row[k]) is not str or not re.fullmatch('[a-f0-9]{64}',row[k]) for k in ('context_sha256','manifest_sha256'))):
            _refuse()
        for field in ('hashes','files'):
            if (type(row[field]) is not list or len(row[field])>8192
                    or any(type(item) is not str or not re.fullmatch('[a-f0-9]{64}',item) for item in row[field])):
                _refuse()
    if len(json.dumps(value).encode())>1024*1024:
        _refuse()
    return json.loads(json.dumps(value))


def source_pins(root, inventory, target):
    """Private per-use observations, not a rewrite of the source inventory."""
    from .security_inventory import _PIN, _logical_requirements
    from .security_osv_snapshot import REQUIREMENTS_RE
    from pip._vendor.packaging.markers import Marker
    manifests={row['path']:row['sha256'] for row in inventory['manifests']}
    result,cache={},{}
    for dep in inventory['dependencies']:
        if dep['ecosystem']!='PyPI':
            continue
        path=dep['manifest']
        if path not in cache:
            raw=read_file(root,path,32*1024*1024)
            if hashlib.sha256(raw).hexdigest()!=manifests.get(path):
                _refuse()
            cache[path]=raw.decode('utf-8')
        hashes,files,active=set(),set(),True
        name=Path(path).name
        if name=='uv.lock':
            packages=[row for row in tomllib.loads(cache[path]).get('package',[]) if
                package_key('PyPI',row.get('name'),row.get('version'))==package_key('PyPI',dep['name'],dep['version'])]
            if len(packages)!=1 or set(packages[0].get('source',{}))!={'registry'}:
                _refuse()
            for wheel in packages[0].get('wheels',[]):
                url,sha=wheel.get('url'),wheel.get('hash','').removeprefix('sha256:')
                if type(url) is not str or not re.fullmatch('[a-f0-9]{64}',sha):
                    _refuse()
                files.add(digest(dict(filename=url.rsplit('/',1)[-1],sha256=sha,url=url)))
            if not files:
                _refuse()
        elif REQUIREMENTS_RE.fullmatch(name):
            variants=[]
            for line in _logical_requirements(cache[path]):
                clean=re.sub(r'\s+--hash=sha256:[a-fA-F0-9]{64}','',line).strip()
                match=_PIN.fullmatch(clean)
                if match is None or package_key('PyPI',match[1],match[3])!=package_key('PyPI',dep['name'],dep['version']):
                    continue
                if sorted(filter(None,(match[2] or '').split(',')))!=dep['extras']:
                    continue
                applies=';' not in clean or Marker(clean.split(';',1)[1]).evaluate(environment=target['marker_environment'])
                variants.append((applies,set(item.lower() for item in re.findall(r'--hash=sha256:([a-fA-F0-9]{64})',line))))
            if not variants:
                _refuse()
            active=any(applies for applies,_ in variants)
            chosen=[values for applies,values in variants if applies] if active else [values for _,values in variants]
            constrained=[values for values in chosen if values]
            if constrained:
                hashes=set.intersection(*constrained) if active else set.union(*constrained)
                if not hashes:
                    _refuse()
        elif name!='pyproject.toml':
            _refuse()
        result[digest(_subject(dep))]=dict(context_sha256=_context_key(dep),manifest_sha256=manifests[path],
            hashes=sorted(hashes),files=sorted(files),marker_active=active)
    return validate_source_pins(result)


def _pin_for(dep, expected):
    if 'source_pins' not in expected:
        return None
    row=expected['source_pins'].get(digest(_subject(dep)))
    if row is None or row['context_sha256']!=_context_key(dep):
        _refuse()
    return row


def _allowed_pin(pin, filename, sha, url):
    return (pin is None or (not pin['hashes'] or sha in pin['hashes']) and
        (not pin['files'] or digest(dict(filename=filename,sha256=sha,url=url)) in pin['files']))


def _filename(value):
    if type(value) is not str or len(value) > 256 or not value.endswith('.whl') or '/' in value or '\\' in value:
        _refuse()
    fields = value[:-4].split('-')
    if len(fields) not in (5,6) or math.prod(len(part.split('.')) for part in fields[-3:]) > 4096:
        _refuse()
    try:
        from pip._vendor.packaging.utils import parse_wheel_filename
        name, version, _, tags = parse_wheel_filename(value)
        return name, str(version), {str(tag) for tag in tags}
    except (ImportError, ValueError):
        _refuse()


def _python_compatible(value, version):
    if value is None:
        return True
    if type(value) is not str or len(value) > 1024:
        _refuse()
    try:
        from pip._vendor.packaging.specifiers import SpecifierSet
        return SpecifierSet(value).contains(version, prereleases=True)
    except (ImportError, ValueError):
        _refuse()


def select_dependency(index, dependency, expected):
    _binding(expected)
    _, tags = _facts()
    ranks = {tag: index for index,tag in enumerate(tags)}
    urls = index.get('urls')
    if type(urls) is not list or len(urls) > 8192:
        _refuse()
    candidates = []
    pin = _pin_for(dependency,expected)
    for row in urls:
        if type(row) is not dict or row.get('packagetype') != 'bdist_wheel' or row.get('yanked') is not False:
            continue
        if not _python_compatible(row.get('requires_python'), expected['target']['python_version']):
            continue
        filename, hashes = row.get('filename'), row.get('digests')
        if type(hashes) is not dict or any(dependency.get(k) is not None and dependency[k] != wanted
                for k,wanted in (('artifact_filename',filename),('artifact_sha256',hashes.get('sha256')),('artifact_source',row.get('url')))):
            continue
        if not _allowed_pin(pin,filename,hashes.get('sha256'),row.get('url')):
            continue
        name, version, wheel_tags = _filename(filename)
        if package_key('PyPI',name,version) != package_key('PyPI',dependency.get('name'),dependency.get('version')):
            _refuse()
        matches = wheel_tags & ranks.keys()
        if matches:
            candidates.append((min(ranks[tag] for tag in matches),row))
    if not candidates:
        _refuse()
    best = min(score for score,_ in candidates)
    selected = [row for score,row in candidates if score == best]
    if len(selected) != 1:
        _refuse()
    row = selected[0]
    return dict(dependency, artifact_filename=row['filename'], artifact_sha256=row['digests'].get('sha256'), artifact_source=row.get('url'))


def observation(value):
    if (type(value) is not dict or set(value)-{'subject_sha256'} != {'binding_sha256','target_sha256','wheel_tags'}
            or any(type(value[k]) is not str or not re.fullmatch('[a-f0-9]{64}',value[k]) for k in ('binding_sha256','target_sha256'))
            or type(value['wheel_tags']) is not list or not 1 <= len(value['wheel_tags']) <= 128
            or len(set(value['wheel_tags'])) != len(value['wheel_tags'])
            or any(type(tag) is not str or len(tag) > 128 or not re.fullmatch('[a-z0-9_]+-[a-z0-9_]+-[a-z0-9_]+',tag) for tag in value['wheel_tags'])):
        _refuse()
    if 'subject_sha256' in value and (type(value['subject_sha256']) is not str or not re.fullmatch('[a-f0-9]{64}',value['subject_sha256'])):
        _refuse()
    return json.loads(json.dumps(value))


def wheel_observation(filename, files, expected, *, dependency=None):
    _binding(expected)
    _, supported = _facts()
    _, _, filename_tags = _filename(filename)
    names = [name for name in files if name.endswith('.dist-info/WHEEL') and name.count('/') == 1]
    metadata = [name for name in files if name.endswith('.dist-info/METADATA') and name.count('/') == 1]
    if len(names) != 1 or len(metadata) != 1 or names[0].rsplit('/',1)[0] != metadata[0].rsplit('/',1)[0] or len(files[names[0]]) > 65536:
        _refuse()
    parsed = BytesParser().parsebytes(files[names[0]])
    meta = BytesParser().parsebytes(files[metadata[0]])
    python = meta.get_all('Requires-Python', [])
    if (parsed.defects or meta.defects or len(python) > 1
            or not _python_compatible(python[0] if python else None, expected['target']['python_version'])):
        _refuse()
    tags = parsed.get_all('Tag',[])
    value = observation(dict(binding_sha256=digest(expected),target_sha256=digest(expected['target']),wheel_tags=sorted(tags)))
    if 'source_pins' in expected:
        if dependency is None:
            _refuse()
        _pin_for(dependency,expected)
        value['subject_sha256']=digest(_subject(dependency))
    if (parsed.get_all('Wheel-Version') != ['1.0'] or parsed.get_all('Root-Is-Purelib') not in (['true'],['false'])
            or set(tags) != filename_tags or not set(tags).intersection(supported)):
        _refuse()
    return value


def verify_record(record, payload, expected, *, files=None, dependency=None):
    if expected is None or record.get('ecosystem') != 'PyPI':
        _refuse()
    claimed = observation(record.get('python_target'))
    if hashlib.sha256(payload).hexdigest() != record.get('sha256'):
        _refuse()
    if 'source_pins' in expected:
        key=claimed.get('subject_sha256')
        pin=expected['source_pins'].get(key)
        derived=dict(ecosystem=record['ecosystem'],name=record['name'],version=record['version'],context=record.get('context',{}))
        if (pin is None or pin['context_sha256']!=digest(derived)
                or dependency is not None and digest(_subject(dependency))!=key
                or not _allowed_pin(pin,record['filename'],record['sha256'],record['origin']['artifact_url'])):
            _refuse()
        # The source-use key is rechecked above; metadata validation needs no
        # caller-controlled dependency when freezing the structural catalog.
        measurement_expected={key:value for key,value in expected.items() if key!='source_pins'}
        measured=wheel_observation(record['filename'],archive_files(payload,record['filename']) if files is None else files,measurement_expected)
        measured['binding_sha256']=digest(expected)
        measured['subject_sha256']=key
    else:
        measured = wheel_observation(record['filename'],archive_files(payload,record['filename']) if files is None else files,expected)
    if claimed != measured:
        _refuse()
    return measured
