"""Named Factory CP312 inputs and freshly composed output, separate from host uses."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import tomllib
from email.parser import BytesParser

from .security_artifacts import (ArtifactError, MAX_ARTIFACT_BYTES, MAX_INDEX_BYTES,
    archive_files, archive_inventory, artifact_identity, read_file, select_artifact)
from .security_data import _json
from .security_python_target import digest

PROFILE = 'ubuntu-24.04-x86_64-cpython312'
MARKERS = dict(sys_platform='linux',os_name='posix',platform_system='Linux',platform_machine='x86_64',
    implementation_name='cpython',platform_python_implementation='CPython',python_version='3.12')
MAX_TOTAL = 512*1024*1024


def _refuse(code='artifact-factory-input'):
    raise ArtifactError(code,'named Factory input/output source, target or custody differs')


def _app_members(root,scratch):
    from .security_cli import _git
    with tempfile.TemporaryDirectory(prefix='factory-source-',dir=scratch) as directory:
        paths=_git(root,['ls-files','factory/src/getzilla_factory'],Path(directory)).splitlines()
    if not 1 <= len(paths) <= 10000:
        _refuse()
    members={}
    total=0
    for relative in paths:
        if not relative.startswith('factory/src/getzilla_factory/'):
            _refuse()
        raw=read_file(root,relative,16*1024*1024)
        total+=len(raw)
        if total>MAX_TOTAL:
            _refuse('artifact-size')
        key='app/'+relative.removeprefix('factory/src/')
        members[key]=dict(size=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    return members


def declaration(root,inventory,policy,*,scratch):
    """Reobserve policy-pinned selectors; do not alter the source-use inventory."""
    if 'factory_offline_profile' not in policy:
        return None
    from .security_licenses import factory_offline_intent
    intent=factory_offline_intent(root,policy)
    if not intent or intent.get('code')!='license-factory-archive-delivery-unverified':
        _refuse()
    lock=tomllib.loads(read_file(root,'factory/uv.lock',4*1024*1024).decode())
    packages=lock.get('package')
    if not isinstance(packages,list) or len(packages)>10000:
        _refuse()
    deps=[]
    for wheel in intent['components']:
        matches=[row for row in packages if row.get('name')==wheel['name'] and row.get('version')==wheel['version']]
        if len(matches)!=1 or matches[0].get('source')!={'registry':'https://pypi.org/simple'}:
            _refuse()
        files=[row for row in matches[0].get('wheels',[]) if row.get('hash')=='sha256:'+wheel['sha256']
            and row.get('url','').rsplit('/',1)[-1]==wheel['filename']]
        if len(files)!=1:
            _refuse()
        uses=[row for row in inventory['dependencies'] if row.get('ecosystem')=='PyPI'
            and row.get('name')==wheel['name'] and row.get('version')==wheel['version']
            and row.get('manifest') in {'factory/uv.lock','factory/pyproject.toml'}
            and row.get('usage')!='build']
        if not uses or not any(row.get('manifest')=='factory/uv.lock' for row in uses):
            _refuse()
        deps.append(dict(ecosystem='PyPI',name=wheel['name'],version=wheel['version'],manifest='factory/uv.lock',
            usage='runtime',extras=sorted({extra for row in uses for extra in row.get('extras',[])}),
            artifact_filename=wheel['filename'],artifact_sha256=wheel['sha256'],artifact_source=files[0]['url'],
            distribution='redistributed',delivery_kind='factory-offline-archive',
            source_use_sha256=sorted(digest(row) for row in uses)))
    if not deps:
        _refuse()
    project=tomllib.loads(read_file(root,'factory/pyproject.toml',1024*1024).decode())
    value=dict(schema_version=1,profile=PROFILE,policy_profile=policy['factory_offline_profile'],
        inventory_sha256=inventory['digest'],dependencies=deps,app_members_sha256=digest(_app_members(root,scratch)),
        product_version=project.get('project',{}).get('version'))
    return validate_declaration(value)


def validate_declaration(value):
    if (type(value) is not dict or set(value)!={'schema_version','profile','policy_profile','inventory_sha256',
            'dependencies','app_members_sha256','product_version'} or value['schema_version']!=1 or value['profile']!=PROFILE
            or type(value['product_version']) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.!+_-]{0,63}',value['product_version'])
            or type(value['dependencies']) is not list or not 1<=len(value['dependencies'])<=512
            or any(type(value[k]) is not str or not re.fullmatch('[a-f0-9]{64}',value[k])
                for k in ('inventory_sha256','app_members_sha256'))):
        _refuse()
    from .security_licenses import _policy
    _policy(dict(schema_version=1,project_repository='github.com/Dimkox/Getzilla',
        auto_allow=['MIT'],usage_distribution={},factory_offline_profile=value['policy_profile']))
    seen=set()
    fields={'ecosystem','name','version','manifest','usage','extras','artifact_filename','artifact_sha256',
        'artifact_source','distribution','delivery_kind','source_use_sha256'}
    for dep in value['dependencies']:
        if (type(dep) is not dict or set(dep)!=fields or dep['ecosystem']!='PyPI'
                or dep['manifest']!='factory/uv.lock' or dep['usage']!='runtime'
                or dep['distribution']!='redistributed' or dep['delivery_kind']!='factory-offline-archive'
                or type(dep['name']) is not str or dep['name'] in seen
                or not isinstance(dep['artifact_source'],str) or not dep['artifact_source'].startswith('https://files.pythonhosted.org/packages/')
                or type(dep['source_use_sha256']) is not list or not 1<=len(dep['source_use_sha256'])<=512
                or any(type(v) is not str or not re.fullmatch('[a-f0-9]{64}',v) for v in [dep['artifact_sha256'],*dep['source_use_sha256']])):
            _refuse()
        seen.add(dep['name'])
        _allowed_tags(dep['artifact_filename'])
    if len(json.dumps(value).encode())>MAX_INDEX_BYTES:
        _refuse('artifact-size')
    return json.loads(json.dumps(value))


def _allowed_tags(filename):
    from .security_python_target import _filename
    _,_,tags=_filename(filename)
    if not all(re.fullmatch(r'(?:py3|py2)-none-any|cp312-cp312-manylinux(?:2014|_2_17)_x86_64',tag) for tag in tags):
        _refuse('artifact-target-unknown')
    return sorted(tags)


def verify_wheel(dep,payload):
    """Exact final WHEEL and target tags, independent of the executing interpreter."""
    if hashlib.sha256(payload).hexdigest()!=dep['artifact_sha256']:
        _refuse('artifact-hash')
    tags=_allowed_tags(dep['artifact_filename'])
    files=archive_files(payload,dep['artifact_filename'])
    wheel=[name for name in files if name.endswith('.dist-info/WHEEL')]
    metadata=[name for name in files if name.endswith('.dist-info/METADATA')]
    if len(wheel)!=1 or len(metadata)!=1 or wheel[0].rsplit('/',1)[0]!=metadata[0].rsplit('/',1)[0]:
        _refuse()
    header=BytesParser().parsebytes(files[wheel[0]])
    if header.get_all('Wheel-Version')!=['1.0'] or header.get('Root-Is-Purelib') not in {'true','false'} or sorted(header.get_all('Tag',[]))!=tags:
        _refuse('artifact-target-unknown')
    from .security_artifacts import package_metadata,package_key
    actual=package_metadata(files,'PyPI',dep['artifact_filename'])
    if package_key('PyPI',actual['name'],actual['version'])!=package_key('PyPI',dep['name'],dep['version']):
        _refuse('artifact-identity')
    requires=BytesParser().parsebytes(files[metadata[0]]).get('Requires-Python')
    if requires:
        from pip._vendor.packaging.specifiers import SpecifierSet
        if not SpecifierSet(requires).contains('3.12',prereleases=False):
            _refuse('artifact-target-unknown')
    return tags


def output_inventory(declared,binding,environment=None):
    declared=validate_declaration(declared)
    context='factory-'+digest(dict(declaration=declared,source=binding['source'],run=binding['run']))
    deps=[{**{k:v for k,v in dep.items() if k!='source_use_sha256'},'delivery_context':context}
        for dep in declared['dependencies']]
    result=dict(complete=True,gaps=[],dependencies=deps,tools=[],images=[],marker_environment=environment or MARKERS)
    result['digest']=digest(result)
    return result


def _environment(value):
    if (type(value) is not dict or set(value)!=set(MARKERS)|{'python_full_version'}
            or any(value.get(k)!=v for k,v in MARKERS.items())
            or type(value['python_full_version']) is not str
            or not re.fullmatch(r'3\.12\.(?:0|[1-9][0-9]{0,5})',value['python_full_version'])):
        _refuse('artifact-target-unknown')
    return dict(value)


def _command(command,stage):
    from .python_test_runner import execute
    from .security_tools import _environment as command_environment
    from .security_cli import _preparation_step
    with _preparation_step('factory-target' if command[-1]=='--describe-target' else 'factory-output'):
        result=execute(command,stage,command_environment(stage),timeout=120)
        if result.returncode or result.terminal_state!='completed' or result.cleanup_error or len(result.stdout)>65536:
            _refuse('artifact-factory-output')
        return _json(result.stdout.encode())


def _catalog_bytes(root,*,now=None):
    from .security_artifacts import family_evidence
    raw=read_file(root,'manifest.json',MAX_INDEX_BYTES)
    bundle=_json(raw)
    total=len(raw)
    from .security_family_inputs import validate_frontiers
    total+=validate_frontiers(root,bundle.get('family_frontiers',[]),now=now,
        inventory_digest=bundle.get('inventory_digest'),records=bundle['records'])['bound_bytes']
    if total>MAX_TOTAL:
        _refuse('artifact-size')
    for record in bundle['records']:
        if 'kind' in record:
            total+=family_evidence(root,record)['bound_bytes']
        else:
            total+=len(read_file(root,record['path'],MAX_ARTIFACT_BYTES))
            total+=len(read_file(root,record['origin']['index_path'],MAX_INDEX_BYTES))
            if record.get('redistributed_path'):
                total+=len(read_file(root,record['redistributed_path'],MAX_ARTIFACT_BYTES))
        if total>MAX_TOTAL:
            _refuse('artifact-size')
    return total


def prepare(root,artifacts,tools,binding,checker,*,now=None,fetch=None):
    """Run only the trusted builder on exact clean source data and exact wheel bytes."""
    from .security_license_acquisition import acquire_pypi,_write
    from .manifest import _open_root
    from .security_licenses import load_policy
    from .security_cli import _preparation_step
    declared=validate_declaration(binding['factory_inputs'])
    # The caller has independently rederived the declaration and exact source binding.
    main_bytes=_catalog_bytes(artifacts,now=now)
    auxiliary=artifacts/'factory-output'
    auxiliary.mkdir(mode=0o700,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='factory-output-',dir=tools) as directory:
        stage=Path(directory)
        builder=read_file(checker,'factory/runtime/build_offline_release.py',1024*1024)
        helper=read_file(checker,'factory/runtime/setup_manager.py',1024*1024)
        if hashlib.sha256(builder).hexdigest()!=declared['policy_profile']['builder_sha256']:
            _refuse()
        for name,raw in [('build_offline_release.py',builder),('setup_manager.py',helper)]:
            (stage/name).write_bytes(raw)
        command=['/usr/bin/python3.12','-E','-s','-S','-B',str(stage/'build_offline_release.py')]
        observed=_command([*command,'--describe-target'],stage)
        if set(observed)!={'environment','pointer_bits','releaselevel'} or observed['pointer_bits']!=64 or observed['releaselevel']!='final':
            _refuse()
        environment=_environment(observed['environment'])
        inventory=output_inventory(declared,binding,environment)
        with _preparation_step('factory-acquisition'):
            bundle=acquire_pypi(inventory['dependencies'],auxiliary,inventory_digest=inventory['digest'],now=now,
                byte_budget=MAX_TOTAL-main_bytes,**({'fetch':fetch} if fetch is not None else {}))
        if bundle['gaps']:
            _refuse()
        wheelhouse=stage/'wheels'
        wheelhouse.mkdir(mode=0o700)
        for dep in inventory['dependencies']:
            record=select_artifact(dep,bundle['records'])
            raw=read_file(auxiliary,record['path'],MAX_ARTIFACT_BYTES)
            verify_wheel(dep,raw)
            (wheelhouse/dep['artifact_filename']).write_bytes(raw)
        if main_bytes+_catalog_bytes(auxiliary,now=now)>MAX_TOTAL:
            _refuse('artifact-size')
        stem=stage/'factory-output'
        built=_command([*command,'--repository',str(root),'--expected-head',binding['source']['head_sha'],
            '--wheelhouse',str(wheelhouse),'--inventory',str(root/'factory/runtime/runtime-wheels-linux-x86_64-cpython312.json'),
            '--output',str(stem),'--product-version',declared['product_version']],stage)
        if (set(built)!={'archive','manifest','sidecar','archive_sha256','manifest_sha256','source_head','profile','target_environment','host_enforced'}
                or built['source_head']!=binding['source']['head_sha'] or built['profile']!=PROFILE
                or built['host_enforced'] is not True or _environment(built['target_environment'])!=environment):
            _refuse('artifact-factory-output')
        descriptor=None
        published_bytes=main_bytes+_catalog_bytes(auxiliary,now=now)
        try:
            _,descriptor=_open_root(auxiliary)
            for kind,suffix in [('archive','.zip'),('manifest','.manifest.json'),('sidecar','.sha256')]:
                expected=Path(str(stem)+suffix)
                if built[kind]!=str(expected):
                    _refuse('artifact-factory-output')
                raw=read_file(stage,expected.name,MAX_ARTIFACT_BYTES if kind=='archive' else MAX_INDEX_BYTES)
                published_bytes+=len(raw)
                if published_bytes>MAX_TOTAL:
                    _refuse('artifact-size')
                if kind!='sidecar' and hashlib.sha256(raw).hexdigest()!=built[kind+'_sha256']:
                    _refuse('artifact-hash')
                _write(descriptor,expected.name,raw)
            context=inventory['dependencies'][0]['delivery_context']
            bundle['deliveries']=[dict(context=context,kind='factory-offline-archive',profile=PROFILE,
                path='factory-output.zip',sha256=built['archive_sha256'],manifest_path='factory-output.manifest.json',
                manifest_sha256=built['manifest_sha256'],sidecar_path='factory-output.sha256',
                components=[dict(artifact_id=artifact_identity(record),prefix='site-packages/') for record in bundle['records']])]
            _write(descriptor,'manifest.json',json.dumps(bundle,sort_keys=True,separators=(',',':')).encode())
            envelope=dict(schema_version=1,declaration_sha256=digest(declared),source=binding['source'],run=binding['run'],
                environment=environment,builder_sha256=hashlib.sha256(builder).hexdigest(),helper_sha256=hashlib.sha256(helper).hexdigest())
            _write(descriptor,'factory-input.json',json.dumps(envelope,sort_keys=True,separators=(',',':')).encode())
        finally:
            if isinstance(descriptor,int):
                os.close(descriptor)
        observed=verify(artifacts,binding,load_policy(checker),now=now,checker=checker)
        if main_bytes+observed['projection']['payload_size']>MAX_TOTAL:
            _refuse('artifact-size')
        return observed


def verify(artifacts,binding,policy,*,now=None,checker=None):
    """Recompute complete target, original-use, source-app and final composition joins."""
    from .security_licenses import artifact_catalog_source
    from .security_tools import TRUSTED_ROOT
    checker=TRUSTED_ROOT if checker is None else checker
    declared=validate_declaration(binding['factory_inputs'])
    if declared['policy_profile']!=policy.get('factory_offline_profile'):
        _refuse()
    root=artifacts/'factory-output'
    raw=read_file(root,'factory-input.json',MAX_INDEX_BYTES)
    envelope=_json(raw)
    expected=dict(schema_version=1,declaration_sha256=digest(declared),source=binding['source'],run=binding['run'],
        environment=_environment(envelope.get('environment')),builder_sha256=declared['policy_profile']['builder_sha256'],
        helper_sha256=hashlib.sha256(read_file(checker,'factory/runtime/setup_manager.py',1024*1024)).hexdigest())
    if envelope!=expected:
        _refuse()
    inventory=output_inventory(declared,binding,envelope['environment'])
    catalog=_json(read_file(root,'manifest.json',MAX_INDEX_BYTES))
    if len(catalog.get('records',[]))!=len(inventory['dependencies']) or len(catalog.get('deliveries',[]))!=1:
        _refuse()
    for dep in inventory['dependencies']:
        record=select_artifact(dep,catalog['records'])
        verify_wheel(dep,read_file(root,record['path'],MAX_ARTIFACT_BYTES))
    delivery=catalog['deliveries'][0]
    if delivery['context']!=inventory['dependencies'][0]['delivery_context']:
        _refuse()
    if _json(read_file(root,delivery['manifest_path'],MAX_INDEX_BYTES)).get('product_version')!=declared['product_version']:
        _refuse('artifact-factory-source-output')
    members=archive_inventory(read_file(root,delivery['path'],MAX_ARTIFACT_BYTES),delivery['path'])
    if digest({k:v for k,v in members.items() if k.startswith('app/')})!=declared['app_members_sha256']:
        _refuse('artifact-factory-source-output')
    projection=artifact_catalog_source(inventory,root,policy,now=now)
    projection['payload_size']+=len(raw)
    return dict(inventory=inventory,root=root,projection=projection)
