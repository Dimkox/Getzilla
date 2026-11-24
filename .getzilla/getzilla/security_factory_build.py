"""Trusted Factory output construction, separate from input/custody consumption."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import tempfile

def _command(command,stage):
    from . import security_factory_inputs as native
    from .python_test_runner import execute
    from .security_tools import _environment as command_environment
    from .public_security_context import _preparation_step
    with _preparation_step('factory-target' if command[-1]=='--describe-target' else 'factory-output'):
        result=execute(command,stage,command_environment(stage),timeout=120)
        if result.returncode or result.terminal_state!='completed' or result.cleanup_error or len(result.stdout)>65536:
            native._refuse('artifact-factory-output')
        return native._json(result.stdout.encode())


def _catalog_bytes(root,*,now=None):
    from . import security_factory_inputs as native
    from .security_artifacts import family_evidence
    raw=native.read_file(root,'manifest.json',native.MAX_INDEX_BYTES)
    bundle=native._json(raw)
    total=len(raw)
    from .security_family_inputs import validate_frontiers
    total+=validate_frontiers(root,bundle.get('family_frontiers',[]),now=now,
        inventory_digest=bundle.get('inventory_digest'),records=bundle['records'])['bound_bytes']
    if total>native.MAX_TOTAL:
        native._refuse('artifact-size')
    for record in bundle['records']:
        if 'kind' in record:
            total+=family_evidence(root,record)['bound_bytes']
        else:
            total+=len(native.read_file(root,record['path'],native.MAX_ARTIFACT_BYTES))
            total+=len(native.read_file(root,record['origin']['index_path'],native.MAX_INDEX_BYTES))
            if record.get('redistributed_path'):
                total+=len(native.read_file(root,record['redistributed_path'],native.MAX_ARTIFACT_BYTES))
        if total>native.MAX_TOTAL:
            native._refuse('artifact-size')
    return total


def prepare(root,artifacts,tools,binding,checker,*,now=None,fetch=None):
    """Run only the trusted builder on exact clean source data and exact wheel bytes."""
    from . import security_factory_inputs as native
    from .security_license_acquisition import acquire_pypi,_write
    from .manifest import _open_root
    from .security_license_contracts import load_policy
    from .public_security_context import _preparation_step
    declared=native.validate_declaration(binding['factory_inputs'])
    # The caller has independently rederived the declaration and exact source binding.
    main_bytes=native._catalog_bytes(artifacts,now=now)
    auxiliary=artifacts/'factory-output'
    auxiliary.mkdir(mode=0o700,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='factory-output-',dir=tools) as directory:
        stage=Path(directory)
        builder=native.read_file(checker,'factory/runtime/build_offline_release.py',1024*1024)
        helper=native.read_file(checker,'factory/runtime/setup_manager.py',1024*1024)
        if hashlib.sha256(builder).hexdigest()!=declared['policy_profile']['builder_sha256']:
            native._refuse()
        for name,raw in [('build_offline_release.py',builder),('setup_manager.py',helper)]:
            (stage/name).write_bytes(raw)
        command=['/usr/bin/python3.12','-E','-s','-S','-B',str(stage/'build_offline_release.py')]
        observed=native._command([*command,'--describe-target'],stage)
        if set(observed)!={'environment','pointer_bits','releaselevel'} or observed['pointer_bits']!=64 or observed['releaselevel']!='final':
            native._refuse()
        environment=native._environment(observed['environment'])
        inventory=native.output_inventory(declared,binding,environment)
        with _preparation_step('factory-acquisition'):
            bundle=acquire_pypi(inventory['dependencies'],auxiliary,inventory_digest=inventory['digest'],now=now,
                byte_budget=native.MAX_TOTAL-main_bytes,**({'fetch':fetch} if fetch is not None else {}))
        if bundle['gaps']:
            native._refuse()
        wheelhouse=stage/'wheels'
        wheelhouse.mkdir(mode=0o700)
        for dep in inventory['dependencies']:
            record=native.select_artifact(dep,bundle['records'])
            raw=native.read_file(auxiliary,record['path'],native.MAX_ARTIFACT_BYTES)
            native.verify_wheel(dep,raw)
            (wheelhouse/dep['artifact_filename']).write_bytes(raw)
        if main_bytes+native._catalog_bytes(auxiliary,now=now)>native.MAX_TOTAL:
            native._refuse('artifact-size')
        stem=stage/'factory-output'
        built=native._command([*command,'--repository',str(root),'--expected-head',binding['source']['head_sha'],
            '--wheelhouse',str(wheelhouse),'--inventory',str(root/'factory/runtime/runtime-wheels-linux-x86_64-cpython312.json'),
            '--output',str(stem),'--product-version',declared['product_version']],stage)
        if (set(built)!={'archive','manifest','sidecar','archive_sha256','manifest_sha256','source_head','profile','target_environment','host_enforced'}
                or built['source_head']!=binding['source']['head_sha'] or built['profile']!=native.PROFILE
                or built['host_enforced'] is not True or native._environment(built['target_environment'])!=environment):
            native._refuse('artifact-factory-output')
        descriptor=None
        published_bytes=main_bytes+native._catalog_bytes(auxiliary,now=now)
        try:
            _,descriptor=_open_root(auxiliary)
            for kind,suffix in [('archive','.zip'),('manifest','.manifest.json'),('sidecar','.sha256')]:
                expected=Path(str(stem)+suffix)
                if built[kind]!=str(expected):
                    native._refuse('artifact-factory-output')
                raw=native.read_file(stage,expected.name,native.MAX_ARTIFACT_BYTES if kind=='archive' else native.MAX_INDEX_BYTES)
                published_bytes+=len(raw)
                if published_bytes>native.MAX_TOTAL:
                    native._refuse('artifact-size')
                if kind!='sidecar' and hashlib.sha256(raw).hexdigest()!=built[kind+'_sha256']:
                    native._refuse('artifact-hash')
                _write(descriptor,expected.name,raw)
            context=inventory['dependencies'][0]['delivery_context']
            bundle['deliveries']=[dict(context=context,kind='factory-offline-archive',profile=native.PROFILE,
                path='factory-output.zip',sha256=built['archive_sha256'],manifest_path='factory-output.manifest.json',
                manifest_sha256=built['manifest_sha256'],sidecar_path='factory-output.sha256',
                components=[dict(artifact_id=native.artifact_identity(record),prefix='site-packages/') for record in bundle['records']])]
            _write(descriptor,'manifest.json',json.dumps(bundle,sort_keys=True,separators=(',',':')).encode())
            envelope=dict(schema_version=1,declaration_sha256=native.digest(declared),source=binding['source'],run=binding['run'],
                environment=environment,builder_sha256=hashlib.sha256(builder).hexdigest(),helper_sha256=hashlib.sha256(helper).hexdigest())
            _write(descriptor,'factory-input.json',json.dumps(envelope,sort_keys=True,separators=(',',':')).encode())
        finally:
            if isinstance(descriptor,int):
                os.close(descriptor)
        observed=native.verify(artifacts,binding,load_policy(checker),now=now,checker=checker)
        if main_bytes+observed['projection']['payload_size']>native.MAX_TOTAL:
            native._refuse('artifact-size')
        return observed
