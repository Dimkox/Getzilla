"""Canonical in-process image authority and rechecked held kernel proof.

Build orchestration installs and clears these exact private objects. Declarations
and readers cannot restore them. No allocator, daemon or pipeline lives here.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import stat

from .security_artifacts import read_file

CI_BYTES = 8 * 1024 ** 3
CI_MEMORY = 12 * 1024 ** 3


_ACTIVE = object()


_GUARD = None


_CI_CONTROLS = ('memory.max', 'memory.swap.max', 'pids.max', 'cgroup.procs', 'cpu.max')


class BackendUnavailable(ValueError):
    def __init__(self, message, *, detail=None):
        super().__init__(message)
        self.detail = dict(detail or {})


def _filesystem(path):
    # Linux statfs has ample trailing space on all supported 64-bit Linux ABIs.
    result = (ctypes.c_long * 32)()
    if ctypes.CDLL(None, use_errno=True).statfs(os.fsencode(path), ctypes.byref(result)):
        raise BackendUnavailable('cannot establish backend filesystem identity')
    return result[0]


def _ci_control_identity(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink


def _readonly_control(fd):
    import fcntl
    if fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY or os.get_inheritable(fd):
        raise ValueError('control descriptor is not read-only close-on-exec')


def _read_ci_control(controls, name):
    if name not in _CI_CONTROLS:
        raise ValueError('unknown CI control')
    fd, identity = controls[name]
    if type(fd) is not int or _ci_control_identity(os.fstat(fd)) != identity:
        raise ValueError('held control identity differs')
    _readonly_control(fd)
    raw = os.pread(fd, 4097, 0)
    if len(raw) > 4096:
        raise ValueError('kernel control exceeds bound')
    return raw.decode('ascii').strip()


def measured_ci_profile():
    """Recheck inherited held kernel proof; a dictionary or environment is insufficient."""
    if (_GUARD is None or len(_GUARD) != 4 or not isinstance(_GUARD[3], dict)
            or _GUARD[3].get('ci_corpus') is not True):
        return False
    check = 'ci-proof-identities'
    try:
        path, _nonce, _mounted, proof = _GUARD
        volume, cgroup = proof['volume_fd'], proof['cgroup_fd']
        if type(volume) is not int or type(cgroup) is not int:
            raise ValueError('missing held descriptors')
        info, group = os.fstat(volume), os.fstat(cgroup)
        current = os.stat(path, follow_symlinks=False)
        mounted = os.stat('/sys/fs/cgroup', follow_symlinks=False)
        if (not stat.S_ISDIR(info.st_mode) or not stat.S_ISDIR(group.st_mode)
                or (info.st_dev, info.st_ino) != proof['volume_identity']
                or (current.st_dev, current.st_ino) != proof['volume_identity']
                or (group.st_dev, group.st_ino) != (proof['cgroup_root_device'], proof['cgroup_root_inode'])
                or (mounted.st_dev, mounted.st_ino) != (group.st_dev, group.st_ino)
                or _filesystem(path) != 0x01021994 or _filesystem('/sys/fs/cgroup') != 0x63677270):
            raise ValueError('held kernel identity differs')
        check = 'ci-proof-volume'
        size = os.fstatvfs(volume)
        if size.f_blocks * size.f_frsize != CI_BYTES or size.f_flag & (os.ST_NOSUID | os.ST_NODEV) != os.ST_NOSUID | os.ST_NODEV:
            raise ValueError('held volume bound differs')
        check = 'ci-proof-controls'
        controls = proof['controls']
        if set(controls) != set(_CI_CONTROLS):
            raise ValueError('closed control set differs')
        def control(name):
            nonlocal check
            check = 'ci-control-' + name
            return _read_ci_control(controls, name)
        if (control('memory.max') != str(CI_MEMORY) or control('memory.swap.max') != '0'
                or control('pids.max') != '256' or str(os.getpid()) not in control('cgroup.procs').split()):
            raise ValueError('held resource controls differ')
        quota, period = control('cpu.max').split()
        check = 'ci-proof-cpu'
        if not 0 < int(quota) <= 6 * int(period) or not 0 < len(os.sched_getaffinity(0)) <= 6:
            raise ValueError('held CPU controls differ')
        return True
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        raise BackendUnavailable('live CI image kernel proof unavailable', detail={
            'phase': 'ci-kernel-proof', 'command_id': check, 'errno': getattr(error, 'errno', None),
            'cause': 'os-error' if isinstance(error, OSError) else 'identity-or-value'}) from error


_LIVE = None




_MEMBER_SEAL = object()


def require_builds(inventory, source, run):
    builds = inventory.get('builds', [])
    if not builds:
        return
    if _LIVE is None or _LIVE['source'] != source or _LIVE['run'] != run:
        raise BackendUnavailable('current source builds require the live owned producer')
    expected = {row['build_sha256'] for row in builds}
    if expected != set(_LIVE['builds']):
        raise BackendUnavailable('current build recipes differ from actual completed builds')
    for row in builds:
        matches = [use for use in inventory['images'] if use['manifest'] == row['manifest']
                   and use['line'] == row['line'] and use['source_reference'] == row['source_reference']]
        if len(matches) != 1 or matches[0]['reference'] != _LIVE['builds'][row['build_sha256']]:
            raise BackendUnavailable('current build output differs from actual completed graph')


def ci_use_observations(root,inventory,source,run,graphs):
    """Current owned CI consumers only; no restored JSON or host-to-image target credit."""
    if _LIVE is None:
        return None
    from .public_security_context import validate_selection_authority
    from .security_python_target import digest,_subject
    if _GUARD is None or _LIVE.get('native_guard') is not _GUARD:
        raise BackendUnavailable('CI use observation needs the live owned namespace')
    validate_selection_authority(source,run)
    require_builds(inventory,source,run)
    if inventory.get('builds')!=_LIVE.get('build_inputs'):
        raise BackendUnavailable('CI consumer graph differs from actual completed build inputs')
    consumers=[]
    for row in sorted(inventory.get('builds',[]),key=lambda item:(item['dockerfile'],item['build_sha256'])):
        recipe=row['dockerfile']
        from .security_python_target import ci_install_context
        context = ci_install_context(root, recipe)
        if context is None:
            continue
        if context['recipe_sha256'] != row['dockerfile_sha256']:
            raise BackendUnavailable('current CI recipe differs from its owned completed build')
        requirements = context['requirements']
        installed = context['install_requirements']
        proof=graphs.get('evidence',{})
        expected=graphs.get('graphs',{}).get('trust-ci/pyproject.toml#runtime',[])
        if (context['graph'] not in expected or recipe not in proof
                or any(proof.get(path) != sha for path, sha in {**context['source_inputs'], **installed}.items())):
            continue
        if hashlib.sha256(read_file(root,recipe,4*1024*1024)).hexdigest()!=proof[recipe]:
            raise BackendUnavailable('current CI consumer source changed')
        consumer = dict(recipe=recipe,recipe_sha256=row['recipe_sha256'],build_sha256=row['build_sha256'],
            image=_LIVE['builds'][row['build_sha256']],requirements=requirements,
            requirements_sha256=proof[requirements],install_requirements=installed,distribution='internal',purpose='isolated-public-ci',
            image_target_observed=False)
        observed = _LIVE.get('base_targets',{}).get(row['recipe_sha256'])
        if observed is not None:
            from .security_python_target import source_pins
            consumer.update(image_target_observed=True,base=observed['base'],target=observed['target'],
                supported_tags=observed['supported_tags'],site_packages=observed['site_packages'],
                base_observation={key:observed[key] for key in ('observer_manifest','observer_config','observer_recipe_sha256')
                                  if key in observed},
                source_pins=source_pins(root,inventory,observed['target']),
                dependencies=[dict(dep) for dep in inventory['dependencies'] if dep.get('ecosystem')=='PyPI'
                    and (dep.get('manifest') in installed or dep.get('manifest')=='trust-ci/pyproject.toml'
                         and (dep.get('usage') in {'runtime','build'} or dep.get('usage')=='optional'
                              and requirements in {'trust-ci/requirements-test.txt','trust-ci/requirements-runner.txt'}))])
        consumers.append(consumer)
    subjects={}
    for dep in inventory['dependencies']:
        if dep.get('ecosystem')!='PyPI':
            continue
        indexes=[]
        for index,consumer in enumerate(consumers):
            manifest=dep['manifest']
            direct=manifest in consumer['install_requirements']
            project=manifest=='trust-ci/pyproject.toml' and (
                dep['usage'] in {'runtime','build'} or dep['usage']=='optional'
                and consumer['requirements'] in {'trust-ci/requirements-test.txt','trust-ci/requirements-runner.txt'})
            if direct or project:
                indexes.append(index)
        if indexes:
            subjects[digest(_subject(dep))]=indexes
    value=dict(schema_version=1,source=source,run=run,inventory_sha256=inventory['digest'],
        closure_graphs_sha256=digest(graphs),subjects=subjects,consumers=consumers,
        assurance='observed CI use only; original production/customer uses and image targets remain separate')
    _LIVE['ci_uses']=json.loads(json.dumps(value))
    return json.loads(json.dumps(value))


def validate_ci_uses(value,source,run):
    if (_LIVE is None or _GUARD is None or _LIVE.get('native_guard') is not _GUARD
            or _LIVE['source']!=source or _LIVE['run']!=run or _LIVE.get('ci_uses')!=value):
        raise BackendUnavailable('current CI use observation cannot be restored from declarations')
    return json.loads(json.dumps(value))


def ci_member_evidence(value,source,run,index,paths):
    from .security_oci import read_members, scanner_identity
    uses=validate_ci_uses(value,source,run)
    if type(index) is not int or not 0<=index<len(uses['consumers']):
        raise BackendUnavailable('CI installation consumer is missing')
    consumer=uses['consumers'][index]
    image=_LIVE.get('images',{}).get(consumer['image'])
    if image is None or image.reference!=consumer['image'] or consumer.get('image_target_observed') is not True:
        raise BackendUnavailable('CI installation image proof is missing')
    facts=_LIVE.setdefault('member_facts',{})
    fact=facts.get(consumer['image'])
    valid=type(fact) is tuple and len(fact)==3 and fact[0] is _MEMBER_SEAL and fact[1] is image
    previous=fact[2] if valid else {}
    # Reuse decoded data only after fresh hashes of the entire actual graph.
    # No saved JSON can produce the seal or the live imported image object.
    if valid:
        scanner_identity(dict(Metadata=dict(ImageID=image.config_digest)),image)
    missing=[path for path in paths if path not in previous]
    if missing:
        current=read_members(image,missing)
        retained=_LIVE.get('member_fact_bytes',0)+sum(len(body) for body in current.values())
        if retained>16*1024*1024:
            raise BackendUnavailable('CI installation evidence exceeds retained byte bound')
        previous={**previous,**current}
        facts[consumer['image']]=(_MEMBER_SEAL,image,previous)
        _LIVE['member_fact_bytes']=retained
    return {path:previous[path] for path in paths}
