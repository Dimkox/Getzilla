"""Current Linux Compose/OCI producer, consumed while owned resources stay live.

Build completion is private process state. A selection/catalog JSON file alone
never restores it. The existing OCI importer independently checks every graph.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import gzip
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile
import tempfile
import time

from .security_artifacts import read_file
from .security_image_backend import BuildKit, _ACTIVE, BackendUnavailable, _diagnostic
from .security_image_registry import Registry, RegistryError
from .security_inventory import collect_inventory, declared_inventory
from .security_oci import LIMITS, active_limits, INDEX, MANIFEST, OCIError, canonical, document, _descriptor, import_layouts

_LIVE = None
_PHASE = 'opening'


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


def _write(root, relative, raw):
    if active_limits()['max_storage_bytes'] > LIMITS['max_storage_bytes']:
        return _ci_write(root, relative, raw)
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists():
        if read_file(root, relative, active_limits()['max_storage_bytes']) != raw:
            raise BackendUnavailable('conflicting immutable producer artifact')
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)


def _ci_write(root, relative, raw):
    """Image outputs stay below held native volume, including through parents."""
    from . import security_image_backend as native
    from .security_oci import _Root
    root, relative = Path(root), Path(relative)
    if (not root.is_relative_to(native._GUARD[0]) or relative.is_absolute()
            or not relative.parts or '..' in relative.parts or len(relative.parts) > 64):
        raise BackendUnavailable('CI image output leaves its held volume')
    held = _Root(root)
    fd = None
    try:
        fd = os.dup(held.fd)
        if os.fstat(fd).st_dev != os.fstat(native._GUARD[3]['volume_fd']).st_dev:
            raise BackendUnavailable('CI image output filesystem differs')
        for name in relative.parts[:-1]:
            try:
                os.mkdir(name, mode=0o700, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
            if os.fstat(fd).st_dev != os.fstat(native._GUARD[3]['volume_fd']).st_dev:
                raise BackendUnavailable('CI image output parent leaves its bounded filesystem')
        try:
            output = os.open(relative.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=fd)
        except FileExistsError:
            if read_file(root, str(relative), active_limits()['max_storage_bytes']) != raw:
                raise BackendUnavailable('conflicting immutable producer artifact')
            return
        with os.fdopen(output, 'wb') as stream:
            stream.write(raw)
    finally:
        if fd is not None:
            os.close(fd)
        held.close()


def _unpack_export(archive, layout):
    """Extract only exact OCI members; never tarfile.extract or path/link fallback."""
    total, seen, index = 0, set(), None
    with tarfile.open(archive, 'r:') as stream:
        for member in stream:
            if member.isdir() and member.name.rstrip('/') in {'blobs', 'blobs/sha256'}:
                continue
            name = member.name
            if (name in seen or not member.isfile() or member.size < 0
                    or not (name in {'index.json', 'oci-layout'} or re.fullmatch(r'blobs/sha256/[0-9a-f]{64}', name))):
                raise BackendUnavailable('build export contains unsafe or unknown OCI member')
            seen.add(name)
            total += member.size
            if total > active_limits()['max_storage_bytes'] or len(seen) > 100002:
                raise BackendUnavailable('build export exceeds existing storage/member bound')
            source = stream.extractfile(member)
            if source is None:
                raise BackendUnavailable('build export member unavailable')
            with source:
                raw = source.read(member.size + 1)
            if len(raw) != member.size:
                raise BackendUnavailable('build export member truncated')
            if name.startswith('blobs/'):
                if hashlib.sha256(raw).hexdigest() != name.rsplit('/', 1)[1]:
                    raise BackendUnavailable('build export digest mismatch')
                _write(layout, name, raw)
            elif name == 'index.json':
                index = document(raw)
            elif document(raw) != {'imageLayoutVersion': '1.0.0'}:
                raise BackendUnavailable('build export layout version unsupported')
    if index is None or 'oci-layout' not in seen or len(index.get('manifests', [])) != 1:
        raise BackendUnavailable('build export must have one actual output graph')
    descriptor = index['manifests'][0]
    media, _, _ = _descriptor(descriptor)
    if media not in {INDEX, MANIFEST}:
        raise BackendUnavailable('build export root is not an image graph')
    return descriptor


def _copy_context(root, recipe, destination):
    destination.mkdir(mode=0o700)
    for row in recipe['context_files']:
        raw = read_file(root, row['path'], row['bytes'])
        if len(raw) != row['bytes'] or hashlib.sha256(raw).hexdigest() != row['sha256']:
            raise BackendUnavailable('source context changed before build')
        relative = str(PurePosixPath(row['path']).relative_to(recipe['context']))
        _write(destination, relative, raw)
        os.chmod(destination / relative, row['mode'])


def _binding(use, reference, platform='linux/amd64'):
    return {**{key: use[key] for key in ('manifest', 'line', 'source_sha256', 'source_reference')},
            'reference': reference, 'platform': platform}


def _choice_name(expression):
    match = re.fullmatch(r'\$\{(TRUST_CI_[A-Z_]+)(?::[?-][^}]*)?\}', expression)
    return match[1] if match else None


@contextmanager
def produce(root, source, run, volume, builder):
    """Acquire actual source graphs and build four recipes covering five uses."""
    global _LIVE
    if _LIVE is not None or type(builder) is not BuildKit:
        raise BackendUnavailable('nested build producer is forbidden')
    root, volume = Path(root), Path(volume)
    deadline = time.monotonic() + LIMITS['deadline_seconds']
    registry = Registry(deadline=deadline)
    layout = volume / 'oci'
    layout.mkdir(mode=0o700)
    raw_inventory = collect_inventory(root)
    if any(gap['code'] not in {'unresolved-image', 'unsupported-compose-composition'} for gap in raw_inventory['gaps']):
        raise BackendUnavailable('source inventory has uncovered inputs outside this producer')
    ci = document(read_file(root, '.getzilla/config/ci-images.json', 65536))
    if ci.get('schema_version') != 1 or ci.get('platform') != 'linux/amd64':
        raise BackendUnavailable('current source CI base image declaration is unsupported')
    choices = {'TRUST_CI_POSTGRES_IMAGE': ci['postgres']['reference'], '${PYTHON_BASE_IMAGE}': ci['python']['reference']}
    example = read_file(root, 'trust-ci/.env.example', 65536).decode()
    dind = re.findall(r'^TRUST_CI_DIND_IMAGE=([a-z0-9:/._-]+)@sha256:REPLACE_WITH_DIND_DIGEST$', example, re.M)
    if len(dind) != 1:
        raise BackendUnavailable('current source lacks one explicit DIND tag declaration')
    choices['TRUST_CI_DIND_IMAGE'] = dind[0]
    bindings, roots, resolved = [], {}, {}
    deferred = []
    for use in raw_inventory['images']:
        expression = use['source_reference']
        name = _choice_name(expression)
        target = choices.get(expression, choices.get(name, expression))
        if '$' in target:
            deferred.append(use)
            continue
        if target not in resolved:
            resolved[target] = registry.resolve(target, 'linux/amd64')
        reference, descriptor = resolved[target]
        roots[reference] = descriptor
        bindings.append(_binding(use, reference))
    build_inventory = collect_inventory(root, image_bindings=bindings)
    if len(build_inventory.get('builds', [])) != 5 or any(gap['code'] not in
            {'unresolved-image', 'missing-image-source-selection', 'unused-image-source-selection'} for gap in build_inventory['gaps']):
        raise BackendUnavailable('current source does not match the five closed local builds')
    # The hard mounted volume contains every registry blob, context, cache and
    # output. Kernel ENOSPC refuses even while an untrusted build is running.
    for digest, raw in registry.blobs.items():
        _write(layout, 'blobs/sha256/' + digest[7:], raw)
    del registry.blobs
    completed, by_service, by_recipe = {}, {}, {}
    if builder.deadline > deadline:
        builder.deadline = deadline
    for recipe in build_inventory['builds']:
            identity = recipe['recipe_sha256']
            if identity not in by_recipe:
                context, archive = volume / ('context-' + identity), volume / ('export-' + identity + '.tar')
                _copy_context(root, recipe, context)
                marker = builder.build(recipe, context, archive)
                if marker is not _ACTIVE:
                    raise BackendUnavailable('build port did not prove actual owned process completion')
                descriptor = _unpack_export(archive, layout)
                reference = 'getzilla.local/build-' + identity + '@' + descriptor['digest']
                roots[reference] = descriptor
                by_recipe[identity] = reference
                archive.unlink()
            reference = by_recipe[identity]
            completed[recipe['build_sha256']] = reference
            by_service[recipe['service']] = reference
            bindings.append(_binding(recipe, reference, recipe['platform']))
    built_choices = {'TRUST_CI_API_IMAGE': by_service['api'], 'TRUST_CI_WORKER_IMAGE': by_service['worker'],
        'TRUST_CI_RUNNER_IMAGE': by_service['runner-image'], 'TRUST_CI_RUNNER_BUILD_TAG': by_service['runner-image'],
        'TRUST_CI_TEST_BUILD_TAG': by_service['postgres-integration']}
    for use in deferred:
        reference = built_choices.get(_choice_name(use['source_reference']))
        if reference is None:
            raise BackendUnavailable('unresolved image use is outside the current build adapter')
        bindings.append(_binding(use, reference))
    inventory = collect_inventory(root, image_bindings=bindings)
    if not inventory['complete'] or {row['build_sha256'] for row in inventory['builds']} != set(completed):
        raise BackendUnavailable('source changed or remains uncovered after actual builds')
    descriptors = {value['digest']: value for value in roots.values()}
    _write(layout, 'oci-layout', canonical({'imageLayoutVersion': '1.0.0'}))
    _write(layout, 'index.json', canonical(dict(schemaVersion=2, mediaType=INDEX, manifests=list(descriptors.values()))))
    catalog = dict(schema_version=1, inventory_sha256=inventory['digest'], source_bindings=bindings,
                   records=[dict(reference=reference, platform='linux/amd64', layout=str(layout)) for reference in sorted(roots)])
    profile = dict(active_limits(), images=sorted(roots), platform='linux/amd64')
    # Validate the ORIGINAL catalog against independently recollected raw source
    # before any declaration projection. No producer success bypasses OCI checks.
    with import_layouts(catalog, inventory, profile, volume):
        pass
    from .public_security_context import selection_document, project_catalog
    from .security_cli import _clock
    selection = selection_document(inventory, source, run, _clock().isoformat())
    declared = declared_inventory(root, selection)
    catalog = project_catalog(catalog, declared['digest'])
    _LIVE = dict(source=source, run=run, builds=completed)
    try:
        require_builds(declared, source, run)
        yield selection, catalog
    finally:
        _LIVE = None


def _event(stage):
    global _PHASE
    _PHASE = stage
    sys.stdout.write(json.dumps({'stage': stage}) + '\n')
    sys.stdout.flush()


def _pipeline_tools(request, volume):
    if active_limits()['max_storage_bytes'] > LIMITS['max_storage_bytes']:
        from . import security_image_backend as native
        if Path(volume) != native._GUARD[0]:
            raise BackendUnavailable('CI tools root differs from held image volume')
        return Path(volume) / 'tools'
    return Path(request['tools'])


def _pipeline(request, volume, builder):
    global _PHASE
    _PHASE = 'producer'
    from . import security_cli as cli
    root = Path(request['root'])
    database, artifacts = (Path(request[key]) for key in ('database', 'artifacts'))
    tools = _pipeline_tools(request, volume)
    with tempfile.TemporaryDirectory(prefix='source-', dir=volume) as directory:
        source = cli.source_binding(root, cli.TRUSTED_ROOT, Path(directory))
        cli.validate_selection_authority(source, request['run'])
        with produce(root, source, request['run'], volume, builder) as (selection, catalog):
            selection_path, catalog_path = volume / 'selection.json', volume / 'catalog.json'
            _write(volume, selection_path.name, canonical(selection))
            _write(volume, catalog_path.name, canonical(catalog))
            options = dict(run=request['run'], image_artifacts=catalog_path, image_selection=selection_path)
            _event('declare')
            profile = cli.prepare_inputs(root, database, artifacts, tools, write_profile=True, **options)
            cli._atomic(Path(request['profile']), canonical(profile))
            _event('prepare')
            preparation = cli.prepare_inputs(root, database, artifacts, tools, profile=profile,
                                             refresh=True, provision=True, **options)
            cli._atomic(Path(request['preparation']), canonical(preparation))
            if preparation.get('status') != 'prepared':
                raise BackendUnavailable('input preparation did not meet existing obligations')
            _event('evaluate')
            report = cli.evaluate(root, database, artifacts, tools, profile=profile, **options)
            cli._atomic(Path(request['report']), canonical(report))
            # Both reports retain UNVERIFIED/fail when ordinary obligations fail.
            # Build completion never changes scanner/finalizer outcome.
            return report


def _worker():
    global _PHASE
    from . import security_image_backend as native
    request = document(sys.stdin.buffer.read(65537))
    if len(sys.argv) not in (3, 4) or len(sys.argv) == 4 and sys.argv[3] != 'ci-corpus' or not isinstance(request, dict):
        raise BackendUnavailable('invalid image worker dispatch')
    volume, cgroup = Path(sys.argv[1]), Path(sys.argv[2])
    _PHASE = 'kernel'
    with native.namespace_volume(volume, cgroup, ci_corpus=len(sys.argv) == 4):
        if isinstance(request, dict) and request.get('kind') == 'offline-tool-control':
            if set(request) != {'kind', 'tool', 'archive'} or request['tool'] not in {'trivy', 'buildkit'}:
                raise BackendUnavailable('invalid fixed offline tool control')
            result = _offline_tool_control(request, volume)
            for stage in ('declare', 'prepare', 'evaluate'):
                _event(stage)
            return _result(result)
        if request == {'kind': 'kernel-self-test'}:
            _write(volume, 'owned-control', b'owned kernel control\n')
            child = os.fork()
            if child == 0:
                os.setsid()
                time.sleep(60)
                os._exit(0)
            for stage in ('declare', 'prepare', 'evaluate'):
                _event(stage)
            return _result(dict(kind='image-kernel-control', qualification='UNVERIFIED',
                storage_bytes=os.statvfs(volume).f_blocks * os.statvfs(volume).f_frsize,
                namespace_cgroup=Path('/proc/self/cgroup').read_text(encoding='utf-8').strip(),
                control_readback={name: (Path('/sys/fs/cgroup') / name).read_text(encoding='utf-8').strip()
                                  for name in ('memory.max', 'memory.swap.max', 'pids.max', 'cpu.max')},
                owned_child_created=child > 1,
                cgroup_root_identity=native._GUARD[3],
                ordinary_file_verified=read_file(volume, 'owned-control', 4096) == b'owned kernel control\n'))
        keys = {'kind', 'root', 'database', 'artifacts', 'tools', 'profile', 'preparation', 'report', 'pins', 'run', 'uid', 'gid'}
        if (set(request) != keys or request['kind'] != 'pipeline' or type(request['uid']) is not int
                or type(request['gid']) is not int or request['uid'] <= 0 or request['gid'] <= 0):
            raise BackendUnavailable('invalid fixed image pipeline request')
        uid, gid = request['uid'], request['gid']
        os.chown(volume, uid, gid)
        with BuildKit(volume, deadline=time.monotonic() + LIMITS['deadline_seconds'], **request['pins']) as builder:
            builder.handoff_client(uid, gid)
            child = os.fork()
            if child == 0:
                try:
                    os.setgroups([])
                    os.setgid(gid)
                    os.setuid(uid)
                    os.environ.clear()
                    os.environ.update(PATH=os.defpath, LANG='C.UTF-8', PYTHONDONTWRITEBYTECODE='1')
                    report = _pipeline(request, volume, builder)
                    _result(report)
                    os._exit(0)
                except BaseException as error:
                    # Never echo candidate source, anonymous tokens or raw paths.
                    _fault(error)
                    os._exit(1)
            _, status = os.waitpid(child, 0)
            if status != 0:
                raise BackendUnavailable('owned image controller did not complete')
    return 0


def _offline_tool_control(request, volume):
    """Fixed nonsecret interface fixtures only; never a project or build claim."""
    from .architecture_diff import _run_capped
    from .security_oci import DOCKER_MANIFEST, DOCKER_CONFIG, DOCKER_GZIP
    with open('/proc/net/route', 'rb') as stream:
        raw_routes = stream.read(4097)
    if len(raw_routes) > 4096:
        raise BackendUnavailable('offline tool route observation exceeds bound')
    route = raw_routes.decode().splitlines()
    if len(route) > 1:
        raise BackendUnavailable('offline tool control has an unexpected network route')
    tool = request['tool']
    layout = volume / 'control-layout'
    layout.mkdir(mode=0o700)
    if tool == 'buildkit':
        context = volume / 'control-context'
        context.mkdir(mode=0o700)
        _write(context, 'Dockerfile', b'FROM scratch\nCOPY owned-marker /owned-marker\n')
        _write(context, 'owned-marker', b'owned build marker\n')
        archive = volume / 'control-export.tar'
        with BuildKit(volume, archive=request['archive'], deadline=time.monotonic() + 8) as builder:
            recipe = dict(context='.', dockerfile='Dockerfile', platform='linux/amd64', arguments={})
            uid, gid = os.environ.get('SUDO_UID', ''), os.environ.get('SUDO_GID', '')
            if not uid.isdecimal() or not gid.isdecimal() or int(uid) <= 0 or int(gid) <= 0:
                raise BackendUnavailable('offline build control needs its real sudo caller identity')
            uid, gid = int(uid), int(gid)
            builder.handoff_client(uid, gid)
            for path in (context, context / 'Dockerfile', context / 'owned-marker'):
                os.chown(path, uid, gid, follow_symlinks=False)
            child = os.fork()
            if child == 0:
                try:
                    os.setgroups([])
                    os.setgid(gid)
                    os.setuid(uid)
                    if builder.build(recipe, context, archive, offline_control=True) is not _ACTIVE:
                        raise BackendUnavailable('owned child build completion marker missing')
                    os._exit(0)
                except BaseException as error:
                    _fault(error)
                    os._exit(1)
            _, status = os.waitpid(child, 0)
            if status:
                raise BackendUnavailable('owned unprivileged control client did not complete',
                    detail=dict(phase='buildkit-client-handoff', command_id='owned-client-child', exit_code=os.waitstatus_to_exitcode(status)))
            descriptor = _unpack_export(archive, layout)
            identities = builder.tool_identities
        archive.unlink()
    else:
        from .security_acquisition import TRIVY_ARCHIVE_SHA256, trivy_binary
        archive = Path(request['archive'])
        raw = read_file(archive.parent, archive.name, 64 * 1024 * 1024)
        if hashlib.sha256(raw).hexdigest() != TRIVY_ARCHIVE_SHA256:
            raise BackendUnavailable('Trivy archive differs from existing selected source pin')
        binary = trivy_binary(raw)
        _write(volume, 'pinned-trivy', binary)
        os.chmod(volume / 'pinned-trivy', 0o500)
        identities = {'trivy': {'sha256': hashlib.sha256(binary).hexdigest(), 'bytes': len(binary)}}
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w') as archive:
            member = tarfile.TarInfo('owned-marker')
            member.size = len(b'owned marker\n')
            archive.addfile(member, io.BytesIO(b'owned marker\n'))
        tar = stream.getvalue()
        def blob(media, raw):
            digest = hashlib.sha256(raw).hexdigest()
            _write(layout, 'blobs/sha256/' + digest, raw)
            return dict(mediaType=media, digest='sha256:' + digest, size=len(raw))
        layer = blob(DOCKER_GZIP, gzip.compress(tar, mtime=0))
        config = blob(DOCKER_CONFIG, canonical(dict(architecture='amd64', os='linux',
            rootfs=dict(type='layers', diff_ids=['sha256:' + hashlib.sha256(tar).hexdigest()]))))
        descriptor = blob(DOCKER_MANIFEST, canonical(dict(schemaVersion=2, mediaType=DOCKER_MANIFEST,
                                                        config=config, layers=[layer])))
    _write(layout, 'oci-layout', canonical({'imageLayoutVersion': '1.0.0'}))
    _write(layout, 'index.json', canonical(dict(schemaVersion=2, mediaType=INDEX, manifests=[descriptor])))
    reference = 'owned.local/tool-control@' + descriptor['digest']
    inventory = dict(complete=True, gaps=[], images=[dict(reference=reference, platform='linux/amd64')])
    inventory['digest'] = hashlib.sha256(canonical(inventory)).hexdigest()
    catalog = dict(schema_version=1, inventory_sha256=inventory['digest'],
                   records=[dict(reference=reference, platform='linux/amd64', layout=str(layout))])
    profile = dict(LIMITS, images=[reference], platform='linux/amd64')
    with import_layouts(catalog, inventory, profile, volume) as images:
        image = images[0]
        marker_verified = False
        if tool == 'buildkit':
            manifest = document(read_file(image.layout, 'blobs/sha256/' + image.manifest_digest[7:], LIMITS['max_manifest_bytes']))
            if len(manifest['layers']) != 1:
                raise BackendUnavailable('scratch COPY control output has unexpected layers')
            layer = manifest['layers'][0]
            with tarfile.open(image.layout / 'blobs/sha256' / layer['digest'][7:], 'r|*') as stream:
                for member in stream:
                    image.remaining_seconds()
                    if member.name.removeprefix('./') == 'owned-marker' and member.isfile() and member.size == 19:
                        source = stream.extractfile(member)
                        with source:
                            marker_verified = source.read(20) == b'owned build marker\n'
            if not marker_verified:
                raise BackendUnavailable('scratch COPY control did not retain owned marker bytes')
        if tool == 'trivy':
            output = volume / 'trivy-consumer.json'
            command = [str(volume / 'pinned-trivy'), 'image', '--scanners', 'license', '--offline-scan',
                '--skip-db-update', '--skip-java-db-update', '--skip-version-check', '--format', 'json',
                '--input', str(image.layout) + '@' + image.manifest_digest, '--output', str(output)]
            code, _, stderr = _run_capped(command, cwd=volume, env={'PATH': os.defpath, 'HOME': str(volume),
                'TMPDIR': str(volume), 'TRIVY_CACHE_DIR': str(volume / 'trivy-cache')}, stdin_data=None,
                stdout_limit=1024, stderr_limit=4096, timeout=5)
            if code:
                from .security_image_backend import _diagnostic
                raise BackendUnavailable('pinned offline Trivy consumer refused', detail=dict(
                    phase='trivy-consumer', command_id='trivy-license-only', exit_code=code, errno=None,
                    stderr=_diagnostic(stderr)))
            report = document(read_file(volume, output.name, 16 * 1024 * 1024))
            from .security_oci import scanner_identity
            scanner_identity(report, image)
        return dict(kind='offline-tool-interface-control', tool=tool, qualification='UNVERIFIED',
                    manifest_digest=image.manifest_digest, config_digest=image.config_digest,
                    tool_identities=identities, network_routes=0, project_scanned=False,
                    owned_marker_verified=marker_verified if tool == 'buildkit' else None)


def _fault(error):
    kind = type(error)
    detail = dict(error.detail) if kind is BackendUnavailable else {}
    detail.setdefault('phase', _PHASE)
    detail.setdefault('command_id', 'worker')
    number = getattr(error, 'errno', None)
    detail.setdefault('errno', number if type(number) is int else None)
    detail.setdefault('exit_code', 1)
    detail['reason'] = 'worker operation refused'
    if (kind in (BackendUnavailable, RegistryError, OCIError) and len(error.args) == 1
            and type(error.args[0]) is str and len(error.args[0]) <= 4096):
        raw = error.args[0].encode('utf-8', errors='replace')
        if len(raw) <= 4096:
            detail['reason'] = _diagnostic(raw)['first'][:128]
    os.write(2, canonical({'fault': detail}) + b'\n')


def _entry():
    try:
        return _worker()
    except BaseException as error:
        _fault(error)
        return 1


def _result(value):
    sys.stdout.write(json.dumps({'result': value}, sort_keys=True, allow_nan=False) + '\n')
    sys.stdout.flush()
    return 0


def run_pipeline(args, run):
    from .security_image_job import run_job
    uid, gid = os.environ.get('SUDO_UID', ''), os.environ.get('SUDO_GID', '')
    if not uid.isdecimal() or not gid.isdecimal() or int(uid) <= 0 or int(gid) <= 0:
        raise BackendUnavailable('run the selected producer through sudo from the ephemeral runner user')
    path = args.backend_tool_pins.absolute()
    pins = document(read_file(path.parent, path.name, 16384))
    from .security_image_provision import VERSION, ARCHIVE_SHA256, ARCHIVE_SIZE
    if (not isinstance(pins, dict) or set(pins) != {'schema_version', 'version', 'archive', 'sha256', 'bytes'}
            or pins['schema_version'] != 1 or pins['version'] != VERSION
            or pins['sha256'] != ARCHIVE_SHA256 or pins['bytes'] != ARCHIVE_SIZE):
        raise BackendUnavailable('source-pinned BuildKit distribution is required')
    paths = {key: str(getattr(args, key).absolute()) for key in ('root', 'database', 'artifacts', 'tools')}
    outputs = dict(profile=str(args.input_profile.absolute()), report=str(args.json_out.absolute()),
                   preparation=str(args.json_out.absolute().with_name('security-input-preparation.json')))
    request = dict(kind='pipeline', **paths, **outputs, pins={'archive': pins['archive']}, run=run, uid=int(uid), gid=int(gid))
    payload = canonical(request)
    if len(payload) > 65536:
        raise BackendUnavailable('image producer request exceeds finite metadata bound')
    # This directory is private task runtime on a workstation, RUNNER_TEMP on
    # ephemeral GitHub runners. It never contains candidate source or user data.
    workspace = args.json_out.absolute().parent
    return run_job(payload, workspace, slice_name='system.slice', ci_corpus=getattr(args, 'ci_image_corpus', False))
