"""Current Linux Compose/OCI producer, consumed while owned resources stay live.

Build completion is private process state. A selection/catalog JSON file alone
never restores it. The existing OCI importer independently checks every graph.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
import hashlib
import gzip
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import tempfile
import time

from .security_artifacts import ArtifactError, read_file
from . import security_image_authority as authority
from .security_image_authority import (  # noqa: F401 compatibility function/seal aliases
    _MEMBER_SEAL,
    ci_member_evidence,
    ci_use_observations,
    require_builds,
    validate_ci_uses,
)
from .security_image_backend import BuildKit, _ACTIVE, BackendUnavailable, _diagnostic
from .security_image_registry import Registry, RegistryError
from .security_inventory import collect_inventory, declared_inventory
from .security_oci import LIMITS, active_limits, INDEX, MANIFEST, OCIError, canonical, document, _descriptor, import_layouts

_PHASE = 'opening'


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
    from .security_oci import _Root
    root, relative = Path(root), Path(relative)
    if (not root.is_relative_to(authority._GUARD[0]) or relative.is_absolute()
            or not relative.parts or '..' in relative.parts or len(relative.parts) > 64):
        raise BackendUnavailable('CI image output leaves its held volume')
    held = _Root(root)
    fd = None
    try:
        fd = os.dup(held.fd)
        if os.fstat(fd).st_dev != os.fstat(authority._GUARD[3]['volume_fd']).st_dev:
            raise BackendUnavailable('CI image output filesystem differs')
        for name in relative.parts[:-1]:
            try:
                os.mkdir(name, mode=0o700, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
            if os.fstat(fd).st_dev != os.fstat(authority._GUARD[3]['volume_fd']).st_dev:
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


def _build_recipe(root, recipe, volume, layout, builder):
    """Retain the completed graph and private recipe state until job teardown."""
    from .security_oci import _Root
    held = _Root(volume)
    directory = None
    try:
        name = Path(tempfile.mkdtemp(prefix='context-', dir=volume)).name
        directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=held.fd)
        birth = os.fstat(directory)
        if birth.st_uid != os.geteuid() or birth.st_mode & 0o077:
            raise BackendUnavailable('owned recipe directory permissions refused')
        scope = Path(volume) / name
        try:
            context, archive = scope / 'source', scope / 'export.tar'
            _copy_context(root, recipe, context)
            if builder.build(recipe, context, archive) is not _ACTIVE:
                raise BackendUnavailable('build port did not prove actual owned process completion')
            descriptor = _unpack_export(archive, layout)
        finally:
            current = os.stat(name, dir_fd=held.fd, follow_symlinks=False)
            if ((current.st_dev, current.st_ino, current.st_uid) != (birth.st_dev, birth.st_ino, birth.st_uid)
                    or not stat.S_ISDIR(current.st_mode) or current.st_mode & 0o077):
                raise BackendUnavailable('owned recipe directory identity changed')
            # Do not delete through a mutable recipe pathname. The existing
            # whole-job teardown reclaims this bounded ephemeral volume.
    finally:
        if directory is not None:
            os.close(directory)
        held.close()
    # This is the sole cache-retirement join: output bytes were fully copied
    # and hash checked before daemon cache pruning. Recipe state stays private
    # in the same bounded volume until whole-job teardown.
    builder.prune()
    return descriptor


def _binding(use, reference, platform='linux/amd64'):
    return {**{key: use[key] for key in ('manifest', 'line', 'source_sha256', 'source_reference')},
            'reference': reference, 'platform': platform}


def _choice_name(expression):
    match = re.fullmatch(r'\$\{(TRUST_CI_[A-Z_]+)(?::[?-][^}]*)?\}', expression)
    return match[1] if match else None


def registry_inputs(inventory):
    # A selected local recipe gets its binding only from its completed BuildKit export.
    keys = ("manifest", "line", "source_sha256", "source_reference")
    local = {tuple(recipe[k] for k in keys) for recipe in inventory.get("builds", ())}
    for use in inventory["images"]:
        if use["source_reference"].startswith("compose-build:"):
            if tuple(use[k] for k in keys) not in local:
                raise BackendUnavailable("local output lacks its source recipe")
        else:
            yield use


PG = "e80acae3f1109e8e4533618b594918936f2858c63afc7204c4773148a673add8"


def require_factory_pin(rows, pins):
    uses = [row["source_reference"] for row in rows if row["manifest"] == "factory/compose.yaml"]
    if uses != ["postgres:17-alpine@sha256:" + PG] or pins["postgres"]["reference"] != "postgres@sha256:" + PG:
        raise ValueError("Factory and the reviewed PostgreSQL server must use the same immutable image")


@contextmanager
def produce(root, source, run, volume, builder):
    """Acquire actual source graphs and build five recipes covering six uses."""
    if authority._LIVE is not None or type(builder) is not BuildKit:
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
    require_factory_pin(raw_inventory['images'], ci)
    choices = {'TRUST_CI_POSTGRES_IMAGE': ci['postgres']['reference'], '${PYTHON_BASE_IMAGE}': ci['python']['reference']}
    bindings, roots, resolved = [], {}, {}
    deferred = []
    for use in registry_inputs(raw_inventory):
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
    build_count = len(build_inventory.get('builds', []))
    deferred_codes = {'unresolved-image', 'missing-image-source-selection', 'unused-image-source-selection'}
    refused = [gap for gap in build_inventory['gaps'] if gap['code'] not in deferred_codes]
    expected_services = {'api','migrate','worker','runner-image','postgres-integration','docker-engine'}
    if (build_count != len(expected_services) or {r['service'] for r in build_inventory['builds']} != expected_services or refused):
        detail = refused[0]['code'] if refused else 'build-count'
        if refused and refused[0]['message'] == 'unresolved COPY source':
            detail += ': unresolved COPY source'
        raise BackendUnavailable(f'local build inventory: expected 6, found {build_count}; '
                                 f'{len(refused)} blocking gaps; first condition: {detail}')
    # The hard mounted volume contains every registry blob, context, cache and
    # output. Kernel ENOSPC refuses even while an untrusted build is running.
    for digest, raw in registry.blobs.items():
        _write(layout, 'blobs/sha256/' + digest[7:], raw)
    del registry.blobs
    from .security_oci import _Budget
    shared_budget=_Budget(dict(active_limits(),images=[],platform='linux/amd64'))
    shared_budget.deadline=min(shared_budget.deadline,deadline)
    base_targets,observed_bases={},{}
    completed, by_service, by_recipe = {}, {}, {}
    if builder.deadline > deadline:
        builder.deadline = deadline
    for recipe in build_inventory['builds']:
            identity = recipe['recipe_sha256']
            if identity not in by_recipe:
                from .security_tools import TRUSTED_ROOT
                from .security_ci_inputs import observe_base
                base=recipe['arguments'].get('PYTHON_BASE_IMAGE')
                if (recipe['dockerfile'] in {'trust-ci/Dockerfile.api','trust-ci/Dockerfile.worker','trust-ci/Dockerfile.test','trust-ci/runner.Dockerfile'}
                        and base==resolved[ci['python']['reference']][0]
                        and read_file(root,recipe['dockerfile'],4*1024*1024)==read_file(TRUSTED_ROOT,recipe['dockerfile'],4*1024*1024)):
                    if base not in observed_bases:
                        observed_bases[base]=observe_base(builder,base,volume,shared_budget)
                    base_targets[identity]=observed_bases[base]
                descriptor = _build_recipe(root, recipe, volume, layout, builder)
                reference = 'getzilla.local/build-' + identity + '@' + descriptor['digest']
                roots[reference] = descriptor
                by_recipe[identity] = reference
            reference = by_recipe[identity]
            completed[recipe['build_sha256']] = reference
            by_service[recipe['service']] = reference
            bindings.append(_binding(recipe, reference, recipe['platform']))
    built_choices = {'TRUST_CI_DIND_IMAGE': by_service['docker-engine'], 'TRUST_CI_API_IMAGE': by_service['api'], 'TRUST_CI_WORKER_IMAGE': by_service['worker'],
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
    with ExitStack() as verified:
        imported=verified.enter_context(import_layouts(catalog, inventory, profile, volume,_budget=shared_budget,measure_entries=True,index_components=True))
        from .public_security_context import selection_document, project_catalog
        from .public_security_context import _clock
        selection = selection_document(inventory, source, run, _clock().isoformat())
        declared = declared_inventory(root, selection)
        catalog = project_catalog(catalog, declared['digest'])
        authority._LIVE = dict(source=source, run=run, builds=completed,native_guard=authority._GUARD,
            build_inputs=json.loads(json.dumps(declared['builds'])),base_targets=base_targets,
            root=root,declared_inventory=json.loads(json.dumps(declared)),
            images={image.reference:image for image in imported})
        try:
            require_builds(declared, source, run)
            yield selection, catalog
        finally:
            authority._LIVE = None

def _event(stage):
    global _PHASE
    _PHASE = stage
    sys.stdout.write(json.dumps({'stage': stage}) + '\n')
    sys.stdout.flush()


def _pipeline_tools(request, volume):
    if active_limits()['max_storage_bytes'] > LIMITS['max_storage_bytes']:
        if Path(volume) != authority._GUARD[0]:
            raise BackendUnavailable('CI tools root differs from held image volume')
        return Path(volume) / 'tools'
    return Path(request['tools'])


def _postdrop_preflight(request, volume, builder):
    """Check fixed prerequisite roles as the actual controller UID, not root."""
    import ssl
    import sysconfig
    import _ssl
    import _socket
    import zlib
    from .security_image_registry import BoundedHTTP, RegistryError
    check = 'postdrop-volume'
    try:
        volume = Path(volume)
        if authority._GUARD is None or authority._GUARD[0] != volume or os.geteuid() == 0:
            raise ValueError('owned dropped controller required')
        tools = _pipeline_tools(request, volume)
        check = 'postdrop-resolver'
        with open('/etc/resolv.conf', 'rb') as stream:
            if len(stream.read(65537)) > 65536:
                raise ValueError('resolver exceeds existing bound')
        check = 'postdrop-python'
        if not os.access(sys.executable, os.R_OK | os.X_OK):
            raise ValueError('interpreter inaccessible')
        check = 'postdrop-bootstrap-files'
        modules = [Path(__file__), Path(__file__).with_name('security_image_registry.py'),
                   Path(__file__).with_name('security_oci.py'), Path(__file__).with_name('__init__.py'),
                   Path(sysconfig.get_path('stdlib')) / 'ssl.py']
        for module in (_ssl, _socket, zlib):
            filename = getattr(module, '__file__', None)
            if filename is not None:
                modules.append(Path(filename))
            elif module.__spec__.origin not in {'built-in', 'frozen'}:
                raise ValueError('native module origin unavailable')
        for path in modules:
            with path.open('rb') as stream:
                stream.read(1)
        check = 'postdrop-ca'
        ssl.create_default_context()
        check = 'postdrop-client'
        if not os.access(builder.client, os.R_OK | os.X_OK):
            raise ValueError('owned client inaccessible')
        check = 'postdrop-socket'
        if not stat.S_ISSOCK(builder.socket.stat().st_mode) or not os.access(builder.socket, os.W_OK):
            raise ValueError('owned socket inaccessible')
        check = 'postdrop-temp'
        with tempfile.TemporaryFile() as temporary:
            temporary.write(b'owned prerequisite')
            temporary.flush()
            if os.fstat(temporary.fileno()).st_dev != volume.stat().st_dev:
                raise ValueError('temporary leaves owned store')
        outputs = {'database': Path(request['database']), 'artifacts': Path(request['artifacts']), 'tools': tools,
                   'profile': Path(request['profile']).parent, 'preparation': Path(request['preparation']).parent,
                   'report': Path(request['report']).parent}
        for role, path in outputs.items():
            check = 'postdrop-output-' + role
            for _ in range(64):
                if path.exists():
                    break
                path = path.parent
            else:
                raise ValueError('output ancestry exceeds bound')
            if not path.is_dir() or not os.access(path, os.W_OK | os.X_OK):
                raise ValueError('output parent inaccessible')
        check = 'postdrop-python-worker'
        BoundedHTTP(deadline=builder.deadline).bootstrap()
    except RegistryError as error:
        error.detail['prerequisite'] = check
        raise
    except (OSError, ValueError, ImportError, AttributeError, TypeError) as error:
        raise BackendUnavailable('postdrop prerequisite refused', detail={
            'phase': 'postdrop-preflight', 'command_id': check,
            'errno': getattr(error, 'errno', None)}) from None


def _pipeline(request, volume, builder):
    global _PHASE
    _PHASE = 'producer'
    from . import security_cli as cli
    root = Path(request['root'])
    database, artifacts = (Path(request[key]) for key in ('database', 'artifacts'))
    tools = _pipeline_tools(request, volume)
    with cli._preparation_step('package-target'):
        from .security_python_target import observe_target
        package_target = observe_target()
    with tempfile.TemporaryDirectory(prefix='source-', dir=volume) as directory:
        source = cli.source_binding(root, cli.TRUSTED_ROOT, Path(directory))
        cli.validate_selection_authority(source, request['run'])
        with produce(root, source, request['run'], volume, builder) as (selection, catalog):
            selection_path, catalog_path = volume / 'selection.json', volume / 'catalog.json'
            _write(volume, selection_path.name, canonical(selection))
            _write(volume, catalog_path.name, canonical(catalog))
            options = dict(run=request['run'], image_artifacts=catalog_path, image_selection=selection_path,
                           package_target=package_target)
            _event('declare')
            profile = cli.prepare_inputs(root, database, artifacts, tools, write_profile=True, **options)
            cli._atomic(Path(request['report']).parent / 'security-run-inputs.json',
                        canonical(dict(selection=selection, catalog=catalog)))
            cli._atomic(Path(request['profile']), canonical(profile))
            _event('prepare')
            from .security_oci import ImageSecurityRefusal
            from .security_dind_exception import qualify
            try:
                state = authority._LIVE
                state['dind_exception'] = qualify(root, state['declared_inventory'], Registry(deadline=builder.deadline))
                with cli._preparation_step('prepare-inputs'):
                    preparation = cli.prepare_inputs(root, database, artifacts, tools, profile=profile,
                                                     refresh=True, provision=True, **options)
            except ArtifactError as error:
                # Identify the checker source statements without exposing inputs, exception
                # messages, URLs, local variables or host filesystem paths in diagnostics.
                frames = []
                frame = error.__traceback__
                while frame is not None and len(frames) < 32:
                    filename = Path(frame.tb_frame.f_code.co_filename)
                    if filename.parent == Path(__file__).parent and re.fullmatch(r'security_[a-z_]+\.py', filename.name):
                        frames.append([filename.name, frame.tb_lineno])
                    frame = frame.tb_next
                detail = dict(checker_frames=frames)
                if hasattr(error, 'catalog_budget'):
                    detail['catalog_budget'] = error.catalog_budget
                cli._atomic(Path(request['report']).parent / 'package-refusal.json', canonical(detail))
                raise
            except ImageSecurityRefusal as error:
                _event('evaluate')
                # A known image CVE or an unproved PostgreSQL assessment is a hard
                # refusal, including while the #456 infrastructure waiver exists.
                report = dict(error.report, license_evaluation=cli.LICENSE_EVALUATION, qualification="UNVERIFIED", source=source, run=request['run'])
                cli._atomic(Path(request['report']), canonical(report))
                return report
            finally:
                if state.get('dind_cli_removal'):
                    cli._atomic(Path(request['report']).parent / 'security-dind-cli.json',
                                canonical(dict(state['dind_cli_removal'], module_scan=state.get('dind_cli_module_scan'))))
            with cli._preparation_step('prepare-result'):
                cli._atomic(Path(request['preparation']), canonical(preparation))
                if preparation.get('status') != 'prepared':
                    raise BackendUnavailable('input preparation did not meet existing obligations')
            _event('evaluate')
            report = cli.evaluate(root, database, artifacts, tools, profile=profile, **options)
            servers = list(state.get("postgresql_servers", {}).values())
            if state.get("dind_cli_removal"):
                report["dind_cli_removal"] = state["dind_cli_removal"]
                cli._atomic(Path(request['report']).parent / 'security-dind-cli.json',
                            canonical(dict(state['dind_cli_removal'], module_scan=state.get('dind_cli_module_scan'))))
            if servers:
                report["postgresql_servers"] = servers
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
                cgroup_root_identity=authority._GUARD[3],
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
                    _postdrop_preflight(request, volume, builder)
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
            command = [str(volume / 'pinned-trivy'), 'image', '--scanners', 'secret', '--offline-scan',
                '--skip-db-update', '--skip-java-db-update', '--skip-version-check', '--format', 'json',
                '--input', str(image.layout) + '@' + image.manifest_digest, '--output', str(output)]
            code, _, stderr = _run_capped(command, cwd=volume, env={'PATH': os.defpath, 'HOME': str(volume),
                'TMPDIR': str(volume), 'TRIVY_CACHE_DIR': str(volume / 'trivy-cache')}, stdin_data=None,
                stdout_limit=1024, stderr_limit=4096, timeout=5)
            if code:
                from .security_image_backend import _diagnostic
                raise BackendUnavailable('pinned offline Trivy consumer refused', detail=dict(
                    phase='trivy-consumer', command_id='trivy-offline-control', exit_code=code, errno=None,
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
    from .security_oci import bound_fault
    from .public_security_context import _preparation_fault
    detail = dict(error.detail) if kind in (BackendUnavailable, RegistryError) else bound_fault(error)
    detail.pop('preparation', None)
    preparation = _preparation_fault(error)
    if preparation:
        detail['preparation'] = preparation
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
