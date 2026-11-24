"""Closed local Compose build inputs. Declarations are never build execution proof."""
from __future__ import annotations

import hashlib
import os
import re
import shlex
import stat
from pathlib import PurePosixPath

from .security_artifacts import read_file
from .security_oci import LIMITS


class BuildInputError(ValueError):
    pass


def _digest(value):
    from .security_inventory import canonical_digest
    return canonical_digest(value)


def _relative(base, value):
    if (not isinstance(value, str) or not value or '\\' in value or ':' in value
            or PurePosixPath(value).is_absolute() or '..' in value.split('/')):
        raise BuildInputError('local build path escapes or names a remote input')
    return str(PurePosixPath(base) / value)


def _scalar(node, label):
    if node is None or node.kind != 'scalar' or not isinstance(node.value, str):
        raise BuildInputError(f'{label} requires one explicit scalar')
    return node.value


def _mapping(node, label):
    if node is None or node.kind != 'mapping':
        raise BuildInputError(f'{label} requires a closed mapping')
    return node.value


def _choice(bindings, path, line, source_hash, expression):
    if not isinstance(bindings, list):
        return None
    rows = [row for row in bindings if all(row.get(k) == v for k, v in
            [('manifest', path), ('line', line), ('source_sha256', source_hash), ('source_reference', expression)])]
    if len(rows) > 1:
        raise BuildInputError('duplicate build source image selection')
    return rows[0] if rows else None


def _context_leaves(root, context, selected):
    """Refuse hidden/ignored inputs without opening their bytes or following links."""
    from .security_oci import _Root
    held = _Root(root)
    current = os.dup(held.fd)
    pending, observed, count = [], set(), 0
    directories = {str(parent) for name in selected for parent in PurePosixPath(name).parents}
    try:
        for name in PurePosixPath(context).parts:
            if name == '.':
                continue
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = child
        pending.append((current, PurePosixPath(context), 0))
        current = None
        while pending:
            fd, relative, depth = pending.pop()
            try:
                with os.scandir(fd) as entries:
                    for entry in entries:
                        count += 1
                        if count > 100000 or depth > 64:
                            raise BuildInputError('physical build context exceeds finite source bound')
                        path = str(relative / entry.name)
                        mode = entry.stat(follow_symlinks=False).st_mode
                        if stat.S_ISDIR(mode):
                            if path not in directories:
                                raise BuildInputError('physical build context has an unselected directory')
                            child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                            pending.append((child, relative / entry.name, depth + 1))
                        elif not stat.S_ISREG(mode) or path not in selected:
                            raise BuildInputError('physical build context has an unselected input or link')
                        else:
                            observed.add(path)
            finally:
                os.close(fd)
        if observed != set(selected):
            raise BuildInputError('physical build context differs from selected source closure')
    finally:
        if current is not None:
            os.close(current)
        for fd, _, _ in pending:
            os.close(fd)
        held.close()


def _instructions(text):
    pending, first = '', 0
    result = []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if re.match(r'#\s*(?:syntax|escape|check)\s*=', stripped, re.I):
            raise BuildInputError('Dockerfile parser directives are outside the closed build grammar')
        if not stripped or stripped.startswith('#'):
            continue
        if not pending:
            first = number
        pending += stripped.removesuffix('\\') + ' '
        if stripped.endswith('\\'):
            continue
        statement = pending.strip()
        if not re.match(r'(?:ARG|FROM|ENV|RUN|WORKDIR|COPY|USER|EXPOSE|ENTRYPOINT|CMD)\s', statement, re.I):
            raise BuildInputError('Dockerfile instruction is outside the closed current build grammar')
        result.append((first, statement))
        pending = ''
    if pending:
        raise BuildInputError('truncated Dockerfile continuation')
    return result


def describe_build(root, manifest, service, fields, files, bindings):
    """Capture all selected context bytes, not only the COPY subset or parsed manifests."""
    build = fields['build']
    model = _mapping(build, 'Compose build')
    if set(model) - {'context', 'dockerfile', 'args'} or not {'context', 'dockerfile'} <= set(model):
        raise BuildInputError('unknown or missing local Compose build key')
    context = _relative(str(PurePosixPath(manifest).parent), _scalar(model['context'], 'context'))
    dockerfile = _relative(context, _scalar(model['dockerfile'], 'dockerfile'))
    context_parts = PurePosixPath(context).parts
    selected = sorted(path for path in files if PurePosixPath(path).parts[:len(context_parts)] == context_parts)
    if not selected or dockerfile not in selected:
        raise BuildInputError('local build context/Dockerfile is not completely inventoried')
    _context_leaves(root, context, selected)
    rows, total, body = [], 0, None
    for path in selected:
        # read_file pins physical ancestry and the regular leaf, rejecting links.
        before = (root / path).stat(follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode):
            raise BuildInputError('local build context contains a link or non-regular input')
        raw = read_file(root, path, LIMITS['max_storage_bytes'] - total)
        after = (root / path).stat(follow_symlinks=False)
        if any(getattr(before, key) != getattr(after, key) for key in
               ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode')):
            raise BuildInputError('local build context changed during capture')
        total += len(raw)
        if total > LIMITS['max_storage_bytes']:
            raise BuildInputError('local build context exceeds existing storage bound')
        rows.append({'path': path, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                     'mode': 0o755 if before.st_mode & 0o111 else 0o644})
        if path == dockerfile:
            body = raw
    _context_leaves(root, context, selected)
    if body is None:
        raise BuildInputError('local Dockerfile bytes unavailable')
    text = body.decode('utf-8')
    source = read_file(root, manifest, 1024 * 1024)
    source_hash, file_hash = hashlib.sha256(source).hexdigest(), hashlib.sha256(body).hexdigest()
    arguments, froms = {}, []
    instructions = _instructions(text)
    for number, stripped in instructions:
        if re.match(r'#\s*syntax\s*=', stripped, re.I) or re.match(r'(?:ADD\s|COPY\s+--|RUN\s+--)', stripped, re.I):
            raise BuildInputError('Dockerfile needs unsupported remote/context/mount composition')
        argument = re.fullmatch(r'ARG\s+([A-Z][A-Z0-9_]*)(?:=(.*))?', stripped, re.I)
        if argument:
            if argument[1] in arguments:
                raise BuildInputError('duplicate Dockerfile build argument')
            arguments[argument[1]] = argument[2]
        if re.match(r'FROM\s', stripped, re.I):
            froms.append((number, stripped.split()[1:]))
    if len(froms) != 1 or froms[0][1] != ['${PYTHON_BASE_IMAGE}']:
        raise BuildInputError('local build requires the closed current Python base FROM form')
    arg_nodes = _mapping(model['args'], 'build args') if 'args' in model else {}
    if set(arg_nodes) - set(arguments) or 'PYTHON_BASE_IMAGE' not in arg_nodes:
        raise BuildInputError('build arguments are missing or not declared by Dockerfile')
    base = _choice(bindings, dockerfile, froms[0][0], file_hash, '${PYTHON_BASE_IMAGE}')
    supplied = {name: _scalar(value, 'build argument') for name, value in arg_nodes.items()}
    expression = supplied['PYTHON_BASE_IMAGE']
    if expression.startswith('${'):
        if not re.fullmatch(r'\$\{TRUST_CI_PYTHON_BASE_IMAGE:\?[^}]+\}', expression) or base is None:
            raise BuildInputError('build base argument needs its exact immutable FROM selection')
        supplied['PYTHON_BASE_IMAGE'] = base['reference']
    if not re.fullmatch(r'[^\s$@]+@sha256:[0-9a-f]{64}', supplied['PYTHON_BASE_IMAGE']):
        raise BuildInputError('build base is not an immutable image')
    if base and base['reference'] != supplied['PYTHON_BASE_IMAGE']:
        raise BuildInputError('Compose argument differs from Dockerfile base selection')
    optional = {'PUBLIC_CHECKER_REPOSITORY', 'PUBLIC_CHECKER_COMMIT', 'PUBLIC_CHECKER_TREE'}
    for name, default in arguments.items():
        if name not in supplied:
            if default is not None:
                supplied[name] = default
            elif name in optional:
                supplied[name] = ''  # existing private-image branch, never a checker promotion
            else:
                raise BuildInputError('unresolved Dockerfile argument')
        if '$' in supplied[name] or name in optional and supplied[name]:
            raise BuildInputError('dynamic build argument or unchecked checker promotion')
    for _, line in instructions:
        if not re.match(r'\s*COPY\s', line, re.I):
            continue
        values = shlex.split(line.strip()[5:])
        if len(values) < 2:
            raise BuildInputError('unsupported COPY source grammar')
        for value in values[:-1]:
            value = re.sub(r'\$\{([A-Z][A-Z0-9_]*)\}', lambda m: supplied.get(m[1], '$'), value)
            if value == 'requirements-*.txt':
                expected = {'requirements-build.txt', 'requirements-runner.txt',
                            'requirements-runtime.txt', 'requirements-test.txt'}
                matches = set()
                for row in rows:
                    relative = PurePosixPath(row['path']).relative_to(context)
                    name = relative.parts[0]
                    if name.startswith('requirements-') and name.endswith('.txt'):
                        if len(relative.parts) != 1:
                            raise BuildInputError('requirements COPY matched a directory')
                        matches.add(name)
                if matches != expected:
                    raise BuildInputError('requirements COPY differs from the four captured lock profiles')
                continue
            if '$' in value or re.search(r'[*?\[\]]', value):
                raise BuildInputError('unresolved COPY source')
            source_path = _relative(context, value)
            parts = PurePosixPath(source_path).parts
            if not any(PurePosixPath(row['path']).parts[:len(parts)] == parts for row in rows):
                raise BuildInputError('COPY source lacks complete selected context coverage')
    output_expression = 'compose-build:' + service
    output = _choice(bindings, manifest, build.line, source_hash, output_expression)
    literal = _scalar(fields['platform'], 'platform') if 'platform' in fields else None
    platform = literal or (output or base or {}).get('platform')
    if platform not in {'linux/amd64', 'linux/arm64'} or any(
            row and row.get('platform') != platform for row in (base, output)):
        raise BuildInputError('build platform is unresolved or conflicts with a selected image')
    result = {'manifest': manifest, 'service': service, 'line': build.line,
              'source_sha256': source_hash, 'context': context, 'dockerfile': dockerfile,
              'dockerfile_sha256': file_hash, 'context_files': rows,
              'context_sha256': _digest(rows), 'arguments': dict(sorted(supplied.items())),
              'platform': platform, 'source_reference': output_expression}
    result['recipe_sha256'] = _digest({key: result[key] for key in
        ('context', 'context_sha256', 'dockerfile', 'dockerfile_sha256', 'arguments', 'platform')})
    result['build_sha256'] = _digest(result)
    return result
