#!/usr/bin/env python3
"""Build a local audit bundle, or emit read-only EU audit execution evidence.

Normal bundles require a passing local verification receipt. --ci-check requires committed
EU opt-in and a comparison base, evaluates release obligations, writes only stdout and gives
no release eligibility. A trusted installed verifier can authenticate a signed CI execution;
that signature does not cover the bytes of a newly generated bundle.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess  # nosec B404
import sys
import threading
import time
from datetime import date, datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
VERIFIER_TIMEOUT = 30
VERIFIER_OUTPUT_LIMIT = 1024 * 1024
GIT_INVENTORY_TIMEOUT = 30
GIT_PATH_OUTPUT_LIMIT = 16 * 1024 * 1024
AUDIT_SCRIPT = 'scripts/getzilla_audit_bundle.py'


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def _git(root: Path, *args: str) -> str:
    return _git_bytes(root, *args).decode('utf-8', 'surrogateescape').strip()


def _git_bytes(root: Path, *args: str) -> bytes:
    from getzilla.project_ingestion import _env

    return subprocess.run(['git', '--no-replace-objects', '--no-optional-locks', '-c', 'core.fsmonitor=false',  # nosec B603 B607
                           '-c', 'core.untrackedCache=false', '-c', 'protocol.allow=never', '-C', str(root), *args],
                          capture_output=True, env=_env(), check=True, timeout=30).stdout


def _committed_blob(root: Path, head: str, relative: str) -> bytes | None:
    entry = _git(root, 'ls-tree', head, '--', relative)
    if not entry.startswith(('100644 ', '100755 ')):
        return None
    return _git_bytes(root, 'show', f'{head}:{relative}')


def _git_paths(root: Path, *args: str) -> set[str]:
    return _path_inventory(_git_bytes(root, *args))


def _path_inventory(raw: bytes) -> set[str]:
    if not raw:
        return set()
    if not raw.endswith(b'\0'):
        raise RuntimeError('malformed Git path inventory')
    paths = {os.fsdecode(path) for path in raw[:-1].split(b'\0')}
    if any(Path(path).is_absolute() or any(part in {'', '.', '..'} for part in path.split('/'))
           for path in paths):
        raise RuntimeError('malformed Git path inventory')
    return paths


def _receipt_untracked_paths(root: Path) -> set[str]:
    """Honor receipt ignore policy only for untracked paths, without Git redirection."""
    from getzilla import fsx

    git_dir = _git(root, 'rev-parse', '--absolute-git-dir')
    config_keys = {'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM', 'GIT_CONFIG_NOSYSTEM'}
    env = {key: value for key, value in os.environ.items()
           if not key.startswith('GIT_') or key in config_keys}
    env.update({'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0', 'GIT_NO_LAZY_FETCH': '1',
                'GIT_NO_REPLACE_OBJECTS': '1', 'LC_ALL': 'C'})
    argv = ['git', '--no-replace-objects', '--no-optional-locks', '--git-dir=' + git_dir,
            '--work-tree=' + str(root.resolve()), '-c', 'core.fsmonitor=false',
            '-c', 'core.untrackedCache=false', '-c', 'protocol.allow=never',
            'ls-files', '--others', '--exclude-standard', '-z']
    deadline = time.monotonic() + GIT_INVENTORY_TIMEOUT
    process = fsx.owned_popen(argv, cwd=root, env=env, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    expired = threading.Event()

    def stop() -> None:
        try:
            job = fsx.owned_job(process)
            if job:
                job.terminate(1)
            else:
                fsx.kill_process_tree(process.pid)
        except ProcessLookupError:
            pass

    def timeout() -> None:
        expired.set()
        stop()

    timer = threading.Timer(max(0, deadline - time.monotonic()), timeout)
    timer.daemon = True
    timer.start()
    try:
        output = process.stdout.read(GIT_PATH_OUTPUT_LIMIT + 1)
        if len(output) > GIT_PATH_OUTPUT_LIMIT:
            raise RuntimeError('Git inventory output exceeds limit')
        process.wait(timeout=max(0.001, deadline - time.monotonic()))
        if expired.is_set():
            raise RuntimeError('Git inventory timeout')
        if process.returncode != 0:
            raise RuntimeError('Git path inventory failed')
        return _path_inventory(output)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError('Git inventory timeout') from exc
    finally:
        timer.cancel()
        stop()
        process.wait(timeout=2)
        process.stdout.close()
        job = fsx.owned_job(process)
        if job:
            job.close()


def _tracked_changes(root: Path, head: str) -> set[str]:
    return (_git_paths(root, 'diff', '--name-only', '--no-renames', '-z', '--cached', head)
            | _git_paths(root, 'diff', '--name-only', '--no-renames', '-z', head))


def _audit_fingerprint(root: Path, head: str) -> str:
    """Keep the local receipt digest grammar, with one head and sanitized Git inventories."""
    from getzilla.util import _fingerprint_noise, file_sha256

    paths = _tracked_changes(root, head)
    indexed = _git_paths(root, 'ls-files', '--cached', '-z')
    for relative in _receipt_untracked_paths(root):
        if relative in paths or relative in indexed or not (
                _fingerprint_noise(relative) or relative.startswith('.qwen/tmp/')):
            paths.add(relative)
    digest = hashlib.sha256(head.encode())
    for relative in sorted(paths):
        digest.update(os.fsencode(relative))
        path = root / relative
        try:
            if path.is_symlink():
                digest.update(os.fsencode(os.readlink(path)))
            elif path.is_file():
                digest.update(file_sha256(path).encode())
            else:
                digest.update(b'MISSING')
        except OSError:
            digest.update(b'ERROR')
    return digest.hexdigest()


def _base(root: Path, base: str | None, *, required: bool = False) -> str | None:
    if not base:
        if required:
            raise ValueError('a comparison base is required (--base or TRUST_CI_BASE_SHA)')
        return None
    return _git(root, 'rev-parse', '--verify', '--end-of-options', base + '^{commit}')


def _committed_inputs(root: Path, *, require_opt_in: bool = False) -> tuple[str, dict[str, bytes | None]]:
    from getzilla import eu_ai_act, fsx

    head = _git(root, 'rev-parse', '--verify', 'HEAD^{commit}')
    if _tracked_changes(root, head):
        raise RuntimeError('the audit needs a clean committed tree')
    data_paths = {eu_ai_act.COMPLIANCE_CONFIG, eu_ai_act.OBLIGATIONS, eu_ai_act.REGISTRY,
                  '.getzilla/config/diff-risk-rules.json', '.getzilla/config/cost-providers.json'}
    paths = data_paths | {AUDIT_SCRIPT}
    # Check the union of committed and present executable inputs. Looking only at disk misses
    # deletions hidden from status by skip-worktree or assume-unchanged bits.
    committed = _git_bytes(root, 'ls-tree', '-r', '--name-only', '-z', head).decode('utf-8', 'surrogateescape')
    paths.update(name for name in committed.split('\0')
                 if name.startswith('.getzilla/getzilla/') and name.endswith('.py'))
    package = root / '.getzilla/getzilla'
    if package.exists():
        if fsx.is_link(package.lstat()):
            raise RuntimeError('audit source inputs must be committed regular files')
        for directory, directories, files in os.walk(package, followlinks=False):
            for name in directories:
                if fsx.is_link((Path(directory) / name).lstat()):
                    raise RuntimeError('audit source inputs must not contain symlinks')
            paths.update((Path(directory) / name).relative_to(root).as_posix() for name in files if name.endswith('.py'))
    inputs: dict[str, bytes | None] = {}
    for relative in sorted(paths):
        path = root / relative
        entry = _git(root, 'ls-tree', head, '--', relative)
        present = os.path.lexists(path)
        if not present and not entry:
            if relative in data_paths:
                inputs[relative] = None
            continue
        if not present or not entry.startswith(('100644 ', '100755 ')) or not path.is_file():
            raise RuntimeError(f'{relative} must be present as a committed regular file before audit')
        if any(fsx.is_link(parent.lstat()) for parent in (path, *path.parents)
               if parent != root and root in parent.parents):
            raise RuntimeError(f'{relative} must be a committed regular file without links')
        blob = _git_bytes(root, 'show', f'{head}:{relative}')
        if blob != path.read_bytes():
            raise RuntimeError(f'{relative} differs from committed audit input')
        if relative in data_paths:
            inputs[relative] = blob
    opted_in = eu_ai_act.config_enabled(inputs[eu_ai_act.COMPLIANCE_CONFIG])
    if require_opt_in and not opted_in:
        raise RuntimeError('CI audit requires enabled committed EU opt-in')
    if opted_in:
        for relative in sorted(data_paths - {eu_ai_act.REGISTRY}):
            if inputs[relative] is None:
                raise RuntimeError(f'{relative} must be present as a committed regular file before audit')
    return head, inputs


def _repository(root: Path, expected: str | None) -> str | None:
    if expected:
        if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', expected):
            raise ValueError('repository must be owner/name')
        return expected
    try:
        remote = _git(root, 'remote', 'get-url', 'origin')
    except subprocess.CalledProcessError:
        return None
    match = re.fullmatch(r'(?:https://github\.com/|git@github\.com:)([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?', remote)
    return match.group(1) if match else None


def _audit_argv(argv: object, base: str) -> bool:
    """Closed invocation grammar: actual script execution, no wrapper or extra options."""
    if not isinstance(argv, list) or not all(isinstance(arg, str) for arg in argv):
        return False
    if len(argv) not in (3, 5) or argv[0] not in {'python', 'python3', 'python3.12'}:
        return False
    if argv[1:3] != [AUDIT_SCRIPT, '--ci-check']:
        return False
    return len(argv) == 3 or argv[3:] == ['--base', base]


def attestation_problem(payload: object, commit: str, base: str | None, repository: str | None) -> str | None:
    if not isinstance(payload, dict):
        return 'attestation payload must be an object'
    if type(payload.get('schema_version')) is not int or payload['schema_version'] != 2:
        return 'attestation schema_version must be 2 for EU execution evidence'
    for key, expected in (('status', 'passed'), ('head_sha', commit), ('base_sha', base), ('repository', repository)):
        if expected is None or payload.get(key) != expected:
            return f'attestation {key} does not match the audited source'
    results = payload.get('command_results')
    if not isinstance(results, list) or not any(
            isinstance(item, dict) and item.get('status') == 'pass' and type(item.get('exit_code')) is int
            and item['exit_code'] == 0 and _audit_argv(item.get('argv'), base)
            for item in results):
        return 'attestation has no successful EU audit --ci-check command with signed argv'
    if any(not isinstance(payload.get(key), str) or not payload[key]
           for key in ('attestation_id', 'key_id', 'policy_digest')):
        return 'attestation identity metadata is missing'
    return None


def verify_attestation(root: Path, attestation: Path, public_key: Path, verifier: Path | None) -> dict:
    """Call the independently installed verifier with bounded output and no project imports.

    The executable and public key are operator trust inputs, not repository merge authority.
    Never discover executables from the project's PATH or run with its cwd/PYTHONPATH.
    """
    from getzilla import fsx

    if verifier is None:
        found = shutil.which('adaptive-trust-ci', path=os.defpath)
        verifier = Path(found) if found else None
    if verifier is None or not verifier.is_absolute():
        raise ValueError('a trusted absolute attestation verifier executable is required')
    verifier = verifier.resolve()
    if verifier == root.resolve() or root.resolve() in verifier.parents:
        raise ValueError('attestation verifier must be installed outside the audited project')
    if not verifier.is_file():
        raise ValueError('trusted attestation verifier executable is unavailable')
    environment = {'PATH': os.defpath, 'PYTHONNOUSERSITE': '1', 'PYTHONSAFEPATH': '1',
                   'PYTHONUTF8': '1', 'LANG': 'C.UTF-8'}
    if os.name == 'nt' and 'SystemRoot' in os.environ:
        environment['SystemRoot'] = os.environ['SystemRoot']
    argv = [str(verifier), 'attestation-verify', '--attestation', str(attestation.resolve()),
            '--public-key', str(public_key.resolve())]
    output = bytearray()
    overflow = threading.Event()
    deadline = time.monotonic() + VERIFIER_TIMEOUT
    try:
        process = fsx.owned_popen(argv, cwd=verifier.parent, env=environment, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except OSError as exc:
        raise ValueError('attestation verifier could not start') from exc

    def stop() -> None:
        job = fsx.owned_job(process)
        try:
            if job:
                job.terminate(1)
            else:
                fsx.kill_process_tree(process.pid)
        except ProcessLookupError:
            pass

    def read() -> None:
        while True:
            chunk = process.stdout.read(65536)
            if not chunk:
                return
            available = VERIFIER_OUTPUT_LIMIT + 1 - len(output)
            output.extend(chunk[:max(0, available)])
            if len(output) > VERIFIER_OUTPUT_LIMIT:
                overflow.set()
                stop()
                return

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    try:
        try:
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
            reader.join(timeout=max(0, deadline - time.monotonic()))
            if reader.is_alive():
                raise subprocess.TimeoutExpired(argv, VERIFIER_TIMEOUT)
        except subprocess.TimeoutExpired as exc:
            stop()
            process.wait(timeout=2)
            reader.join(timeout=2)
            raise ValueError('attestation verifier timeout') from exc
        if overflow.is_set():
            raise ValueError('attestation verifier output exceeds limit')
        if process.returncode != 0:
            raise ValueError('attestation verifier rejected the envelope or public key')
        try:
            payload = json.loads(output)
        except (ValueError, UnicodeError) as exc:
            raise ValueError('attestation verifier returned malformed JSON') from exc
        if not isinstance(payload, dict):
            raise ValueError('attestation verifier returned a non-object payload')
        return payload
    finally:
        stop()
        process.stdout.close()
        job = fsx.owned_job(process)
        if job:
            job.close()


def _compliance(root: Path, base: str | None, head: str, today: date,
                inputs: dict[str, bytes | None]) -> tuple[dict, list[str], list[str]]:
    from getzilla import eu_ai_act

    reasons: list[str] = []
    review: list[str] = []
    mapping = eu_ai_act.parse_iso_map(_committed_blob(root, head, eu_ai_act.ISO_MAP))
    compliance: dict[str, object] = {
        'eu_ai_act': None,
        'iso42001': {'gating': False, 'map': mapping, 'note': eu_ai_act.ISO_NOTE} if mapping is not None else None,
    }
    if inputs[eu_ai_act.OBLIGATIONS] is not None and eu_ai_act.config_enabled(inputs[eu_ai_act.COMPLIANCE_CONFIG]):
        report = eu_ai_act.evaluate(root, 'release', [base] if base else [], head, today=today, audit_inputs=inputs)
        registry = inputs[eu_ai_act.REGISTRY]
        compliance['eu_ai_act'] = {
            **report.to_dict(),
            'obligations_sha256': hashlib.sha256(inputs[eu_ai_act.OBLIGATIONS]).hexdigest(),
            'registry_sha256': hashlib.sha256(registry).hexdigest() if registry is not None else None,
            'registry': json.loads(registry) if registry is not None else None,
        }
        if report.status != 'pass':
            (review if report.decision == 'review' else reasons).extend(report.problems or [report.summary])
    return compliance, reasons, review


def ci_check(root: Path, base: str | None, *, repository: str | None = None) -> dict:
    """Read-only evidence output. It cannot assert release eligibility or create a receipt."""
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        today = datetime.now(timezone.utc).date()
        head, inputs = _committed_inputs(root, require_opt_in=True)
        base = _base(root, base, required=True)
        compliance, reasons, review = _compliance(root, base, head, today, inputs)
        report = compliance.get('eu_ai_act')
        if not isinstance(report, dict) or report.get('status') not in {'pass', 'fail'}:
            raise RuntimeError('CI audit requires an evaluated EU compliance report')
        return {'schema_version': 'getzilla-eu-audit-check-v1', 'commit': head, 'comparison_base': base,
                'repository': _repository(root, repository), 'authority': 'evidence-only',
                'decision': 'block' if reasons else 'review' if review else 'pass',
                'reasons': reasons + review, 'compliance': compliance}
    finally:
        sys.dont_write_bytecode = previous


def build(root: Path, base: str | None, *, attestation: Path | None = None, public_key: Path | None = None,
          verifier: Path | None = None, repository: str | None = None) -> dict[str, object]:
    from getzilla.util import runtime_dir

    if bool(attestation) != bool(public_key):
        raise ValueError('attestation and public-key must be supplied together')
    today = datetime.now(timezone.utc).date()
    head, inputs = _committed_inputs(root, require_opt_in=attestation is not None)
    base = _base(root, base, required=attestation is not None)
    fingerprint = _audit_fingerprint(root, head)
    receipts = []
    for path in sorted((runtime_dir(root) / 'receipts').glob('*/*.json')):
        try:
            content = path.read_bytes()
            data = json.loads(content)
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and data.get('tree_fingerprint') == fingerprint:
            receipts.append({'route_id': path.parent.name, 'kind': data.get('kind', path.stem),
                             'status': data.get('status'), 'created_at': data.get('created_at'),
                             'sha256': hashlib.sha256(content).hexdigest()})
    compliance, reasons, review = _compliance(root, base, head, today, inputs)
    if not any(item['kind'] == 'verification' and item['status'] == 'pass' for item in receipts):
        reasons.append('no passing verification receipt for this tree; run scripts/getzilla_verify.py --mode release')
    version = _committed_blob(root, head, 'VERSION')
    bundle = {
        'schema_version': 'getzilla-audit-bundle-v1',
        'version': version.decode('utf-8', 'replace').strip() if version is not None else None,
        'commit': head, 'tree': _git(root, 'rev-parse', head + '^{tree}'), 'tree_fingerprint': fingerprint,
        'comparison_base': base, 'repository': _repository(root, repository),
        'compliance': compliance, 'receipts': receipts,
        'authority': 'evidence only; the independent decision is Trust CI running this command on the exact commit',
    }
    if attestation is not None:
        try:
            payload = verify_attestation(root, attestation, public_key, verifier)
            problem = attestation_problem(payload, head, base, bundle['repository'])
            if problem:
                reasons.append(problem)
            else:
                bundle['attestation'] = {key: payload[key] for key in
                                         ('attestation_id', 'key_id', 'policy_digest', 'head_sha', 'base_sha', 'repository')}
                bundle['attestation']['scope'] = 'CI audit execution; not regenerated bundle bytes'
                bundle['authority'] = 'trust-ci-attested'
        except (OSError, ValueError) as exc:
            reasons.append(f'attestation rejected: {exc}')
    bundle['release_decision'] = 'blocked' if reasons else 'review' if review else 'eligible'
    bundle['reasons'] = reasons + review
    return bundle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--base', help='comparison base; defaults to TRUST_CI_BASE_SHA')
    parser.add_argument('--repository', help='expected owner/name; otherwise use the GitHub origin')
    parser.add_argument('--out', type=Path, help='bundle directory (default .getzilla/runtime/audit)')
    parser.add_argument('--ci-check', action='store_true', help='read-only EU execution evidence; no receipts or release claim')
    parser.add_argument('--attestation', type=Path)
    parser.add_argument('--public-key', type=Path)
    parser.add_argument('--attestation-verifier', type=Path, help='trusted absolute installed adaptive-trust-ci executable')
    args = parser.parse_args(argv)
    if bool(args.attestation) != bool(args.public_key):
        parser.error('--attestation and --public-key must be supplied together')
    if args.ci_check and any((args.out, args.attestation, args.public_key, args.attestation_verifier)):
        parser.error('--ci-check cannot write a bundle or consume an attestation')
    root = args.root.resolve()
    base = args.base or os.environ.get('TRUST_CI_BASE_SHA')
    repository = args.repository or os.environ.get('TRUST_CI_REPOSITORY')
    try:
        if args.ci_check:
            result = ci_check(root, base, repository=repository)
            print(json.dumps(result, indent=2))
            return 0 if result['decision'] == 'pass' else 1
        bundle = build(root, base, attestation=args.attestation, public_key=args.public_key,
                       verifier=args.attestation_verifier, repository=repository)
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}))
        return 2
    out = args.out or root / '.getzilla' / 'runtime' / 'audit'
    out.mkdir(parents=True, exist_ok=True)
    content = _canonical(bundle) + b'\n'
    digest = hashlib.sha256(content).hexdigest()
    name = f'audit-{bundle["commit"][:12]}.json'
    (out / name).write_bytes(content)
    (out / f'{name}.sha256').write_text(f'{digest}  {name}\n', encoding='utf-8', newline='\n')
    print(json.dumps({'ok': True, 'bundle': str(out / name), 'sha256': digest,
                      'release_decision': bundle['release_decision'], 'reasons': bundle['reasons']}, indent=2))
    return 0 if bundle['release_decision'] == 'eligible' else 1


if __name__ == '__main__':
    raise SystemExit(main())
