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
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
VERIFIER_TIMEOUT = 30
VERIFIER_OUTPUT_LIMIT = 1024 * 1024
AUDIT_SCRIPT = 'scripts/getzilla_audit_bundle.py'


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def _git(root: Path, *args: str) -> str:
    return subprocess.run(['git', '-C', str(root), *args], capture_output=True, text=True, encoding='utf-8',  # nosec B603 B607
                          check=True, timeout=30).stdout.strip()


def _base(root: Path, base: str | None, *, required: bool = False) -> str | None:
    if not base:
        if required:
            raise ValueError('a comparison base is required (--base or TRUST_CI_BASE_SHA)')
        return None
    return _git(root, 'rev-parse', '--verify', '--end-of-options', base + '^{commit}')


def _committed_inputs(root: Path, *, require_opt_in: bool = False) -> str:
    from getzilla import eu_ai_act

    if _git(root, 'status', '--porcelain', '--untracked-files=no'):
        raise RuntimeError('the audit needs a clean committed tree')
    head = _git(root, 'rev-parse', 'HEAD')
    if require_opt_in and not eu_ai_act.enabled(root):
        raise RuntimeError('CI audit requires enabled EU opt-in')
    paths = {eu_ai_act.COMPLIANCE_CONFIG, eu_ai_act.OBLIGATIONS, eu_ai_act.REGISTRY, AUDIT_SCRIPT}
    # Also check local executable inputs when installed in the audited tree. An ignored added
    # module must not change evaluation while the signed identity still names only HEAD.
    package = root / '.getzilla/getzilla'
    if package.exists():
        if package.is_symlink():
            raise RuntimeError('audit source inputs must be committed regular files')
        for directory, directories, files in os.walk(package, followlinks=False):
            for name in directories:
                if (Path(directory) / name).is_symlink():
                    raise RuntimeError('audit source inputs must not contain symlinks')
            paths.update((Path(directory) / name).relative_to(root).as_posix() for name in files if name.endswith('.py'))
    for relative in sorted(paths):
        path = root / relative
        if not path.exists() and not path.is_symlink():
            continue
        if any(parent.is_symlink() for parent in (path, *path.parents) if parent != root and root in parent.parents):
            raise RuntimeError(f'{relative} must be a committed regular file without links')
        entry = _git(root, 'ls-tree', head, '--', relative)
        if not entry.startswith(('100644 ', '100755 ')) or not path.is_file():
            raise RuntimeError(f'{relative} must be committed before audit')
        blob = subprocess.run(['git', '-C', str(root), 'show', f'{head}:{relative}'],  # nosec B603 B607
                              capture_output=True, check=True, timeout=30).stdout
        if blob != path.read_bytes():
            raise RuntimeError(f'{relative} differs from committed audit input')
    return head


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


def _compliance(root: Path, base: str | None) -> tuple[dict, list[str], list[str]]:
    from getzilla import eu_ai_act

    reasons: list[str] = []
    review: list[str] = []
    mapping = eu_ai_act.load_iso_map(root)
    compliance: dict[str, object] = {
        'eu_ai_act': None,
        'iso42001': {'gating': False, 'map': mapping, 'note': eu_ai_act.ISO_NOTE} if mapping is not None else None,
    }
    if eu_ai_act.enabled(root):
        report = eu_ai_act.evaluate(root, 'release', [base] if base else [], 'HEAD')
        registry = root / eu_ai_act.REGISTRY
        compliance['eu_ai_act'] = {
            **report.to_dict(),
            'obligations_sha256': hashlib.sha256((root / eu_ai_act.OBLIGATIONS).read_bytes()).hexdigest(),
            'registry_sha256': hashlib.sha256(registry.read_bytes()).hexdigest() if registry.is_file() else None,
            'registry': json.loads(registry.read_text(encoding='utf-8')) if registry.is_file() else None,
        }
        if report.status != 'pass':
            (review if report.decision == 'review' else reasons).extend(report.problems or [report.summary])
    return compliance, reasons, review


def ci_check(root: Path, base: str | None, *, repository: str | None = None) -> dict:
    """Read-only evidence output. It cannot assert release eligibility or create a receipt."""
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        head = _committed_inputs(root, require_opt_in=True)
        base = _base(root, base, required=True)
        compliance, reasons, review = _compliance(root, base)
        return {'schema_version': 'getzilla-eu-audit-check-v1', 'commit': head, 'comparison_base': base,
                'repository': _repository(root, repository), 'authority': 'evidence-only',
                'decision': 'block' if reasons else 'review' if review else 'pass',
                'reasons': reasons + review, 'compliance': compliance}
    finally:
        sys.dont_write_bytecode = previous


def build(root: Path, base: str | None, *, attestation: Path | None = None, public_key: Path | None = None,
          verifier: Path | None = None, repository: str | None = None) -> dict[str, object]:
    from getzilla.util import runtime_dir, tree_fingerprint

    if bool(attestation) != bool(public_key):
        raise ValueError('attestation and public-key must be supplied together')
    head = _committed_inputs(root, require_opt_in=attestation is not None)
    base = _base(root, base, required=attestation is not None)
    fingerprint = tree_fingerprint(root)
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
    compliance, reasons, review = _compliance(root, base)
    if not any(item['kind'] == 'verification' and item['status'] == 'pass' for item in receipts):
        reasons.append('no passing verification receipt for this tree; run scripts/getzilla_verify.py --mode release')
    bundle = {
        'schema_version': 'getzilla-audit-bundle-v1',
        'version': (root / 'VERSION').read_text(encoding='utf-8').strip() if (root / 'VERSION').is_file() else None,
        'commit': head, 'tree': _git(root, 'rev-parse', 'HEAD^{tree}'), 'tree_fingerprint': fingerprint,
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
