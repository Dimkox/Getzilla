#!/usr/bin/env python3
"""Release decision with an audit bundle: obligations, evidence and receipts of the exact tree.

  python3 scripts/getzilla_audit_bundle.py [--base REF] [--out DIR]

The bundle is canonical JSON with its own SHA-256 sidecar. It lists the EU AI Act obligation matrix
(when the compliance:eu-ai-act component is installed), the AI system register, and every local
receipt bound to the current tree fingerprint. ``release_decision`` is ``eligible`` only when the
obligations are met and a passing verification receipt covers this tree.

The bundle is evidence, not authority: the author's machine produced it. The independent release
decision is the same command run by Trust CI on the exact commit, whose signed attestation covers it.
Exit code 0 means eligible, 1 blocked, 2 the bundle could not be built.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess  # nosec B404 - fixed git argv below
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def _git(root: Path, *args: str) -> str:
    return subprocess.run(['git', '-C', str(root), *args], capture_output=True, text=True, encoding='utf-8',  # nosec B603 B607
                          check=True).stdout.strip()


def build(root: Path, base: str | None) -> dict[str, object]:
    sys.path.insert(0, str(root / '.getzilla'))
    from getzilla import eu_ai_act
    from getzilla.util import runtime_dir, tree_fingerprint

    if _git(root, 'status', '--porcelain', '--untracked-files=no'):
        raise RuntimeError('the audit bundle needs a clean committed tree')
    head = _git(root, 'rev-parse', 'HEAD')
    fingerprint = tree_fingerprint(root)
    receipts = []
    for path in sorted((runtime_dir(root) / 'receipts').glob('*/*.json')):
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and data.get('tree_fingerprint') == fingerprint:
            receipts.append({'route_id': path.parent.name, 'kind': data.get('kind', path.stem),
                             'status': data.get('status'), 'created_at': data.get('created_at'),
                             'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    reasons: list[str] = []
    review: list[str] = []
    compliance: dict[str, object] = {'eu_ai_act': None}
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
    if not any(item['kind'] == 'verification' and item['status'] == 'pass' for item in receipts):
        reasons.append('no passing verification receipt for this tree; run scripts/getzilla_verify.py --mode release')
    return {
        'schema_version': 'getzilla-audit-bundle-v1',
        'version': (root / 'VERSION').read_text(encoding='utf-8').strip() if (root / 'VERSION').is_file() else None,
        'commit': head,
        'tree': _git(root, 'rev-parse', 'HEAD^{tree}'),
        'tree_fingerprint': fingerprint,
        'comparison_base': base,
        'compliance': compliance,
        'receipts': receipts,
        'release_decision': 'blocked' if reasons else 'review' if review else 'eligible',
        'reasons': reasons + review,
        'authority': 'evidence only; the independent decision is Trust CI running this command on the exact commit',
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--base', help='comparison base for changed AI code (for example the previous release tag)')
    parser.add_argument('--out', type=Path, help='output directory (default .getzilla/runtime/audit)')
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        bundle = build(root, args.base)
    except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError) as exc:
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
