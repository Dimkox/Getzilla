# Getzilla rename rules

This is the exact script that produced the `rename:` commit of the Getzilla import from the predecessor at `c4e506f3d3a45e000f5b9f9121f698c1d16814e3` (final PR #242 head, tree-identical to its merged `f97966c`). It is kept as a record of what was renamed and what was deliberately kept; it is not part of the product and is not meant to be run again on this tree.

Later syncs extended `SCRIPTS` with names of new predecessor scripts (`m8`: `scripts/grok_m8.py`, predecessor PR #245) so they are renamed like the original ones.

Getzilla later replaced its root `README.md` with a short plain-language introduction. The script therefore ends by moving the predecessor's detailed README to `docs/REFERENCE.md` (relative links get a `../` prefix) and pointing the tests that read it there, so syncs bring predecessor README changes into the reference instead of the short README.

Follow-up commits on the same branch restored a few files byte-for-byte (checksum-bound migration 021, frozen v1 contracts) and quoted frozen predecessor records verbatim in tests; the script below already encodes those exclusions.

```python
#!/usr/bin/env python3
"""Rename the adaptive-grok-build-pro product identity to Getzilla.

Three kinds of "grok"/"adaptive" names live in this tree and only the first
is the product brand:

1. Product brand            -> renamed (package, stack dir, scripts, docs, URLs)
2. Grok Build CLI contract  -> kept    (.grok/ dir, `grok` binary, AGENTS.md)
3. Grok model provider      -> kept    (GROK_API_KEY_ENV, GROK_MODEL_ID, grok-4 ...)

Live-infrastructure identities are kept so the deployed services keep working:
Trust CI (adaptive-trust-ci*, adaptive_trust_ci*, TRUST_CI_*) and the L5
runtime (adaptive-l5*). Historical, hash-bound records are kept verbatim.

Usage: rename_to_getzilla.py <repo-root> [--dry-run]
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# Files whose text is a historical or hash-bound record: never rewritten.
FROZEN_PREFIXES = (
    'engineering/changes/',
    'docs/superpowers/',
    '.superpowers/',
    'tests/fixtures/',
    'factory/tests/fixtures/',
    'trust-ci/tests/fixtures/',
)
FROZEN_FILES = {
    'CHANGELOG.md',
    'mistakes.md',
    'decisions.md',
    'DARK_FACTORY_ROADMAP.md',
    'FACTORY_UNIFIED_UPGRADE_TZ_v1.5_FINAL.md',
    'FACTORY_TZ_v1.5_ADDENDUM_BB-01.md',
    'PROJECT_STATE.json',  # current-identity fields are edited by hand
    'LICENSE',
    # immutable, hash-pinned v1 contracts
    'factory/contracts/openapi/factory-control.v1.json',
    'factory/contracts/openapi/factory-execution.v1.json',
    'factory/contracts/jsonschema/static-landing-spec.v1.schema.json',
    'factory/contracts/openapi/landing-dogfood.v1.json',
}

SCRIPTS = (
    'agent', 'approve', 'architecture', 'artifacts', 'change', 'demo', 'deploy',
    'doctor', 'gate', 'governance', 'history', 'landing_publish', 'm8', 'protected_write',
    'review', 'route', 'spec', 'status', 'verify',
)
SCRIPT_RE = r'\bgrok_(' + '|'.join(SCRIPTS) + r')\b'

# Ordered: longer / more specific patterns first. Identifiers that are part of
# persisted data or digests are protected (see PROTECTED) and never reach here.
CONTENT_RULES: list[tuple[str, str]] = [
    (r'Dimkox/adaptive-grok-build-pro', 'Dimkox/Getzilla'),
    (r'adaptive-grok-build-pro', 'getzilla'),
    (r'Adaptive Grok Build Pro', 'Getzilla'),
    (r'Adaptive Grok Build', 'Getzilla'),
    (r'\.grok-stack/adaptive_grok', '.getzilla/getzilla'),
    (r'\.grok-stack', '.getzilla'),
    (r'__ADAPTIVE_GROK_LOCATION__', '__GETZILLA_LOCATION__'),
    (r'(?<![\w])adaptive-grok\b', 'getzilla'),
    (r'adaptive_grok', 'getzilla'),
    (r'Adaptive Grok', 'Getzilla'),
    # Python packages and their distributions / console scripts
    (r'adaptive_factory', 'getzilla_factory'),
    (r'\badaptive-factory(?=-(?:server|admin|result-dispatch)\b|(?![\w-]))', 'getzilla-factory'),
    (r'\badaptive-landing-(server|state|submit)\b', r'getzilla-landing-\1'),
    (r'Adaptive Factory', 'Getzilla Factory'),
    (r'adaptive_delivery', 'getzilla_delivery'),
    (r'\badaptive-delivery(?![\w-])', 'getzilla-delivery'),
    (r'Adaptive Delivery', 'Getzilla Delivery'),
    (r'Adaptive Landing', 'Getzilla Landing'),
    (r'Adaptive Pilot', 'Getzilla Pilot'),
    # repository scripts and local test-runner knobs
    (SCRIPT_RE, r'getzilla_\1'),
    (r'scripts/grok_\*\.py', 'scripts/getzilla_*.py'),
    (r'startswith\("grok"\)', 'startswith("getzilla")'),
    (r'_GROK_TEST_CHILD', '_GETZILLA_TEST_CHILD'),
    (r'\bGROK_(TEST_WORKERS|VERIFY_CAPABILITY|VERIFY_FORCE_FULL)\b', r'GETZILLA_\1'),
    (r'grok-test-runner', 'getzilla-test-runner'),
]
COMPILED = [(re.compile(p), r) for p, r in CONTENT_RULES]

# Kept verbatim inside otherwise-renamed files:
# - links to the predecessor's PRs, releases, commits and pinned trees;
# - schema URNs and digest/domain tags (adaptive-factory.execution-proposal,
#   adaptive-grok.architecture-fingerprint, ...) that bind persisted data,
#   signatures and recorded evidence;
# - names of already-published release artifacts (adaptive-grok-build-pro-v2.0.19.zip);
# - the deployed Trust CI checkout path /opt/adaptive-grok-build-pro.
PROTECTED = re.compile(
    r'github\.com/Dimkox/adaptive-grok-build-pro/'
    r'(?:pull|issues|releases|commit|commits|compare|tree|blob|actions|checks|runs)\b'
    r'|urn:adaptive-[A-Za-z0-9-]+'
    r'|\badaptive-(?:grok|factory|delivery|pilot|landing|demo)\.[A-Za-z]'
    r'|\badaptive-grok-build-pro-v2\.'
    r'|/opt/adaptive-grok-build-pro\b'
)

PATH_RULES: list[tuple[str, str]] = [
    (r'^\.grok-stack/adaptive_grok/', '.getzilla/getzilla/'),
    (r'^\.grok-stack/', '.getzilla/'),
    (r'^factory/src/adaptive_factory/', 'factory/src/getzilla_factory/'),
    (r'^delivery/src/adaptive_delivery/', 'delivery/src/getzilla_delivery/'),
    (r'^(\.agents|\.grok)/skills/adaptive-delivery/', r'\1/skills/getzilla-delivery/'),
    (r'^scripts/grok_(' + '|'.join(SCRIPTS) + r')\.py$', r'scripts/getzilla_\1.py'),
]


def frozen(rel: str) -> bool:
    if rel.startswith('factory/src/adaptive_factory/resources/') and rel.endswith('.sql'):
        return False  # path moves with the package; content handled in frozen_content()
    return rel in FROZEN_FILES or rel.startswith(FROZEN_PREFIXES)


def frozen_content(rel: str) -> bool:
    # applied database migrations are checksum-bound: move them, never edit them
    return frozen(rel) or (rel.startswith('factory/src/adaptive_factory/resources/') and rel.endswith('.sql'))


def new_path(rel: str) -> str:
    if frozen(rel):
        return rel
    for pattern, repl in PATH_RULES:
        rel2, n = re.subn(pattern, repl, rel)
        if n:
            return rel2
    return rel


def rewrite(text: str) -> str:
    kept: list[str] = []

    def hold(match: re.Match[str]) -> str:
        kept.append(match.group(0))
        return f'\x00{len(kept) - 1}\x00'

    text = PROTECTED.sub(hold, text)
    for rx, repl in COMPILED:
        text = rx.sub(repl, text)
    return re.sub(r'\x00(\d+)\x00', lambda m: kept[int(m.group(1))], text)


def main() -> int:
    root = Path(sys.argv[1]).resolve()
    dry = '--dry-run' in sys.argv
    files = subprocess.run(['git', '-C', str(root), 'ls-files', '-z'], check=True,
                           capture_output=True).stdout.decode().split('\0')
    files = [f for f in files if f]
    edited = moved = 0
    for rel in files:
        path = root / rel
        if path.is_symlink() or not path.is_file():
            continue
        if not frozen_content(rel):
            raw = path.read_bytes()
            if b'\0' not in raw[:8192]:
                try:
                    text = raw.decode('utf-8')
                except UnicodeDecodeError:
                    text = None
                if text is not None:
                    new = rewrite(text)
                    if new != text:
                        edited += 1
                        if not dry:
                            path.write_bytes(new.encode('utf-8'))
        dest = new_path(rel)
        if dest != rel:
            moved += 1
            if not dry:
                (root / dest).parent.mkdir(parents=True, exist_ok=True)
                subprocess.run(['git', '-C', str(root), 'mv', '-k', rel, dest], check=True)
    if not dry:
        relocate_readme(root)
    print(f'content edited: {edited} files; paths moved: {moved}')
    return 0


# Getzilla keeps its own short README.md. The predecessor's detailed README
# lives on as docs/REFERENCE.md, so its changes land there during syncs.
REFERENCE = 'docs/REFERENCE.md'
RELATIVE_LINK = re.compile(r'\]\((?!https?://|mailto:|#|/)([^)\s]+)\)')
README_READ = re.compile(r'''ROOT / (["'])README\.md\1''')


def relocate_readme(root: Path) -> None:
    readme = root / 'README.md'
    if not readme.is_file() or (root / REFERENCE).exists():
        return
    text = RELATIVE_LINK.sub(lambda m: f'](../{m.group(1)})', readme.read_text(encoding='utf-8'))
    subprocess.run(['git', '-C', str(root), 'mv', 'README.md', REFERENCE], check=True)
    (root / REFERENCE).write_text(text, encoding='utf-8')
    tests = subprocess.run(['git', '-C', str(root), 'ls-files', '-z', '--', 'tests', 'trust-ci/tests'],
                           check=True, capture_output=True).stdout.decode().split('\0')
    for rel in filter(None, tests):
        path = root / rel
        if rel.endswith('.py') and not frozen(rel) and not path.is_symlink():
            source = path.read_text(encoding='utf-8')
            moved = README_READ.sub(lambda m: f'ROOT / {m.group(1)}{REFERENCE}{m.group(1)}', source)
            if moved != source:
                path.write_text(moved, encoding='utf-8')


if __name__ == '__main__':
    raise SystemExit(main())
```
