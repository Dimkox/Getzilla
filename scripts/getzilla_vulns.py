from __future__ import annotations

import argparse
import json
import os
import sys
sys.dont_write_bytecode = True
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.known_vulns import ECOSYSTEMS, VulnerabilityError, download_database, lockfile_gate, recheck_report, scan  # noqa: E402
from getzilla.util import find_root  # noqa: E402
from getzilla.security_data import osv_alias_text  # noqa: E402

parser = argparse.ArgumentParser(
    description='Check pinned dependencies against known vulnerabilities (OSV: GitHub Advisory, PyPA, RustSec, Go, npm, NVD).',
)
parser.add_argument('--json', action='store_true', help='print the full report as JSON')
parser.add_argument('--online', action='store_true', help='explicitly acquire a qualified query snapshot into the selected database')
parser.add_argument('--db', help='offline OSV mirror directory (same as GETZILLA_OSV_DB)')
parser.add_argument('--download-db', metavar='DIR',
                    help='refresh an offline mirror in DIR and exit; run on a host with network access')
parser.add_argument('--ecosystem', action='append', choices=ECOSYSTEMS,
                    help='with --download-db: only these ecosystems (default: all supported)')
args = parser.parse_args()

try:
    if args.download_db:
        if args.online:
            raise VulnerabilityError('online query acquisition and catalog download are distinct operations')
        for path in download_database(Path(args.download_db), args.ecosystem or ECOSYSTEMS):
            print(f'updated {path}')
        raise SystemExit(0)
    environ = dict(os.environ)
    if args.online:
        environ['GETZILLA_OSV_ONLINE'] = '1'
    if args.db:
        environ['GETZILLA_OSV_DB'] = args.db
    root = find_root()
    if args.online:
        database = environ.get('GETZILLA_OSV_DB', '').strip()
        if not database:
            raise VulnerabilityError('qualified online acquisition requires --db DIR or GETZILLA_OSV_DB')
        from getzilla.security_acquisition import refresh_query
        result = refresh_query(root, Path(database))
        if result['status'] not in {'pass', 'skip'}:
            raise VulnerabilityError(result['reason'])
    report = scan(root, environ=environ)
    recheck_report(root, report, environ=environ)
    report = lockfile_gate(report)
except VulnerabilityError as exc:
    print(f'getzilla_vulns: {exc}', file=sys.stderr)
    raise SystemExit(2) from exc

if args.json:
    print(json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True))
else:
    print(f"{report['status'].upper()} known-vulnerabilities: {report['summary']}")
    for item in report['findings']:
        fixed = f" -> fixed in {', '.join(item['fixed'])}" if item['fixed'] else ' (no fixed version yet)'
        raw_aliases = item.get('raw_aliases', item['aliases'])
        aliases = f" ({osv_alias_text(raw_aliases)})" if raw_aliases else ''
        severity = f" [{item['severity']}]" if item['severity'] else ''
        print(f"  {item['ecosystem']} {item['package']} {item['version']}: {item['id']}{aliases}{severity}{fixed} — {item['manifest']}")
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        grouped: dict[tuple[str, str, str, str], list[dict]] = {}
        for item in report['findings']:
            grouped.setdefault((item['manifest'], item['ecosystem'], item['package'], item['version']), []).append(item)
        for (manifest, ecosystem, package, version), items in sorted(grouped.items()):
            # Different maintenance lines cannot supply one safe global-max
            # upgrade recommendation. Preserve each advisory's published fixes.
            fixes = '; '.join(
                f"{item['id']}: fixed in {', '.join(item['fixed'])}" if item['fixed']
                else f"{item['id']}: no fixed version published" for item in items)
            level = 'error' if any(item['fixed'] for item in items) else 'notice'
            print(f"::{level} file={manifest},title={ecosystem} {package} {version}: {len(items)} known vulnerabilities::{fixes}. Review the advisory release ranges before selecting an upgrade.")
    for item in report['accepted']:
        print(f"  accepted until {item['accepted_until']}: {item['package']} {item['version']} {item['id']}")
status = report['status']
raise SystemExit(0 if status in {'pass', 'skip'} else 1 if status == 'fail' else 2)
