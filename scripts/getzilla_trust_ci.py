"""getzilla trust-ci: one-command bootstrap and status of the self-hosted Trust CI host.

`init` does every machine-side step (secrets, CI attestation key, image pins, PostgreSQL, live
harness) and is safe to re-run. `status` reports what is done and what a human still has to do.
`github-app` and `trust-key` are the tools for those human steps. See QUICKSTART.md,
"Operator: Trust CI host".
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

import argparse  # noqa: E402
import os  # noqa: E402

from getzilla.trust_ci_setup import DEFAULT_SCOPES, Bootstrap  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='getzilla trust-ci',
                                     description='Bootstrap and check the self-hosted Trust CI host.')
    parser.add_argument('--trust-ci-dir', type=Path, default=ROOT / 'trust-ci',
                        help='the trust-ci/ directory to set up (default: the one in this checkout)')
    sub = parser.add_subparsers(dest='command', required=True, metavar='{init,status,github-app,trust-key}')

    init = sub.add_parser('init', help='do every machine-side step; safe to re-run')
    init.add_argument('--project-name', help='Docker Compose project name (default adaptive-trust-ci); '
                                             'recorded in trust-ci/.env')
    init.add_argument('--public-url', help='public HTTPS address of the API, for example https://ci.example.org')
    init.add_argument('--rebuild', action='store_true',
                      help='rebuild api, worker and runner and re-pin them (this starts a new policy epoch)')
    init.add_argument('--skip-harness', action='store_true', help='do not run the live PostgreSQL harness')

    status = sub.add_parser('status', help='report the host state and the pending human steps (read-only); '
                                           'exit 0 ready, 1 broken, 3 waiting on a step')
    status.add_argument('--project-name')
    status.add_argument('--json', action='store_true')

    app = sub.add_parser('github-app', help='human step 1: give the GitHub App to the worker only')
    app.add_argument('--app-id', required=True)
    app.add_argument('--installation-id', required=True, help='a number, or "auto" for an App on several accounts')
    app.add_argument('--private-key', required=True, type=Path, help='the .pem file downloaded from GitHub')

    key = sub.add_parser('trust-key', help='human step 3: trust a human Ed25519 public key (API only)')
    key.add_argument('--public-key', required=True, type=Path, help='the .pub.pem file from adaptive-trust-ci keygen')
    key.add_argument('--actor', required=True, help='the human identity that signs approvals')
    key.add_argument('--key-id', help='the key_id that keygen printed; checked against the key')
    key.add_argument('--scopes', default=','.join(DEFAULT_SCOPES))
    key.add_argument('--days', type=int, default=365, help='validity of the trust entry (default 365)')
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    trust = args.trust_ci_dir.expanduser().resolve()
    if not (trust / 'compose.yaml').is_file():
        print(f'getzilla trust-ci: {trust} has no compose.yaml. Run this from a Getzilla checkout on the Trust CI '
              'host, or pass --trust-ci-dir.', file=sys.stderr)
        return 2
    tool = Bootstrap(trust, out=lambda line: print(line, flush=True))
    if args.command == 'init':
        if os.name == 'nt':
            print('getzilla trust-ci init runs on the Linux Trust CI host, not on Windows.', file=sys.stderr)
            return 2
        return tool.init(project=args.project_name, public_url=args.public_url, rebuild=args.rebuild,
                         harness=not args.skip_harness)
    if args.command == 'status':
        return tool.status(project=args.project_name, as_json=args.json)
    if args.command == 'github-app':
        return tool.github_app(app_id=args.app_id, installation_id=args.installation_id, private_key=args.private_key)
    scopes = tuple(item.strip() for item in args.scopes.split(',') if item.strip())
    return tool.trust_key(public_key=args.public_key, actor=args.actor, key_id=args.key_id, scopes=scopes,
                          days=args.days)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
