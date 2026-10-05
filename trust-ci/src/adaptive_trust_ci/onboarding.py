"""Build a reviewed catalog policy that verifies Getzilla and every repository of an owner.

Pure planning: reads the deployed policy, never writes it. The operator reviews
the printed epochs and installs the new file deliberately.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Mapping

from .holdout import bundle_digest
from .policy import PolicyCatalog, PolicyError

GETZILLA_REPOSITORY = 'Dimkox/Getzilla'

GETZILLA_COMMANDS: list[dict[str, Any]] = [
    {'name': 'root-unittest', 'argv': ['python3', '-m', 'unittest', 'discover', '-s', 'tests'],
     'timeout_seconds': 900, 'required': True},
    {'name': 'trust-ci-unittest', 'argv': ['python3', '-m', 'unittest', 'discover', '-s', 'trust-ci/tests'],
     'timeout_seconds': 900, 'required': True},
    {'name': 'compileall', 'argv': ['python3', '-m', 'compileall', '-q', '.getzilla/getzilla', 'scripts', 'trust-ci/src'],
     'timeout_seconds': 300, 'required': True},
    {'name': 'repository-verification',
     'argv': ['python3', 'scripts/getzilla_verify.py', '--mode', 'pr', '--no-record', '--json'],
     'timeout_seconds': 1200, 'required': True},
]
GETZILLA_HOLDOUT_COMMANDS: list[dict[str, Any]] = [
    {'name': 'adaptive-holdout', 'argv': ['python3', '/holdout/validate.py', '/workspace'],
     'timeout_seconds': 300, 'required': True},
]
OWNER_COMMANDS: list[dict[str, Any]] = [
    {'name': 'getzilla-verify',
     'argv': ['python3', 'scripts/getzilla_verify.py', '--mode', 'pr', '--no-record', '--json'],
     'timeout_seconds': 1200, 'required': True},
]
OWNER_HOLDOUT_COMMANDS: list[dict[str, Any]] = [
    {'name': 'getzilla-consumer-holdout', 'argv': ['python3', '/holdout/validate.py', '/workspace'],
     'timeout_seconds': 300, 'required': True},
]


def _holdout(name: str, *, holdout_root: Path, host_root: Path, bundle: Path,
             commands: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        'path': str(holdout_root / name),
        'host_path': str(host_root / name),
        'digest': bundle_digest(bundle),
        'commands': copy.deepcopy(commands),
    }


def plan_catalog(
    deployed: Mapping[str, Any],
    *,
    owner: str,
    holdout_root: Path,
    holdout_host_root: Path,
    getzilla_bundle: Path,
    owner_bundle: Path,
) -> dict[str, Any]:
    """Return a catalog policy: existing repositories unchanged, plus Getzilla and an owner profile."""
    data = copy.deepcopy(dict(deployed))
    if 'repository_profiles' in data or 'owner_profiles' in data:
        profiles = list(data.pop('repository_profiles', []))
        owners = list(data.pop('owner_profiles', []))
    else:
        # Catalog holdouts must be strict subdirectories of the trusted roots, so
        # each legacy repository gets its own copy of the unchanged legacy bundle
        # under <root>/<repository name>; the digest stays the same.
        repositories = data.pop('allowed_repositories')
        commands = data.pop('commands')
        holdout = data.pop('holdout')
        profiles = [
            {'repository': repository, 'commands': copy.deepcopy(commands),
             'holdout': {**copy.deepcopy(holdout),
                         'path': str(holdout_root / repository.split('/', 1)[1]),
                         'host_path': str(holdout_host_root / repository.split('/', 1)[1])}}
            for repository in repositories
        ]
        owners = []
    profiles = [item for item in profiles if item.get('repository') != GETZILLA_REPOSITORY]
    profiles.append({
        'repository': GETZILLA_REPOSITORY,
        'commands': copy.deepcopy(GETZILLA_COMMANDS),
        'holdout': _holdout('getzilla', holdout_root=holdout_root, host_root=holdout_host_root,
                            bundle=getzilla_bundle, commands=GETZILLA_HOLDOUT_COMMANDS),
    })
    owners = [item for item in owners if item.get('owner') != owner]
    owners.append({
        'owner': owner,
        'commands': copy.deepcopy(OWNER_COMMANDS),
        'holdout': _holdout(f'owner-{owner.lower()}', holdout_root=holdout_root, host_root=holdout_host_root,
                            bundle=owner_bundle, commands=OWNER_HOLDOUT_COMMANDS),
    })
    data['repository_profiles'] = profiles
    data['owner_profiles'] = owners
    PolicyCatalog.from_dict(data)  # fail before anything is printed or written
    return data


def epoch_report(old: Mapping[str, Any], new: Mapping[str, Any], repositories: list[str]) -> list[dict[str, Any]]:
    old_catalog = PolicyCatalog.from_dict(old)
    new_catalog = PolicyCatalog.from_dict(new)
    report = []
    for repository in repositories:
        try:
            before = old_catalog.resolve_repository(repository).check_name
        except PolicyError:
            before = None
        after = new_catalog.resolve_repository(repository).check_name
        report.append({'repository': repository, 'check_before': before, 'check_after': after,
                       'rerun_branch_protect': before != after})
    return report


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description='Plan a catalog policy covering Getzilla and every repository of an owner.')
    parser.add_argument('--policy', type=Path, required=True, help='deployed policy (read only)')
    parser.add_argument('--out', type=Path, required=True, help='where to write the planned policy')
    parser.add_argument('--owner', default='Dimkox')
    parser.add_argument('--holdout-root', type=Path, required=True, help='TRUST_CI_HOLDOUT_PATH as seen by API/worker')
    parser.add_argument('--holdout-host-root', type=Path, required=True, help='TRUST_CI_HOLDOUT_HOST_PATH on the host')
    parser.add_argument('--getzilla-bundle', type=Path, required=True)
    parser.add_argument('--owner-bundle', type=Path, required=True)
    parser.add_argument('--repository', action='append', default=[], help='also report this repository epoch')
    args = parser.parse_args(argv)
    if args.out.exists():
        raise SystemExit(f'refusing to overwrite {args.out}')
    deployed = json.loads(args.policy.read_text(encoding='utf-8'))
    planned = plan_catalog(
        deployed,
        owner=args.owner,
        holdout_root=args.holdout_root,
        holdout_host_root=args.holdout_host_root,
        getzilla_bundle=args.getzilla_bundle,
        owner_bundle=args.owner_bundle,
    )
    args.out.write_text(json.dumps(planned, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    known = [item['repository'] for item in planned['repository_profiles']]
    report = epoch_report(deployed, planned, sorted(set(known + args.repository)))
    bundles = [
        {'repository': item['repository'], 'path': item['holdout']['path'], 'digest': item['holdout']['digest']}
        for item in planned['repository_profiles']
    ] + [
        {'owner': item['owner'], 'path': item['holdout']['path'], 'digest': item['holdout']['digest']}
        for item in planned['owner_profiles']
    ]
    print(json.dumps({'written': str(args.out), 'epochs': report, 'holdout_bundles': bundles}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
