"""Paid Trust CI access: plan policy changes that add or remove a customer account.

Trust CI verifies private repositories for accounts that pay for it; public
repositories use GitHub Actions instead. A paying account is an owner profile
in the catalog policy: every repository of that GitHub account is verified with
the Getzilla consumer holdout, and no other account is accepted.

Pure planning, like onboarding: the deployed policy is only read, a new file is
written next to it, and the operator installs it deliberately. Adding or
removing an account never changes another profile's check name.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Mapping

from .onboarding import OWNER_COMMANDS, OWNER_HOLDOUT_COMMANDS, _holdout
from .policy import _OWNER_RE, PolicyCatalog, PolicyError


def _catalog(deployed: Mapping[str, Any]) -> dict[str, Any]:
    data = copy.deepcopy(dict(deployed))
    if 'repository_profiles' not in data and 'owner_profiles' not in data:
        raise PolicyError('the deployed policy is a legacy single-profile policy; run onboarding first')
    PolicyCatalog.from_dict(data)
    return data


def _owner(value: str) -> str:
    if not isinstance(value, str) or not _OWNER_RE.fullmatch(value):
        raise PolicyError(f'not a GitHub account login: {value!r}')
    return value


def list_customers(deployed: Mapping[str, Any]) -> list[str]:
    return sorted(item['owner'] for item in _catalog(deployed).get('owner_profiles', []))


def add_customer(
    deployed: Mapping[str, Any],
    owner: str,
    *,
    holdout_root: Path,
    holdout_host_root: Path,
    bundle: Path,
) -> dict[str, Any]:
    data = _catalog(deployed)
    owner = _owner(owner)
    owners = list(data.get('owner_profiles', []))
    if any(item.get('owner', '').lower() == owner.lower() for item in owners):
        raise PolicyError(f'{owner} already has Trust CI access')
    owners.append({
        'owner': owner,
        'commands': copy.deepcopy(OWNER_COMMANDS),
        'holdout': _holdout(f'owner-{owner.lower()}', holdout_root=holdout_root, host_root=holdout_host_root,
                            bundle=bundle, commands=OWNER_HOLDOUT_COMMANDS),
    })
    data['owner_profiles'] = owners
    PolicyCatalog.from_dict(data)
    return data


def remove_customer(deployed: Mapping[str, Any], owner: str) -> dict[str, Any]:
    data = _catalog(deployed)
    owner = _owner(owner)
    owners = list(data.get('owner_profiles', []))
    kept = [item for item in owners if item.get('owner') != owner]
    if len(kept) == len(owners):
        raise PolicyError(f'{owner} has no Trust CI access to remove')
    data['owner_profiles'] = kept
    PolicyCatalog.from_dict(data)
    return data


def _epochs(old: Mapping[str, Any], new: Mapping[str, Any]) -> list[dict[str, Any]]:
    before = {profile.allowed_repositories[0]: profile.check_name for profile in PolicyCatalog.from_dict(old).profiles}
    after = {profile.allowed_repositories[0]: profile.check_name for profile in PolicyCatalog.from_dict(new).profiles}
    return [
        {'scope': scope, 'check_before': before.get(scope), 'check_after': after.get(scope)}
        for scope in sorted(set(before) | set(after))
        if before.get(scope) != after.get(scope)
    ]


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description='Plan paid Trust CI access for GitHub accounts (private repositories).')
    sub = parser.add_subparsers(dest='command', required=True)
    listing = sub.add_parser('list', help='print the accounts that have Trust CI access')
    listing.add_argument('--policy', type=Path, required=True)
    add = sub.add_parser('add', help='write a new policy that gives an account Trust CI access')
    add.add_argument('--policy', type=Path, required=True, help='deployed policy (read only)')
    add.add_argument('--out', type=Path, required=True, help='where to write the planned policy')
    add.add_argument('--owner', required=True, help='GitHub user or organization login')
    add.add_argument('--holdout-root', type=Path, required=True, help='TRUST_CI_HOLDOUT_PATH as seen by API/worker')
    add.add_argument('--holdout-host-root', type=Path, required=True, help='TRUST_CI_HOLDOUT_HOST_PATH on the host')
    add.add_argument('--bundle', type=Path, required=True, help='the Getzilla consumer holdout bundle')
    remove = sub.add_parser('remove', help='write a new policy without an account')
    remove.add_argument('--policy', type=Path, required=True, help='deployed policy (read only)')
    remove.add_argument('--out', type=Path, required=True, help='where to write the planned policy')
    remove.add_argument('--owner', required=True)
    args = parser.parse_args(argv)

    try:
        deployed = json.loads(args.policy.read_text(encoding='utf-8'))
        if args.command == 'list':
            print(json.dumps({'customers': list_customers(deployed)}, indent=2))
            return 0
        if args.out.exists():
            raise SystemExit(f'refusing to overwrite {args.out}')
        if args.command == 'add':
            planned = add_customer(deployed, args.owner, holdout_root=args.holdout_root,
                                   holdout_host_root=args.holdout_host_root, bundle=args.bundle)
        else:
            planned = remove_customer(deployed, args.owner)
    except PolicyError as exc:
        raise SystemExit(f'customers: {exc}') from exc
    args.out.write_text(json.dumps(planned, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    report: dict[str, Any] = {'written': str(args.out), 'changed_checks': _epochs(deployed, planned)}
    if args.command == 'add':
        holdout = planned['owner_profiles'][-1]['holdout']
        report['install_bundle'] = {'from': str(args.bundle), 'to': holdout['host_path'], 'digest': holdout['digest']}
    print(json.dumps(report, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
