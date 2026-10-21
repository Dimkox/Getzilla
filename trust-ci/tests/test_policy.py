from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from _support import policy_data
from adaptive_trust_ci.policy import CommandSpec, Policy, PolicyCatalog, PolicyError


def catalog_data() -> dict:
    common = policy_data()
    common.pop('allowed_repositories')
    common.pop('commands')
    common.pop('holdout')
    return {
        **common,
        'repository_profiles': [
            {
                'repository': 'Dimkox/Getzilla',
                'commands': policy_data()['commands'],
                'holdout': {**policy_data(holdout_digest='a' * 64)['holdout'], 'host_path': '/srv/holdouts/getzilla'},
            },
            {
                'repository': 'Dimkox/ii-tonya-platform',
                'commands': [
                    {
                        'name': 'platform-unit',
                        'argv': ['pytest', '-q'],
                        'timeout_seconds': 120,
                        'required': True,
                    },
                ],
                'holdout': {**policy_data(holdout_digest='b' * 64)['holdout'], 'host_path': '/srv/holdouts/ii-tonya-platform'},
            },
        ],
    }


class PolicyTests(unittest.TestCase):
    def test_attest_argv_default_and_false_preserve_legacy_identity(self) -> None:
        for explicit_false in (False, True):
            with self.subTest(explicit_false=explicit_false):
                data = policy_data()
                if explicit_false:
                    for command in data['commands'] + data['holdout']['commands']:
                        command['attest_argv'] = False
                policy = Policy.from_dict(data)
                self.assertEqual(policy.digest, '198a4655a16ba7fb36cfe4729e110127860b97286a12aa43f41e91ecf7a7750d')
                self.assertEqual(policy.check_name, 'adaptive-trust-ci/verified@198a4655a16b')
                for command in (*policy.commands, *policy.holdout.commands):
                    self.assertIs(command.attest_argv, False)
                    self.assertNotIn('attest_argv', command.to_dict())

    def test_attest_argv_rejects_non_boolean_values(self) -> None:
        for value in ('true', 'false', 1, 0, None, [], {}):
            for section in ('commands', 'holdout'):
                with self.subTest(value=value, section=section):
                    data = policy_data()
                    commands = data['commands'] if section == 'commands' else data['holdout']['commands']
                    commands[0]['attest_argv'] = value
                    with self.assertRaisesRegex(PolicyError, 'attest_argv.*bool'):
                        Policy.from_dict(data)

    def test_attest_argv_changes_only_the_selected_profile_identity(self) -> None:
        original = PolicyCatalog.from_dict(catalog_data())
        changed = catalog_data()
        changed['repository_profiles'][0]['commands'][0]['attest_argv'] = True
        updated = PolicyCatalog.from_dict(changed)
        selected = updated.resolve_repository('Dimkox/Getzilla')
        self.assertIs(selected.commands[0].attest_argv, True)
        self.assertIs(selected.commands[0].to_dict()['attest_argv'], True)
        self.assertNotEqual(selected.check_name, original.resolve_repository('Dimkox/Getzilla').check_name)
        self.assertNotEqual(updated.digest, original.digest)
        self.assertEqual(updated.resolve_repository('Dimkox/ii-tonya-platform').check_name,
                         original.resolve_repository('Dimkox/ii-tonya-platform').check_name)

    def test_attest_argv_direct_construction_is_strict(self) -> None:
        for value in ('false', 0, 1, None):
            with self.subTest(value=value), self.assertRaisesRegex(PolicyError, 'attest_argv.*bool'):
                CommandSpec('command', ('python3', '--version'), 60, attest_argv=value)

    def test_attest_argv_profiles_reject_reserved_identity_environment(self) -> None:
        names = ('TRUST_CI_BASE_SHA', 'TRUST_CI_HEAD_SHA', 'TRUST_CI_REPOSITORY',
                 'TRUST_CI_POLICY_DIGEST', 'TRUST_CI_FUTURE_IDENTITY')
        for name in names:
            for source in ('allowed_environment', 'attested_command', 'other_command', 'holdout'):
                with self.subTest(name=name, source=source):
                    data = policy_data()
                    data['commands'][0]['attest_argv'] = True
                    if source == 'allowed_environment':
                        data['allowed_environment'] = [name]
                    else:
                        command = (data['holdout']['commands'][0] if source == 'holdout'
                                   else data['commands'][source == 'other_command'])
                        command['env'] = {name: 'forged'}
                    with self.assertRaisesRegex(PolicyError, 'TRUST_CI_'):
                        Policy.from_dict(data)

    def test_attest_argv_holdout_opt_in_protects_identity_for_the_profile(self) -> None:
        data = policy_data()
        data['holdout']['commands'][0]['attest_argv'] = True
        data['commands'][0]['env'] = {'TRUST_CI_BASE_SHA': 'forged'}
        with self.assertRaisesRegex(PolicyError, 'TRUST_CI_'):
            Policy.from_dict(data)

    def test_legacy_environment_and_non_identity_opt_in_environment_stay_valid(self) -> None:
        data = policy_data()
        data['allowed_environment'] = ['TRUST_CI_BASE_SHA']
        data['commands'][0]['env'] = {'TRUST_CI_BASE_SHA': 'legacy'}
        self.assertEqual(Policy.from_dict(data).allowed_environment, ('TRUST_CI_BASE_SHA',))
        data['allowed_environment'] = ['LANG']
        data['commands'][0]['env'] = {'AUDIT_FORMAT': 'json'}
        data['commands'][0]['attest_argv'] = True
        self.assertEqual(Policy.from_dict(data).commands[0].env, (('AUDIT_FORMAT', 'json'),))

    def test_eu_audit_command_fragment_is_explicit_required_opt_in(self) -> None:
        config = Path(__file__).resolve().parents[1] / 'config'
        catalog = PolicyCatalog.load(config / 'policy.example.json')
        self.assertEqual(catalog.digest, 'c23bab5c5881cf4254e1587cebf7a14ec0a9b599d048d6a1c82b77d29fd95b04')
        for profile in catalog.profiles:
            self.assertNotIn('eu-ai-act-audit', [command.name for command in profile.commands])
        fragment = json.loads((config / 'eu-ai-act-audit.command.example.json').read_text(encoding='utf-8'))
        self.assertEqual(fragment, {
            'name': 'eu-ai-act-audit',
            'argv': ['python3', 'scripts/getzilla_audit_bundle.py', '--ci-check'],
            'timeout_seconds': 300, 'required': True, 'attest_argv': True,
        })
        command = CommandSpec.from_dict(fragment)
        self.assertIs(command.attest_argv, True)
        configured = catalog_data()
        configured['repository_profiles'][0]['commands'].append(fragment)
        selected = PolicyCatalog.from_dict(configured).resolve_repository('Dimkox/Getzilla')
        self.assertEqual(selected.commands[-1], command)
        fragment['required'] = False
        with self.assertRaisesRegex(PolicyError, 'mandatory'):
            CommandSpec.from_dict(fragment)

    def test_legacy_policy_catalog_preserves_digest_and_check_name(self) -> None:
        legacy = Policy.from_dict(policy_data())
        catalog = PolicyCatalog.from_dict(policy_data())
        self.assertEqual(catalog.mode, 'legacy')
        self.assertEqual(catalog.digest, legacy.digest)
        self.assertEqual(catalog.resolve_repository('Dimkox/Getzilla').check_name, legacy.check_name)
        self.assertEqual(catalog.profile_count, 1)

    def test_catalog_resolves_exact_isolated_profiles(self) -> None:
        catalog = PolicyCatalog.from_dict(catalog_data())
        a = catalog.resolve_repository('Dimkox/Getzilla')
        b = catalog.resolve_repository('Dimkox/ii-tonya-platform')
        self.assertNotEqual(a.digest, b.digest)
        self.assertEqual(a.commands[0].name, 'unit')
        self.assertEqual(b.commands[0].name, 'platform-unit')
        with self.assertRaisesRegex(PolicyError, 'not configured'):
            catalog.resolve_repository('dimkox/ii-tonya-platform')

    def test_catalog_digest_is_order_independent_and_profile_changes_are_scoped(self) -> None:
        first = catalog_data()
        original = PolicyCatalog.from_dict(first)
        changed = copy.deepcopy(first)
        changed['repository_profiles'][0]['commands'][0]['name'] = 'unit-v2'
        updated = PolicyCatalog.from_dict(changed)
        self.assertNotEqual(original.resolve_repository('Dimkox/Getzilla').digest,
                            updated.resolve_repository('Dimkox/Getzilla').digest)
        self.assertEqual(original.resolve_repository('Dimkox/ii-tonya-platform').digest,
                         updated.resolve_repository('Dimkox/ii-tonya-platform').digest)
        reordered = copy.deepcopy(first)
        reordered['repository_profiles'].reverse()
        self.assertEqual(original.digest, PolicyCatalog.from_dict(reordered).digest)

    def test_catalog_common_change_rotates_all_profiles_and_bound_lookup_is_exact(self) -> None:
        first = PolicyCatalog.from_dict(catalog_data())
        changed = catalog_data()
        changed['max_attempts'] = 4
        second = PolicyCatalog.from_dict(changed)
        for repository in ('Dimkox/Getzilla', 'Dimkox/ii-tonya-platform'):
            self.assertNotEqual(first.resolve_repository(repository).digest,
                                second.resolve_repository(repository).digest)
        profile = first.resolve_repository('Dimkox/ii-tonya-platform')
        self.assertIs(first.resolve_bound('Dimkox/ii-tonya-platform', profile.digest), profile)
        with self.assertRaisesRegex(PolicyError, 'not active'):
            first.resolve_bound('Dimkox/ii-tonya-platform', first.resolve_repository('Dimkox/Getzilla').digest)

    def _owner_catalog(self) -> dict:
        data = catalog_data()
        data['owner_profiles'] = [
            {
                'owner': 'Dimkox',
                'commands': [
                    {
                        'name': 'getzilla-verify',
                        'argv': ['python3', 'scripts/getzilla_verify.py', '--mode', 'pr', '--no-record', '--json'],
                        'timeout_seconds': 1200,
                        'required': True,
                    },
                ],
                'holdout': {**policy_data(holdout_digest='c' * 64)['holdout'], 'host_path': '/srv/holdouts/owner-dimkox'},
            },
        ]
        return data

    def test_owner_profile_covers_every_repository_of_that_owner_only(self) -> None:
        catalog = PolicyCatalog.from_dict(self._owner_catalog())
        exact = catalog.resolve_repository('Dimkox/Getzilla')
        self.assertEqual(exact.commands[0].name, 'unit')
        for repository in ('Dimkox/new-project', 'Dimkox/openclaw-airgap-farm'):
            profile = catalog.resolve_repository(repository)
            self.assertEqual(profile.owner_scope, 'Dimkox')
            self.assertEqual(profile.commands[0].name, 'getzilla-verify')
            self.assertIs(catalog.resolve_bound(repository, profile.digest), profile)
        for repository in ('someone-else/project', 'dimkox/new-project', 'Dimkox/*', 'Dimkox', 'Dimkox/a/b'):
            with self.assertRaisesRegex(PolicyError, 'not configured'):
                catalog.resolve_repository(repository)

    def test_owner_profiles_alone_form_a_catalog(self) -> None:
        data = self._owner_catalog()
        data['repository_profiles'] = []
        catalog = PolicyCatalog.from_dict(data)
        self.assertEqual(catalog.mode, 'catalog')
        self.assertEqual(catalog.resolve_repository('Dimkox/Getzilla').owner_scope, 'Dimkox')
        del data['repository_profiles']
        self.assertEqual(PolicyCatalog.from_dict(data).digest, catalog.digest)

    def test_adding_an_owner_profile_keeps_exact_profile_epochs(self) -> None:
        plain = PolicyCatalog.from_dict(catalog_data())
        owned = PolicyCatalog.from_dict(self._owner_catalog())
        for repository in ('Dimkox/Getzilla', 'Dimkox/ii-tonya-platform'):
            self.assertEqual(plain.resolve_repository(repository).check_name,
                             owned.resolve_repository(repository).check_name)
        self.assertNotEqual(plain.digest, owned.digest)

    def test_owner_profiles_are_validated(self) -> None:
        cases = (
            ({'owner': '*'}, 'owner login'),
            ({'owner': 'Dimkox/x'}, 'owner login'),
            ({'owner': ''}, 'owner login'),
            ({'unexpected': True}, 'owner profile keys'),
        )
        for patch, message in cases:
            data = self._owner_catalog()
            data['owner_profiles'][0].update(patch)
            with self.subTest(patch=patch), self.assertRaisesRegex(PolicyError, message):
                PolicyCatalog.from_dict(data)
        data = self._owner_catalog()
        data['owner_profiles'].append(copy.deepcopy(data['owner_profiles'][0]))
        with self.assertRaisesRegex(PolicyError, 'unique'):
            PolicyCatalog.from_dict(data)
        data = self._owner_catalog()
        del data['owner_profiles'][0]['holdout']['host_path']
        with self.assertRaisesRegex(PolicyError, 'host_path'):
            PolicyCatalog.from_dict(data)

    def test_legacy_policy_never_accepts_a_wildcard_repository(self) -> None:
        data = policy_data()
        data['allowed_repositories'] = ['Dimkox/*']
        with self.assertRaisesRegex(PolicyError, 'exact owner/name'):
            Policy.from_dict(data)

    def test_catalog_rejects_mixed_legacy_fields(self) -> None:
        data = catalog_data()
        data['commands'] = []
        with self.assertRaisesRegex(PolicyError, 'mixed'):
            PolicyCatalog.from_dict(data)

    def test_catalog_requires_absolute_host_path(self) -> None:
        for value in ('missing', None, '', 'relative/holdout'):
            data = catalog_data()
            if value == 'missing':
                del data['repository_profiles'][0]['holdout']['host_path']
            else:
                data['repository_profiles'][0]['holdout']['host_path'] = value
            with self.assertRaisesRegex(PolicyError, 'host_path'):
                PolicyCatalog.from_dict(data)

    def test_catalog_rejects_invalid_or_trimmed_repository_names(self) -> None:
        for repository in ('bad', ' Dimkox/example', 'Dimkox/example '):
            data = catalog_data()
            data['repository_profiles'][0]['repository'] = repository
            with self.assertRaisesRegex(PolicyError, 'repository profile'):
                PolicyCatalog.from_dict(data)

    def test_catalog_rejects_unknown_profile_keys(self) -> None:
        data = catalog_data()
        data['repository_profiles'][0]['unexpected'] = True
        with self.assertRaisesRegex(PolicyError, 'repository profile keys'):
            PolicyCatalog.from_dict(data)

    def test_catalog_digest_binds_canonical_profile_holdout_paths(self) -> None:
        first = catalog_data()
        second = copy.deepcopy(first)
        second['repository_profiles'][0]['holdout']['path'] = '/opt/adaptive-trust-ci/./holdout'
        second['repository_profiles'][0]['holdout']['host_path'] = '/srv/holdouts/./getzilla'
        self.assertEqual(
            PolicyCatalog.from_dict(first).resolve_repository('Dimkox/Getzilla').digest,
            PolicyCatalog.from_dict(second).resolve_repository('Dimkox/Getzilla').digest,
        )

    def test_catalog_rejects_duplicate_and_wildcard_repositories(self) -> None:
        for repository in ('Dimkox/Getzilla', 'Dimkox/*'):
            data = catalog_data()
            data['repository_profiles'][1]['repository'] = repository
            with self.assertRaisesRegex(PolicyError, 'repository'):
                PolicyCatalog.from_dict(data)

    def test_catalog_requires_common_fields(self) -> None:
        for field in ('schema_version', 'status_context', 'pipeline', 'sandbox'):
            data = catalog_data()
            data.pop(field, None)
            with self.assertRaises(PolicyError):
                PolicyCatalog.from_dict(data)

    def test_legacy_digest_and_check_name_remain_exact_without_host_path(self) -> None:
        legacy = Policy.from_dict(policy_data())
        catalog = PolicyCatalog.from_dict(policy_data())
        self.assertEqual(catalog.digest, legacy.digest)
        self.assertEqual(catalog.resolve_repository(legacy.allowed_repositories[0]).check_name, legacy.check_name)
    def test_digest_is_stable_for_equivalent_objects(self) -> None:
        first = policy_data()
        second = copy.deepcopy(first)
        second['allowed_repositories'] = list(reversed(second['allowed_repositories']))
        self.assertEqual(Policy.from_dict(first).digest, Policy.from_dict(second).digest)

    def test_policy_change_changes_digest_and_required_check_name(self) -> None:
        first = Policy.from_dict(policy_data())
        changed = policy_data()
        changed['max_attempts'] = 4
        second = Policy.from_dict(changed)
        self.assertNotEqual(first.digest, second.digest)
        self.assertNotEqual(first.check_name, second.check_name)

    def test_required_check_name_is_bound_to_policy_epoch(self) -> None:
        policy = Policy.from_dict(policy_data())
        self.assertEqual(
            policy.check_name,
            f'adaptive-trust-ci/verified@{policy.digest[:12]}',
        )

    def test_status_context_must_be_an_unversioned_prefix(self) -> None:
        data = policy_data()
        data['status_context'] = 'adaptive-trust-ci/verified@manual'
        with self.assertRaisesRegex(PolicyError, 'epoch'):
            Policy.from_dict(data)

    def test_holdout_digest_changes_policy_digest(self) -> None:
        first = Policy.from_dict(policy_data(holdout_digest='d' * 64))
        second = Policy.from_dict(policy_data(holdout_digest='e' * 64))
        self.assertNotEqual(first.digest, second.digest)

    def test_optional_command_is_rejected(self) -> None:
        data = policy_data()
        data['commands'][0]['required'] = False
        with self.assertRaisesRegex(PolicyError, 'mandatory'):
            Policy.from_dict(data)

    def test_optional_holdout_command_is_rejected(self) -> None:
        data = policy_data()
        data['holdout']['commands'][0]['required'] = False
        with self.assertRaisesRegex(PolicyError, 'mandatory'):
            Policy.from_dict(data)

    def test_external_holdout_is_mandatory(self) -> None:
        data = policy_data()
        del data['holdout']
        with self.assertRaisesRegex(PolicyError, 'holdout'):
            Policy.from_dict(data)

    def test_holdout_path_must_be_absolute(self) -> None:
        data = policy_data(holdout_path='repo/holdout')
        with self.assertRaisesRegex(PolicyError, 'absolute'):
            Policy.from_dict(data)

    def test_mutable_image_tag_is_rejected(self) -> None:
        data = policy_data()
        data['sandbox']['image'] = 'runner:latest'
        with self.assertRaisesRegex(PolicyError, 'immutable'):
            Policy.from_dict(data)

    def test_host_execution_is_rejected(self) -> None:
        data = policy_data()
        data['sandbox']['runtime'] = 'host'
        with self.assertRaisesRegex(PolicyError, 'docker or podman'):
            Policy.from_dict(data)

    def test_command_name_must_be_unique(self) -> None:
        data = policy_data()
        data['commands'][1]['name'] = 'unit'
        with self.assertRaisesRegex(PolicyError, 'unique'):
            Policy.from_dict(data)

    def test_command_names_are_unique_across_repository_and_holdout(self) -> None:
        data = policy_data()
        data['holdout']['commands'][0]['name'] = 'unit'
        with self.assertRaisesRegex(PolicyError, 'globally unique'):
            Policy.from_dict(data)

    def test_required_scopes_are_derived_from_actual_paths(self) -> None:
        policy = Policy.from_dict(policy_data())
        self.assertEqual(
            policy.required_scopes(['trust-ci/src/a.py', 'trust-ci/sql/001_schema.sql']),
            {'governance', 'database'},
        )

    def test_required_scopes_preserve_exact_unusual_git_paths(self) -> None:
        policy = Policy.from_dict(policy_data())
        for path in ('trust-ci/файл.txt', 'trust-ci/line\nbreak.txt', 'trust-ci/tab\tname.txt', 'trust-ci/back\\slash.txt'):
            with self.subTest(path=path):
                self.assertEqual(policy.required_scopes((path,)), {'governance'})
        self.assertEqual(policy.required_scopes(('trust-ci/данные.sql',)), {'governance', 'database'})

    def test_approval_globs_preserve_exact_repo_relative_identity(self) -> None:
        policy = Policy.from_dict(policy_data())
        governance = next(rule for rule in policy.approval_rules if rule.scope == 'governance')
        self.assertIn('.getzilla/**', governance.globs)
        self.assertIn('.grok/**', governance.globs)
        self.assertIn('.github/**', governance.globs)
        self.assertIn('.coveragerc', governance.globs)
        self.assertIn('literal\\target.txt', governance.globs)
        self.assertIn('exact/юникод.txt', governance.globs)
        self.assertIn('exact/line\nname.txt', governance.globs)
        self.assertIn('exact/tab\tname.txt', governance.globs)
        for path in (
            '.getzilla/runtime/active-route.json',
            '.grok/prompt\nname.md',
            '.github/tab\tname.yml',
            '.coveragerc',
            'literal\\target.txt',
            'exact/юникод.txt',
            'exact/line\nname.txt',
            'exact/tab\tname.txt',
        ):
            with self.subTest(path=path):
                self.assertEqual(policy.required_scopes((path,)), {'governance'})

    def test_approval_globs_reject_unsafe_patterns_without_rewriting(self) -> None:
        for pattern in (
            '/absolute/**',
            '../outside/**',
            'safe/../outside',
            './safe/**',
            'safe//name',
            'nul\0name',
            'carriage\rreturn',
            'surrogate\ud800name',
            7,
        ):
            with self.subTest(pattern=repr(pattern)):
                data = policy_data()
                data['approval_rules'] = [{'scope': 'governance', 'globs': [pattern]}]
                with self.assertRaises(PolicyError):
                    Policy.from_dict(data)

    def test_policy_file_with_invalid_utf8_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'policy.json'
            path.write_bytes(b'{"approval_rules":["bad-\xff"]}')
            with self.assertRaisesRegex(PolicyError, 'cannot load policy'):
                Policy.load(path)

    def test_directory_glob_matches_directory_itself(self) -> None:
        policy = Policy.from_dict(policy_data())
        self.assertEqual(policy.required_scopes(['trust-ci']), {'governance'})

    def test_unmatched_paths_need_no_approval(self) -> None:
        policy = Policy.from_dict(policy_data())
        self.assertEqual(policy.required_scopes(['docs/readme.md']), set())

    def test_repository_allowlist_is_exact(self) -> None:
        policy = Policy.from_dict(policy_data())
        self.assertTrue(policy.allows_repository('Dimkox/Getzilla'))
        self.assertFalse(policy.allows_repository('dimkox/getzilla'))


if __name__ == '__main__':
    unittest.main()
