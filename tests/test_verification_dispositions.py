from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import verification
from getzilla import verification_dispositions
from getzilla.util import tree_fingerprint
from getzilla.verification import GitRangeBase, GitRangeSelection, _git_diff_check, _secret_scan


CONFIG = 'engineering/verification-dispositions.json'
EVIDENCE = 'engineering/reviews/public-data.md'
ADDRESS = '0x' + '12' * 20
ASSIGNMENT = ': '.join(('token', repr(ADDRESS)))


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class DispositionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Disposition tests')
        self.git('config', 'user.email', 'tests@example.invalid')
        self.write('README.md', b'fixture\n')
        self.write(EVIDENCE, b'Reviewed public identifier and immutable history.\n')
        self.commit()
        self.base = self.git('rev-parse', 'HEAD').stdout.strip()

    def git(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(['git', *args], cwd=self.root, check=True, capture_output=True, text=True)

    def write(self, relative: str, raw: bytes) -> None:
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)

    def commit(self) -> None:
        self.git('add', '.')
        self.git('commit', '-qm', 'fixture')

    def entry(self, *, path: str = 'protocol.ts', text: str = ASSIGNMENT + '\n',
              line: int = 1, column: int = 1, whitespace: bool = False) -> dict:
        self.write(path, text.encode())
        self.git('add', '--', path)
        value = {
            'id': 'reviewed-eof' if whitespace else 'reviewed-token',
            'check': 'git-diff-check' if whitespace else 'secret-scan',
            'kind': 'immutable-markdown-whitespace' if whitespace else 'public-token-address',
            'rule': 'new-blank-line-at-eof' if whitespace else 'generic-secret',
            'path': path, 'sha256': digest(text.encode()), 'line': line,
            'reason': 'Reviewed public identifier or immutable historical record.',
            'evidence': {'path': EVIDENCE, 'sha256': digest((self.root / EVIDENCE).read_bytes())},
        }
        if not whitespace:
            value.update(column=column, match_sha256=digest(ASSIGNMENT.encode()))
        return value

    def policy(self, entries: list[dict], **extra) -> None:
        self.write(CONFIG, (json.dumps({'schema_version': 1, 'dispositions': entries, **extra}) + '\n').encode())
        self.git('add', '--', CONFIG)

    def summary(self, result) -> dict:
        return next(item for item in result.details if item['code'] == 'disposition-summary')

    def reviewed_scan(self, text: str):
        match = next(verification_dispositions.SECRET_PATTERNS['generic-secret'].finditer(text))
        line = text.count('\n', 0, match.start()) + 1
        column = match.start() - text.rfind('\n', 0, match.start())
        entry = self.entry(text=text, line=line, column=column)
        entry['match_sha256'] = digest(match.group().encode())
        self.policy([entry])
        return _secret_scan(self.root, ['protocol.ts'])

    def range_check(self):
        return _git_diff_check(self.root, 'pr', GitRangeSelection(bases=[
            GitRangeBase('route', 'fixture', self.base, self.base),
        ]))

    def assert_invalid(self) -> None:
        for result in (_secret_scan(self.root, []), _git_diff_check(self.root, 'fast', GitRangeSelection())):
            self.assertEqual(result.status, 'fail', result.to_dict())
            self.assertTrue(any(item['code'] == 'disposition-config-invalid' for item in result.details))

    def test_exact_public_occurrence_retains_raw_severity_and_sanitized_identity(self) -> None:
        self.policy([self.entry()])
        result = _secret_scan(self.root, ['protocol.ts'])
        self.assertEqual(result.status, 'pass')
        raw = next(item for item in result.details if item['code'] == 'generic-secret')
        self.assertEqual((raw['severity'], raw['effective_severity']), ('error', 'info'))
        self.assertEqual((raw['line'], raw['column']), (1, 1))
        self.assertEqual(raw['disposition']['id'], 'reviewed-token')
        self.assertEqual(raw['disposition']['config_sha256'], digest((self.root / CONFIG).read_bytes()))
        self.assertEqual(self.summary(result)['unresolved'], 0)
        self.assertNotIn(ADDRESS, json.dumps(result.to_dict()))

    def test_absent_policy_keeps_every_match_blocking(self) -> None:
        self.write('protocol.ts', (ASSIGNMENT + '; ' + ASSIGNMENT + '\n').encode())
        result = _secret_scan(self.root, ['protocol.ts'])
        self.assertEqual(result.status, 'fail')
        matches = [item for item in result.details if item['code'] == 'generic-secret']
        self.assertEqual(len(matches), 2)
        self.assertNotEqual(matches[0]['column'], matches[1]['column'])

    def test_one_disposition_never_suppresses_second_match_on_same_line(self) -> None:
        opaque = 'unreviewed-' * 3
        text = ASSIGNMENT + '; ' + '='.join(('token', repr(opaque))) + '\n'
        self.policy([self.entry(text=text)])
        result = _secret_scan(self.root, ['protocol.ts'])
        self.assertEqual(result.status, 'fail')
        self.assertEqual(self.summary(result)['observed'], 2)
        self.assertEqual(self.summary(result)['disposed'], 1)
        self.assertEqual(self.summary(result)['unresolved'], 1)
        self.assertNotIn(opaque, json.dumps(result.to_dict()))

    def test_two_occurrences_require_two_location_bindings(self) -> None:
        text = ASSIGNMENT + '\n' + ASSIGNMENT + '\n'
        first = self.entry(text=text)
        second = {**first, 'id': 'second-token', 'line': 2}
        self.policy([first, second])
        result = _secret_scan(self.root, ['protocol.ts'])
        self.assertEqual(result.status, 'pass')
        self.assertEqual(self.summary(result)['disposed'], 2)

    def test_private_and_aws_rules_never_inherit_public_disposition(self) -> None:
        text = ASSIGNMENT + '\n' + '-----BEGIN ' + 'PRIVATE KEY-----\n' + 'AKIA' + 'Z' * 16 + '\n'
        self.policy([self.entry(text=text)])
        result = _secret_scan(self.root, ['protocol.ts'])
        self.assertEqual(result.status, 'fail')
        self.assertEqual(self.summary(result)['unresolved'], 2)
        for label in ('private-key', 'aws-access-key'):
            self.assertEqual(next(item for item in result.details if item['code'] == label)['effective_severity'], 'error')
        self.assertNotIn('Z' * 16, json.dumps(result.to_dict()))

    def test_address_shape_does_not_admit_credential_names_or_opaque_values(self) -> None:
        assignments = [': '.join((field, repr(ADDRESS))) for field in
                       ('password', 'api_key', 'secret', 'auth_token', 'obj.token')]
        assignments += [': '.join(('token', repr(value))) for value in ('opaque' * 6, '0x' + '12' * 32)]
        for assignment in assignments:
            with self.subTest(assignment=assignment.split(':')[0]):
                match = next(verification_dispositions.SECRET_PATTERNS['generic-secret'].finditer(assignment))
                entry = self.entry(text=assignment + '\n', column=match.start() + 1)
                entry['match_sha256'] = digest(match.group().encode())
                self.policy([entry])
                self.assert_invalid()

    def test_real_scanner_suffix_never_disposes_unicode_or_escaped_credentials(self) -> None:
        prefixes = {
            'ascii': 'auth_', 'property': 'obj.', 'dollar': '$',
            'joiner': 'auth\u200d', 'nonjoiner': 'auth\u200c',
            'combining': 'auth\u0301', 'escaped-codepoint': r'auth\u{5f}',
            'escaped-fixed': r'auth\u005f', 'backslash': '\\',
            'non-ascii-space': '\u00a0', 'control': '\u0085',
            'spaced-member': 'client. ', 'multiline-member': 'client.\n ',
            'comment-member': 'client./* member */',
            'spaced-comment-member': 'client. /* member */ ',
            'line-comment-member': 'client.// member ; {\n ',
            'optional-member': 'client?. ', 'namespace-member': 'client:: ',
            'inside-comment': '// ', 'inside-string': 'const text = "note ',
            'ambiguous-regex': 'const pattern = /{ ',
            'inside-template': 'const text = `note ',
            'template-expression': 'const text = `${client. ',
            'completed-template': 'const text = `note`; const ',
        }
        for label, prefix in prefixes.items():
            with self.subTest(boundary=label):
                text = prefix + ASSIGNMENT + '\n'
                match = next(verification_dispositions.SECRET_PATTERNS['generic-secret'].finditer(text))
                self.assertEqual(match.group(), ASSIGNMENT)
                line = text.count('\n', 0, match.start()) + 1
                column = match.start() - text.rfind('\n', 0, match.start())
                entry = self.entry(text=text, line=line, column=column)
                entry['match_sha256'] = digest(match.group().encode())
                self.policy([entry])
                result = _secret_scan(self.root, ['protocol.ts'])
                self.assertEqual(result.status, 'fail')
                finding = next(item for item in result.details if item['code'] == 'generic-secret')
                self.assertEqual((finding['severity'], finding['effective_severity']), ('error', 'error'))
                self.assertNotIn('disposition', finding)
                self.assertNotIn(ADDRESS, json.dumps(result.to_dict()))
                self.assert_invalid()

    def test_reviewed_public_tokens_keep_explicit_ascii_boundaries(self) -> None:
        for prefix in ('', ' ', '\t', '\r\n  ', '{', '[', '(', ',', ';', 'const ',
                       'const other = 1, ', '// reviewed\nconst ', '/* reviewed */ const ',
                       'const other = "literal"; const '):
            with self.subTest(boundary=repr(prefix)):
                text = prefix + ASSIGNMENT + '\n'
                match = next(verification_dispositions.SECRET_PATTERNS['generic-secret'].finditer(text))
                line = text.count('\n', 0, match.start()) + 1
                column = match.start() - text.rfind('\n', 0, match.start())
                entry = self.entry(text=text, line=line, column=column)
                entry['match_sha256'] = digest(match.group().encode())
                self.policy([entry])
                result = _secret_scan(self.root, ['protocol.ts'])
                self.assertEqual(result.status, 'pass')
                self.assertEqual(self.summary(result)['disposed'], 1)

    def test_non_ascii_prefix_cannot_erase_member_context(self) -> None:
        assignment = ' = '.join(('token', repr(ADDRESS)))
        separators = (0x85, 0xA0, 0x1680, *range(0x2000, 0x200E), 0x2028,
                      0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF)
        for codepoint in separators:
            for suffix in (' ', ' /* reviewed */ ', '\t '):
                with self.subTest(separator=hex(codepoint), suffix=suffix):
                    source = 'const client = {}; client.' + chr(codepoint) + suffix + assignment + ';\n'
                    result = self.reviewed_scan(source)
                    self.assertEqual(result.status, 'fail')
                    self.assertEqual(self.summary(result)['disposed'], 0)
                    finding = next(item for item in result.details if item['code'] == 'generic-secret')
                    self.assertEqual(finding['effective_severity'], 'error')
                    self.assertNotIn(ADDRESS, json.dumps(result.to_dict()))

    def test_non_ascii_comment_and_string_prefixes_are_conservatively_refused(self) -> None:
        assignment = ' = '.join(('token', repr(ADDRESS)))
        prefixes = (
            '// reviewed\u2028client.\n ', '// reviewed\u2029client.\n ',
            '// reviewed\u2028client. /* reviewed */ ',
            '// reviewed\u2029client. /* reviewed */ ',
            '/* reviewed \u2028 */ const ', '// reviewed \u00e9\nconst ',
            'const note = "\u00e9"; const ', 'const note = "\\\u2028"; const ',
            'const note = "\\\u2029"; const ',
            'const caf\u00e9 = 1; const ',
        )
        for index, prefix in enumerate(prefixes):
            with self.subTest(case=index):
                result = self.reviewed_scan('const client = {}; ' + prefix + assignment + ';\n')
                self.assertEqual(result.status, 'fail')
                self.assertEqual(self.summary(result)['disposed'], 0)
                self.assert_invalid()

    def test_ascii_whitespace_preserves_declarations_and_member_rejection(self) -> None:
        assignment = ' = '.join(('token', repr(ADDRESS)))
        for separator in (' ', '\t', '\r', '\n', '\f', '\v'):
            for suffix in ('', ' ', ' /* reviewed */ '):
                with self.subTest(separator=repr(separator), suffix=suffix):
                    spacing = separator + suffix
                    declared = self.reviewed_scan('const' + spacing + assignment + ';\n')
                    self.assertEqual(declared.status, 'pass')
                    self.assertEqual(self.summary(declared)['disposed'], 1)
                    member = self.reviewed_scan('const client = {}; client.' + spacing + assignment + ';\n')
                    self.assertEqual(member.status, 'fail')
                    self.assertEqual(self.summary(member)['disposed'], 0)

    def test_unsupported_ascii_constructs_cannot_manufacture_standalone_context(self) -> None:
        assignment = ' = '.join(('token', repr(ADDRESS)))
        prefixes = (
            '<!-- reviewed ', '--> reviewed ',
            'const client = {}; client.\n--> reviewed,\n ',
            '#! unsupported\nconst ', '@decorator\nconst ',
            'const marker = 1;\x1b const ', 'const marker = 1;\x7f const ',
            'const client = {}; client.\\\n ',
        )
        for index, prefix in enumerate(prefixes):
            with self.subTest(case=index):
                result = self.reviewed_scan(prefix + assignment + ';\n')
                self.assertEqual(result.status, 'fail')
                self.assertEqual(self.summary(result)['disposed'], 0)

    def test_closed_schema_rejects_invalid_and_duplicate_entries_outside_selection(self) -> None:
        original = self.entry()
        mutations = [
            {'unknown': True}, {'kind': 'allow-all'}, {'check': 'other'},
            {'rule': 'private-key'}, {'sha256': 'f' * 64}, {'match_sha256': '0' * 64},
            {'line': 2}, {'line': True}, {'column': 0}, {'reason': ''},
            {'reason': 'control\ntext'}, {'id': '../bad'},
            {'path': '../protocol.ts'}, {'path': '/protocol.ts'}, {'path': './protocol.ts'},
            {'path': 'dir//protocol.ts'}, {'path': 'dir\\protocol.ts'}, {'path': '*.ts'},
            {'evidence': {'path': EVIDENCE, 'sha256': '0' * 64}},
            {'evidence': {'path': 'missing.md', 'sha256': '0' * 64}},
            {'evidence': {'path': EVIDENCE, 'sha256': original['evidence']['sha256'], 'unknown': 1}},
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.policy([{**original, **mutation}])
                self.assert_invalid()
        for entries in ([original, original], [original, {**original, 'id': 'different-id'}]):
            self.policy(entries)
            self.assert_invalid()
        self.policy([original], unknown=True)
        self.assert_invalid()

    def test_malformed_duplicate_key_version_and_size_fail_without_findings(self) -> None:
        for raw in (b'{', b'{"schema_version":1,"schema_version":1,"dispositions":[]}',
                    b'{"schema_version":true,"dispositions":[]}',
                    b'{"schema_version":2,"dispositions":[]}', b'[]', b' ' * 131073):
            with self.subTest(length=len(raw)):
                self.write(CONFIG, raw)
                self.git('add', '--', CONFIG)
                self.assert_invalid()
        entry = self.entry()
        self.policy([{**entry, 'id': f'entry-{i}'} for i in range(129)])
        self.assert_invalid()

    def test_untracked_or_ignored_policy_cannot_be_authority(self) -> None:
        self.policy([self.entry()])
        self.git('rm', '--cached', CONFIG)
        self.assert_invalid()
        self.write('.gitignore', (CONFIG + '\n').encode())
        self.assert_invalid()

    def test_untracked_evidence_target_and_hidden_index_flags_fail(self) -> None:
        self.policy([self.entry()])
        for path in (EVIDENCE, 'protocol.ts'):
            with self.subTest(path=path):
                self.git('rm', '--cached', '--', path)
                self.assert_invalid()
                self.git('add', '--', path)
        for path in (CONFIG, EVIDENCE, 'protocol.ts'):
            self.git('update-index', '--assume-unchanged', '--', path)
            self.assert_invalid()
            self.git('update-index', '--no-assume-unchanged', '--', path)
        self.git('update-index', '--skip-worktree', '--', CONFIG)
        self.assert_invalid()

    def test_missing_changed_and_oversized_files_fail_outside_selection(self) -> None:
        self.policy([self.entry()])
        for path in (EVIDENCE, 'protocol.ts'):
            original = (self.root / path).read_bytes()
            for replacement in (None, original + b'changed\n', b'a' * 2_000_001):
                with self.subTest(path=path, size=None if replacement is None else len(replacement)):
                    if replacement is None:
                        (self.root / path).unlink()
                    else:
                        self.write(path, replacement)
                    self.assert_invalid()
                    self.write(path, original)

    @unittest.skipUnless(os.name == 'posix', 'symlinks and executable bits')
    def test_symlink_policy_target_evidence_and_parent_are_rejected(self) -> None:
        self.policy([self.entry()])
        for path in (CONFIG, EVIDENCE, 'protocol.ts'):
            original = (self.root / path).read_bytes()
            (self.root / path).unlink()
            (self.root / path).symlink_to(self.root / 'README.md')
            self.assert_invalid()
            (self.root / path).unlink()
            self.write(path, original)
        reviews = self.root / 'engineering/reviews'
        reviews.rename(self.root / 'reviews')
        reviews.symlink_to(self.root / 'reviews', target_is_directory=True)
        self.assert_invalid()

    def test_runtime_evidence_is_never_authority_even_if_force_tracked(self) -> None:
        entry = self.entry()
        path = '.getzilla/runtime/review.md'
        self.write(path, b'Reviewed.\n')
        self.git('add', '-f', '--', path)
        entry['evidence'] = {'path': path, 'sha256': digest(b'Reviewed.\n')}
        self.policy([entry])
        self.assert_invalid()

    def test_policy_and_evidence_changes_invalidate_source_fingerprint(self) -> None:
        self.policy([self.entry()])
        self.commit()
        before = tree_fingerprint(self.root)
        self.write(EVIDENCE, b'Changed review.\n')
        self.assertNotEqual(before, tree_fingerprint(self.root))
        self.assert_invalid()
        self.git('restore', '--', EVIDENCE)
        config = json.loads((self.root / CONFIG).read_bytes())
        config['dispositions'][0]['reason'] = 'A different reviewed rationale.'
        self.write(CONFIG, json.dumps(config).encode())
        self.assertNotEqual(before, tree_fingerprint(self.root))

    def test_committed_markdown_eof_retains_real_exit_output_and_all_ranges(self) -> None:
        self.policy([self.entry(path='historic.md', text='Evidence.\n\n', line=2, whitespace=True)])
        self.commit()
        selection = GitRangeSelection(bases=[
            GitRangeBase('route', 'route', self.base, self.base),
            GitRangeBase('pr-target', 'target', self.base, self.base),
        ])
        result = _git_diff_check(self.root, 'pr', selection)
        self.assertEqual(result.status, 'pass')
        commands = [item for item in result.details if item['code'] == 'diff-check-command']
        self.assertEqual([item['exit_code'] for item in commands], [0, 0, 2, 2])
        self.assertIn('historic.md:2: new blank line at EOF.', result.stdout)
        self.assertEqual(len([item for item in result.details if item['code'] == 'checked-range']), 2)
        observed = [item for item in result.details if item['code'] == 'new-blank-line-at-eof']
        self.assertEqual(len(observed), 2)
        self.assertTrue(all(item['severity'] == 'error' and item['effective_severity'] == 'info' for item in observed))

    def test_staged_and_worktree_eof_are_bound_to_their_own_bytes(self) -> None:
        entry = self.entry(path='historic.md', text='Evidence.\n\n', line=2, whitespace=True)
        self.policy([entry])
        staged = _git_diff_check(self.root, 'fast', GitRangeSelection())
        self.assertEqual(staged.status, 'pass')
        self.git('reset', '-q', '--', 'historic.md')
        self.write('historic.md', b'Evidence.\n')
        self.git('add', 'historic.md')
        self.write('historic.md', b'Evidence.\n\n')
        worktree = _git_diff_check(self.root, 'fast', GitRangeSelection())
        self.assertEqual(worktree.status, 'pass')
        self.write('historic.md', b'Index-specific content.\n\n')
        self.git('add', 'historic.md')
        self.write('historic.md', b'Evidence.\n\n')
        self.assertEqual(_git_diff_check(self.root, 'fast', GitRangeSelection()).status, 'fail')

    def test_current_worktree_hash_cannot_dispose_a_different_head_blob(self) -> None:
        self.write('historic.md', b'Old content.\n\n')
        self.commit()
        entry = self.entry(path='historic.md', text='Current content.\n\n', line=2, whitespace=True)
        self.policy([entry])
        self.assertEqual(self.range_check().status, 'fail')

    def test_other_whitespace_same_file_or_another_file_stays_blocking(self) -> None:
        entry = self.entry(path='historic.md', text='Evidence.  \n\n', line=2, whitespace=True)
        self.policy([entry])
        result = _git_diff_check(self.root, 'fast', GitRangeSelection())
        self.assertEqual(result.status, 'fail')
        self.assertIn('trailing whitespace.', result.stdout)
        entry = self.entry(path='historic.md', text='Evidence.\n\n', line=2, whitespace=True)
        self.policy([entry])
        self.write('new.txt', b'New error.  \n')
        self.git('add', 'new.txt')
        self.assertEqual(_git_diff_check(self.root, 'fast', GitRangeSelection()).status, 'fail')

    def test_no_eof_wrong_location_extension_and_executable_markdown_fail(self) -> None:
        for path, text, line in (('historic.md', 'Evidence.\n', 1), ('historic.md', 'Evidence.\n\n', 1),
                                 ('historic.py', 'Evidence.\n\n', 2)):
            with self.subTest(path=path, line=line):
                self.policy([self.entry(path=path, text=text, line=line, whitespace=True)])
                self.assert_invalid()
        self.policy([self.entry(path='historic.md', text='Evidence.\n\n', line=2, whitespace=True)])
        (self.root / 'historic.md').chmod(0o755)
        self.assert_invalid()

    def test_unknown_git_output_errors_and_selection_findings_cannot_be_disposed(self) -> None:
        self.policy([self.entry(path='historic.md', text='Evidence.\n\n', line=2, whitespace=True)])
        actual_run = verification.run
        for code, stdout, stderr in ((2, 'unexpected output\n', ''), (128, '', 'fatal: invalid object\n'),
                                      (2, 'historic.md:2: new blank line at EOF.\n', 'warning\n'),
                                      (0, 'unexpected output\n', ''), (2, '', '')):
            def command(args, **kwargs):
                if args == ['git', 'diff', '--check']:
                    return subprocess.CompletedProcess(args, code, stdout, stderr)
                return actual_run(args, **kwargs)
            with self.subTest(code=code, stdout=stdout, stderr=stderr), patch.object(verification, 'run', side_effect=command):
                self.assertEqual(_git_diff_check(self.root, 'fast', GitRangeSelection()).status, 'fail')
        selection = GitRangeSelection(findings=[{'severity': 'error', 'code': 'invalid-base', 'path': 'route', 'message': 'Invalid base.'}])
        self.assertEqual(_git_diff_check(self.root, 'pr', selection).status, 'fail')

    def test_complete_git_output_is_classified_and_retained_past_display_limit(self) -> None:
        self.policy([self.entry(path='historic.md', text='Evidence.\n\n', line=2, whitespace=True)])
        for i in range(180):
            self.write(f'errors/{i:03d}-' + 'x' * 60 + '.md', b'bad  \n')
        self.git('add', '.')
        result = _git_diff_check(self.root, 'fast', GitRangeSelection())
        self.assertEqual(result.status, 'fail')
        self.assertGreater(len(result.stdout), 12000)
        self.assertIn('errors/000-', result.stdout)
        self.assertIn('errors/179-', result.stdout)

    def test_evidence_mutation_during_scan_fails_closed(self) -> None:
        self.policy([self.entry()])
        original = verification.read_text_limited

        def mutate(path, *args, **kwargs):
            result = original(path, *args, **kwargs)
            if path.name == 'protocol.ts':
                self.write(EVIDENCE, b'Changed during scan.\n')
            return result

        with patch.object(verification, 'read_text_limited', side_effect=mutate):
            self.assertEqual(_secret_scan(self.root, ['protocol.ts']).status, 'fail')


if __name__ == '__main__':
    unittest.main()
