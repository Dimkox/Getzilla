import importlib
import unittest


class StudyKernelTests(unittest.TestCase):
    def test_required_tmpfs_cannot_be_missing_duplicated_or_executable(self):
        owner = self.owner()
        readonly = ''.join(f'1 0 0:1 / {target} ro - overlay overlay ro\n'
                           for target in ('/', '/model', '/software', '/worker'))
        temporary = '2 0 0:2 / /tmp rw,nosuid,nodev,noexec - tmpfs tmpfs rw\n'
        self.assertIn('/tmp', owner._mounts(readonly + temporary))
        for value in (readonly, readonly + temporary + temporary,
                      readonly + temporary.replace(',noexec', ''),
                      readonly + temporary.replace('- tmpfs ', '- ext4 ')):
            with self.subTest(value=value), self.assertRaises(ValueError):
                owner._mounts(value)

    def owner(self):
        try:
            return importlib.import_module('getzilla.retrieval.study_kernel')
        except ModuleNotFoundError:
            self.fail('actual kernel readback owner missing')

    def test_cpu_range_parser_rejects_duplicates_empty_or_unbounded(self):
        owner = self.owner()
        self.assertEqual(owner._cpu_list('2-3'), [2, 3])
        for value in ('', '2,2', '3-2', '-1', '0-10000000', 'all'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                owner._cpu_list(value)

    def test_kernel_status_requires_real_all_uid_slots_and_no_new_privs(self):
        owner = self.owner()
        raw = ('Uid:\t65532\t65532\t65532\t65532\nCapEff:\t0000000000000000\n'
               'NoNewPrivs:\t1\nSeccomp:\t2\nCpus_allowed_list:\t2-3\nNSpid:\t1234\t1\n')
        result = owner._status(raw)
        self.assertEqual(result['uid'], 65532)
        self.assertEqual(result['cpu_ids'], [2, 3])
        for changed in (raw.replace('65532\t65532', '0\t65532', 1),
                        raw + 'Uid:\t65532\n', raw.replace('NSpid:', 'Missing:')):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                owner._status(changed)
