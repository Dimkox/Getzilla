"""Synthetic readback validation; passing fixtures are NOT live permits."""
import copy
import importlib
import unittest


class StudyResourceTests(unittest.TestCase):
    def test_tmpfs_name_and_exact_protections_are_required(self):
        owner = self.owner()
        valid = self.fixture()['HostConfig']['Tmpfs']['/tmp']
        for tmpfs in ({}, {'/var/tmp': valid}, {'/tmp': valid, '/extra': valid},
                      {'/tmp': valid.replace(',noexec', '')},
                      {'/tmp': valid.replace('mode=700', 'mode=1777')}):
            item = self.fixture()
            item['HostConfig']['Tmpfs'] = tmpfs
            with self.subTest(tmpfs=tmpfs), self.assertRaises(ValueError):
                self.check(owner, item)

    def owner(self):
        try:
            return importlib.import_module('getzilla.retrieval.study_resources')
        except ModuleNotFoundError:
            self.fail('fixed offline resource readback validator missing')

    def fixture(self):
        return {'Image': 'sha256:' + 'a' * 64,
                'Config': {'User': '65532:65532', 'Entrypoint': ['python'], 'Cmd': ['worker']},
                'HostConfig': {'NetworkMode': 'none', 'ReadonlyRootfs': True,
                    'Privileged': False, 'CapDrop': ['ALL'], 'CapAdd': None,
                    'SecurityOpt': ['no-new-privileges:true'], 'Memory': 6442450944,
                    'MemorySwap': 6442450944, 'PidsLimit': 128, 'CpusetCpus': '2,3',
                    'NanoCpus': 2000000000, 'Runtime': 'runc', 'CgroupnsMode': 'private',
                    'Devices': [], 'DeviceRequests': [], 'PidMode': '', 'IpcMode': 'none',
                    'LogConfig': {'Type': 'none'},
                    'Tmpfs': {'/tmp': 'rw,noexec,nosuid,nodev,size=67108864,mode=700'}},
                'Mounts': [{'Type': 'bind', 'Source': '/fixture/model', 'Destination': '/model',
                            'RW': False, 'Propagation': 'rprivate'},
                           {'Type': 'bind', 'Source': '/fixture/software', 'Destination': '/software',
                            'RW': False, 'Propagation': 'rprivate'},
                           {'Type': 'bind', 'Source': '/fixture/worker', 'Destination': '/worker',
                            'RW': False, 'Propagation': 'rprivate'}]}

    def check(self, owner, value):
        return owner.validate_container_readback(value, image_id='sha256:' + 'a' * 64,
            cpu_ids=(2, 3), command=('python', 'worker'),
            mounts={'/model': '/fixture/model', '/software': '/fixture/software',
                    '/worker': '/fixture/worker'})

    def test_fixed_declarations_are_only_data_validation_not_authority(self):
        self.assertIsNone(self.check(self.owner(), self.fixture()))

    def test_network_swap_privilege_provider_mount_and_log_escape_refuse(self):
        owner = self.owner()
        changes = [('NetworkMode', 'host'), ('MemorySwap', -1), ('PidsLimit', 0),
                   ('ReadonlyRootfs', False), ('CapAdd', ['SYS_ADMIN']),
                   ('CpusetCpus', '2-4'), ('NanoCpus', 0), ('Runtime', 'nvidia'),
                   ('Devices', [{'PathOnHost': '/dev/nvidia0'}]),
                   ('LogConfig', {'Type': 'json-file'})]
        for key, value in changes:
            item = self.fixture()
            item['HostConfig'][key] = value
            with self.subTest(field=key), self.assertRaises(ValueError):
                self.check(owner, item)
        item = self.fixture()
        item['Mounts'].append({'Type': 'bind', 'Source': '/var/run/docker.sock',
                              'Destination': '/socket', 'RW': False, 'Propagation': 'rprivate'})
        with self.assertRaises(ValueError):
            self.check(owner, item)

    def test_image_command_uid_and_incomplete_inspection_refuse(self):
        for field, value in [('Image', 'sha256:' + 'b' * 64), ('Config', {}), ('Mounts', [])]:
            item = copy.deepcopy(self.fixture())
            item[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(self.owner(), item)

    def test_actual_kernel_profile_is_separate_and_missing_values_refuse(self):
        owner = self.owner()
        kernel = {'uid': 65532, 'cap_eff': 0, 'no_new_privs': 1, 'seccomp': 2,
                  'cpu_ids': [2, 3], 'interfaces': ['lo'], 'cgroup_cpu_ids': [2, 3],
                  'memory_max': 6442450944, 'swap_max': 0, 'pids_max': 128}
        self.assertIsNone(owner.validate_kernel_readback(kernel, cpu_ids=(2, 3)))
        for key, value in [('cgroup_cpu_ids', [0, 1, 2, 3]), ('swap_max', 1),
                           ('uid', 0), ('cap_eff', 1), ('interfaces', ['lo', 'eth0']),
                           ('seccomp', 0), ('memory_max', 'max')]:
            with self.subTest(field=key), self.assertRaises(ValueError):
                owner.validate_kernel_readback({**kernel, key: value}, cpu_ids=(2, 3))
