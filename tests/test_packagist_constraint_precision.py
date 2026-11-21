"""Owned pure numeric range controls; no artifact or project workload."""
import ctypes
import os
import socket
import subprocess
import sys
import unittest
from getzilla import security_packagist
from getzilla.security_artifacts import ArtifactError

_ACTIVE = False


def _deny_effect(event, args):
    if _ACTIVE and (event == 'open' or event in ('os.listdir', 'os.scandir', 'os.system', 'os.fork', 'os.posix_spawn')
                    or event.startswith(('socket.', 'subprocess.', 'ctypes.'))):
        raise AssertionError('pure constraint fixture denied external effect')


sys.addaudithook(_deny_effect)


class PackagistConstraintPrecisionTests(unittest.TestCase):
    def check_range(self, expression, inside, outside):
        global _ACTIVE
        _ACTIVE = True
        try:
            for value in inside:
                self.assertTrue(security_packagist.satisfies(value, expression), (expression, value))
            for value in outside:
                self.assertFalse(security_packagist.satisfies(value, expression), (expression, value))
        finally:
            _ACTIVE = False

    def test_tilde_four_component_exclusive_boundary(self):
        self.check_range('~1.2.3.4', ('1.2.3.4', '1.2.3.99'), ('1.2.3.3', '1.2.4.0', '1.3.0.0'))

    def test_caret_four_component_zero_prefix(self):
        self.check_range('^0.0.0.1', ('0.0.0.1', '0.0.0.2', '0.0.0.99'), ('0.0.0.0', '0.0.1.0'))
        self.check_range('^0.0.0.0', ('0.0.0.0', '0.0.0.99'), ('0.0.1.0',))

    def test_three_component_boundaries_unchanged(self):
        self.check_range('~1.2.3', ('1.2.3', '1.2.99.99'), ('1.2.2.99', '1.3.0'))
        self.check_range('^0.0.3', ('0.0.3', '0.0.3.99'), ('0.0.2.99', '0.0.4'))
        self.check_range('^0.2.3', ('0.2.3', '0.2.99'), ('0.2.2.99', '0.3.0'))
        self.check_range('^1.2.3', ('1.2.3', '1.99.99'), ('1.2.2.99', '2'))

    def test_other_precisions_and_comparisons_unchanged(self):
        self.check_range('~1.2', ('1.2', '1.99.99'), ('1.1.99', '2'))
        self.check_range('~1', ('1', '1.99'), ('0.99', '2'))
        self.check_range('^0.0', ('0.0', '0.0.99'), ('0.1',))
        self.check_range('^0', ('0', '0.99'), ('1',))
        self.check_range('^0.2.3.4', ('0.2.3.4', '0.2.99'), ('0.2.3.3', '0.3'))
        self.check_range('>=1.2.3.4,<1.2.4 || =2', ('1.2.3.4', '1.2.3.99', '2'), ('1.2.3.3', '1.2.4', '2.1'))

    def test_pure_guard_and_unsupported_forms(self):
        global _ACTIVE
        _ACTIVE = True
        try:
            for operation in (lambda: open('/etc/hosts'), lambda: os.listdir('/'), socket.socket,
                              lambda: subprocess.run(['true']), lambda: ctypes.CDLL(None)):
                with self.assertRaises(AssertionError):
                    operation()
            for expression in ('~1.2.3.4.5', '^dev-main', '1.*'):
                with self.assertRaises(ArtifactError):
                    security_packagist.satisfies('1.2.3.4', expression)
        finally:
            _ACTIVE = False
