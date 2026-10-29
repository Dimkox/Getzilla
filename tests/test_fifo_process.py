import time
import unittest

from tests.fifo_process import run_fifo_probe


def _value():
    return 'ok'


def _block():
    time.sleep(30)


class FifoProcessTest(unittest.TestCase):
    def test_readiness_budget_is_separate_from_operation_budget(self):
        self.assertEqual(run_fifo_probe(_value, (), startup_delay=0.7, operation_timeout=0.5), 'ok')

    def test_blocked_operation_fails_and_is_reaped(self):
        with self.assertRaisesRegex(AssertionError, 'operation timed out'):
            run_fifo_probe(_block, (), operation_timeout=0.2)
