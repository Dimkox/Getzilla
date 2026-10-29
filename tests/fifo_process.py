"""Run test probes with separate child readiness and operation deadlines."""
from __future__ import annotations

import multiprocessing
import time


def _worker(connection, operation, args, startup_delay):
    try:
        if startup_delay:
            time.sleep(startup_delay)
        connection.send(('ready', None))
        if connection.recv() != 'go':
            return
        try:
            result = operation(*args)
            connection.send(('result', result))
        except Exception as exc:
            connection.send(('error', type(exc).__name__))
    finally:
        connection.close()


def run_fifo_probe(operation, args, *, startup_delay=0, startup_timeout=20, operation_timeout=0.5):
    context = multiprocessing.get_context('spawn')
    parent, child = context.Pipe()
    process = context.Process(target=_worker, args=(child, operation, args, startup_delay))
    process.start()
    child.close()
    try:
        if not parent.poll(startup_timeout) or parent.recv() != ('ready', None):
            raise AssertionError('probe readiness timed out')
        parent.send('go')
        if not parent.poll(operation_timeout):
            raise AssertionError('probe operation timed out')
        kind, result = parent.recv()
        if kind != 'result':
            raise AssertionError('probe child raised ' + str(result))
        process.join(5)
        if process.is_alive() or process.exitcode != 0:
            raise AssertionError('probe child did not exit cleanly')
        return result
    finally:
        parent.close()
        if process.is_alive():
            process.terminate()
            process.join(2)
        if process.is_alive():
            process.kill()
            process.join(2)
        if process.is_alive():
            raise AssertionError('probe child could not be reaped')
        process.close()
