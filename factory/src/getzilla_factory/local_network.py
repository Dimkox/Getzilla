"""Inherited Linux TCP restrictions for an explicitly confined local client.

Use before exec, in a fresh single-threaded child, with no connected sockets.
This is one layer: a private network namespace and a trusted bounded admission
endpoint remain required. This module does not qualify a client or model.
"""
from __future__ import annotations

import ctypes
import os
import platform
import sys


class NetworkBoundaryError(ValueError):
    pass


def validate_tcp_ports(ports: tuple[int, ...]) -> None:
    if (type(ports) is not tuple or not 1 <= len(ports) <= 8
            or any(type(port) is not int or not 1 <= port <= 65535 for port in ports)
            or tuple(sorted(set(ports))) != ports):
        raise NetworkBoundaryError('invalid_tcp_port_allowlist')


def restrict_tcp_ports(ports: tuple[int, ...]) -> None:
    """Deny explicit TCP binds and every connect except declared TCP ports.

Landlock is inherited across fork/exec. Refuse missing ABI support; never fall
back to an unrestricted process. Keep the trusted backend on a different port.
"""
    validate_tcp_ports(ports)
    if sys.platform != 'linux' or platform.machine() not in {'x86_64', 'aarch64'}:
        raise NetworkBoundaryError('linux_network_boundary_unsupported')
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    # Linux generic syscall numbers on the explicitly supported architectures.
    if libc.syscall(444, 0, 0, 1) < 4:
        raise NetworkBoundaryError('landlock_network_abi_required')

    class Ruleset(ctypes.Structure):
        _fields_ = [('handled_access_fs', ctypes.c_uint64),
                    ('handled_access_net', ctypes.c_uint64)]

    class Port(ctypes.Structure):
        _fields_ = [('allowed_access', ctypes.c_uint64), ('port', ctypes.c_uint64)]

    ruleset = Ruleset(0, 3)  # BIND_TCP | CONNECT_TCP; grant only CONNECT_TCP.
    fd = libc.syscall(444, ctypes.byref(ruleset), ctypes.sizeof(ruleset), 0)
    if fd < 0:
        raise NetworkBoundaryError('landlock_ruleset_refused')
    try:
        for port in ports:
            rule = Port(2, port)
            if libc.syscall(445, fd, 2, ctypes.byref(rule), 0) != 0:
                raise NetworkBoundaryError('landlock_port_rule_refused')
        if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS.
            raise NetworkBoundaryError('no_new_privileges_refused')
        if libc.syscall(446, fd, 0) != 0:
            raise NetworkBoundaryError('landlock_enforcement_refused')
    finally:
        os.close(fd)
