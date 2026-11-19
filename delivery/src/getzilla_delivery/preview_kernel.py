"""Limits for the named Linux x86-64 trusted static server, not arbitrary code."""
from __future__ import annotations

import ctypes
import errno
import platform
import socket

from .preview_contracts import PreviewError


def restrict_ip_sockets():
    """No IP socket can be created after this point, including by child git reads.

    No network descriptor is inherited. This narrow filter is not a general
    syscall sandbox, filesystem jail or support for running hostile user code.
    """
    if platform.machine() != 'x86_64':
        raise PreviewError('unsupported_architecture')

    class Instruction(ctypes.Structure):
        _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
                    ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint32)]

    class Program(ctypes.Structure):
        _fields_ = [('length', ctypes.c_ushort), ('filter', ctypes.POINTER(Instruction))]

    # seccomp_data: arch offset4, nr offset0, first argument offset16.
    # x86-64 socket syscall41. Unknown ABI refuses all syscalls.
    instructions = (Instruction * 9)(
        Instruction(0x20, 0, 0, 4), Instruction(0x15, 1, 0, 0xC000003E),
        Instruction(0x06, 0, 0, 0x00050000 | errno.EPERM),
        Instruction(0x20, 0, 0, 0), Instruction(0x15, 0, 3, 41),
        Instruction(0x20, 0, 0, 16), Instruction(0x15, 1, 0, socket.AF_UNIX),
        Instruction(0x06, 0, 0, 0x00050000 | errno.EPERM),
        Instruction(0x06, 0, 0, 0x7FFF0000),
    )
    program = Program(len(instructions), instructions)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) or libc.prctl(22, 2, ctypes.byref(program), 0, 0):
        raise PreviewError('network_restriction_unavailable')
    results = {}
    for label, family in (('AF_INET', socket.AF_INET), ('AF_INET6', socket.AF_INET6)):
        try:
            probe = socket.socket(family, socket.SOCK_STREAM)
        except PermissionError:
            results[label] = 'denied'
        else:
            probe.close()
            raise PreviewError('network_restriction_failed')
    return results
