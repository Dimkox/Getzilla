"""Data-only ELF metadata reconstruction. Never execute, import or load the input."""
from __future__ import annotations

import hashlib
import json
import math
import re
import struct
import time

from getzilla.execution_output import RESPONSE_BYTES

VERSION = '0.1.0'
PROVIDER = 'builtin-elf64-le-v1'
MAX_BYTES = 4 * 1024 * 1024
MATRIX = {PROVIDER: {'format': 'ELF64 little-endian x86-64 ET_EXEC/ET_DYN',
                     'mode': 'static-metadata', 'dependency': 'Python standard library',
                     'target_execution': False},
          'ghidra': {'status': 'unsupported'}, 'rea': {'status': 'unsupported'},
          'PE/Mach-O/JS/APK/WASM': {'status': 'unsupported'}}


class Stopped(ValueError):
    """A fixed code; raw input and rejected names are never diagnostic text."""


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def analyze(raw, *, question, provider=PROVIDER, max_sections=128, max_functions=128,
            deadline=None, cancelled=lambda: False, clock=time.monotonic):
    """Return bounded advisory facts, retaining validated partial facts on a stop.

    The caller owns current source admission, original deadline and cancellation.
    No file, process, socket, model, task or publication API is used here.
    """
    start = clock()
    if (type(raw) is not bytes or type(provider) is not str or len(provider) > 64
            or not re.fullmatch('[A-Za-z0-9_.-]+', provider) or type(question) is not str or not 1 <= len(question) <= 512
            or any(ord(c) < 32 for c in question)):
        raise ValueError('invalid_input')
    if (type(max_sections) is not int or not 1 <= max_sections <= 512
            or type(max_functions) is not int or not 1 <= max_functions <= 512):
        raise ValueError('invalid_limits')
    deadline = start + 1 if deadline is None else deadline
    if (type(deadline) not in (int, float) or not math.isfinite(deadline)
            or deadline - start > 2):
        raise ValueError('invalid_limits')
    result = {'schema_version': 1, 'provider': PROVIDER, 'provider_version': VERSION,
              'question': question, 'requested_provider': provider, 'input_sha256': None, 'input_bytes': len(raw),
              'status': 'partial', 'reason': None, 'needed': [], 'exports': [],
              'behavior': 'unknown', 'target_executed': False,
              'facts': 'declared ELF metadata, not evidence of runtime behavior',
              'unknowns': ['function signatures and semantics', 'runtime dependency availability',
                           'ASLR/load addresses', 'symbol version requirements', 'original source'],
              'handoff': {'component_map': 'needed and exports with byte locators',
                          'behavior_specification': 'unverified; design controlled checks before implementation',
                          'automatic_tasks': False, 'automatic_reimplementation': False,
                          'publication': False},
              'cost': {'external_api_calls': 0, 'external_api_cost': 0, 'compute_cost': None},
              'limits': {'bytes': MAX_BYTES, 'sections': max_sections, 'functions': max_functions,
                         'metadata_entries': 4096, 'result_bytes': RESPONSE_BYTES},
              'observed': {'sections': 0, 'metadata_entries': 0}}

    def check():
        if cancelled():
            raise Stopped('cancelled')
        if clock() >= deadline:
            raise Stopped('deadline_exceeded')

    def need(condition, reason='malformed_elf'):
        if not condition:
            raise Stopped(reason)

    def bounded(offset, size):
        need(0 <= offset <= len(raw) and 0 <= size <= len(raw) - offset)
        return raw[offset:offset + size]

    def text(table, offset, *, dependency=False):
        need(0 <= offset < len(table))
        end = table.find(b'\0', offset, min(len(table), offset + 129))
        need(end >= offset, 'unsupported_name')
        try:
            name = table[offset:end].decode('ascii')
        except UnicodeError:
            raise Stopped('unsupported_name') from None
        pattern = r'[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}' if dependency else r'[A-Za-z_][A-Za-z0-9_.$@-]{0,127}'
        need(bool(re.fullmatch(pattern, name)), 'unsupported_name')
        return name

    def entry():
        check()
        result['observed']['metadata_entries'] += 1
        need(result['observed']['metadata_entries'] <= 4096, 'metadata_limit')

    def append(kind, row):
        result[kind].append(row)
        # Reserve final status/timing fields so reporting the stop also fits.
        if len(_encoded(result)) > RESPONSE_BYTES - 4096:
            result[kind].pop()
            raise Stopped('result_limit')

    try:
        need(provider == PROVIDER, 'provider_unavailable')
        check()
        need(len(raw) <= MAX_BYTES, 'byte_limit')
        result['input_sha256'] = hashlib.sha256(raw).hexdigest()
        need(len(raw) >= 64 and raw[:7] == b'\x7fELF\x02\x01\x01', 'unsupported_format')
        h = struct.unpack_from('<16sHHIQQQIHHHHHH', raw)
        need(h[1] in (2, 3) and h[2] == 62 and h[3] == 1 and h[8] == 64, 'unsupported_elf_profile')
        offset, size, count, names = h[6], h[11], h[12], h[13]
        need(count != 0, 'section_table_unavailable')
        need(count <= max_sections, 'section_limit')
        need(size == 64 and names < count)
        bounded(offset, count * size)
        sections = []
        for index in range(count):
            check()
            row = struct.unpack_from('<IIQQQQIIQQ', raw, offset + index * size)
            need(row[1] == 8 or row[4] + row[5] <= len(raw))
            sections.append(row)
            result['observed']['sections'] += 1
        need(sections[names][1] == 3)
        result['file_type'] = 'executable' if h[1] == 2 else 'shared-or-pie'
        result['architecture'] = 'x86-64'
        result['entry_address'] = h[4]
        for section_index, row in enumerate(sections):
            check()
            if row[1] not in (6, 11):
                continue
            need(not row[2] & 0x800 and row[6] < count)
            table = sections[row[6]]
            need(table[1] == 3 and table[5] <= MAX_BYTES)
            strings = bounded(table[4], table[5])
            width = 16 if row[1] == 6 else 24
            need(row[9] == width and row[5] % width == 0)
            terminated = False
            for index in range(row[5] // width):
                entry()
                position = row[4] + index * width
                if row[1] == 6:
                    tag, value = struct.unpack_from('<qQ', raw, position)
                    if tag == 0:
                        terminated = True
                        break
                    if tag == 1:
                        append('needed', {'name': text(strings, value, dependency=True),
                            'section_index': section_index, 'entry_index': index,
                            'evidence_offset': position, 'string_offset': table[4] + value})
                else:
                    name, info, other, defined, address, length = struct.unpack_from('<IBBHQQ', raw, position)
                    if info & 15 != 2 or info >> 4 not in (1, 2) or not defined or other & 3 not in (0, 3):
                        continue
                    need(defined < count)
                    code = sections[defined]
                    need(code[1] == 1 and code[2] & 4 and code[3] <= address
                         and address - code[3] < code[5] and length <= code[5] - (address - code[3]))
                    need(len(result['exports']) < max_functions, 'function_limit')
                    append('exports', {'name': text(strings, name), 'address': address,
                        'size': length, 'file_offset': code[4] + address - code[3],
                        'section_index': section_index, 'entry_index': index, 'evidence_offset': position,
                        'binding': 'global' if info >> 4 == 1 else 'weak', 'behavior': 'unknown'})
            need(row[1] != 6 or terminated)
        check()
        result.update(status='complete', reason=None)
    except Stopped as error:
        result['reason'] = str(error)
        if str(error) in ('unsupported_format', 'unsupported_elf_profile', 'section_table_unavailable'):
            result['status'] = 'unsupported'
        elif str(error) == 'provider_unavailable':
            result['status'] = 'unavailable'
    result['elapsed_seconds'] = max(0, clock() - start)
    result['elapsed_scope'] = 'parser-only'
    return result


def render_text(report):
    lines = [f"Static ELF report: {report['status']} ({report['reason'] or 'metadata scanned'})",
             f"Provider: {report['provider']} {report['provider_version']}",
             'Research question: ' + report['question'],
             'Target execution: never; behavior: unknown.', 'Input SHA256: ' + str(report['input_sha256'])]
    lines += [f"Needed: {row['name']} at file offset {row['evidence_offset']}" for row in report['needed']]
    lines += [f"Export: {row['name']} at ELF address 0x{row['address']:x}; behavior unknown" for row in report['exports']]
    return '\n'.join(lines)
