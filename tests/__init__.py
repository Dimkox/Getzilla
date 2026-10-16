"""Test package.

On Windows, test fixtures write text with LF exactly as on POSIX: they model files as Git checks
them out here (.gitattributes eol=lf), and Windows' text mode would otherwise turn every newline
into CRLF and break byte-exact canonical documents. Product code is held to explicit newline
control by tests/test_text_writes.py, so this default cannot hide a product bug. Fixtures are read
as UTF-8 for the same reason (Windows would decode the ANSI code page); product reads name their
encoding under the same test.
"""
import os
import pathlib
import sys
import warnings

if os.name == 'nt':
    if not sys.flags.utf8_mode:
        warnings.warn('run the tests in UTF-8 mode on Windows: getzilla test, or python -X utf8 -m pytest',
                      stacklevel=1)
    _write_text = pathlib.Path.write_text

    def _write_text_lf(self, data, encoding=None, errors=None, newline=None):
        return _write_text(self, data, encoding=encoding, errors=errors, newline='\n' if newline is None else newline)

    pathlib.Path.write_text = _write_text_lf

    _read_text = pathlib.Path.read_text

    def _read_text_utf8(self, encoding=None, *args, **kwargs):
        return _read_text(self, 'utf-8' if encoding is None else encoding, *args, **kwargs)

    pathlib.Path.read_text = _read_text_utf8

    # Git for Windows enables core.autocrlf in its system config; the temporary repositories tests
    # create must keep LF bytes like a POSIX checkout. Tests that pass their own GIT_CONFIG_* keep it.
    if "GIT_CONFIG_COUNT" not in os.environ:
        os.environ.update({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.autocrlf", "GIT_CONFIG_VALUE_0": "false"})
