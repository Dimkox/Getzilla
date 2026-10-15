"""Test package.

On Windows, test fixtures write text with LF exactly as on POSIX: they model files as Git checks
them out here (.gitattributes eol=lf), and Windows' text mode would otherwise turn every newline
into CRLF and break byte-exact canonical documents. Product code is held to explicit newline
control by tests/test_text_writes.py, so this default cannot hide a product bug.
"""
import os
import pathlib

if os.name == 'nt':
    _write_text = pathlib.Path.write_text

    def _write_text_lf(self, data, encoding=None, errors=None, newline=None):
        return _write_text(self, data, encoding=encoding, errors=errors, newline='\n' if newline is None else newline)

    pathlib.Path.write_text = _write_text_lf

    # Git for Windows enables core.autocrlf in its system config; the temporary repositories tests
    # create must keep LF bytes like a POSIX checkout. Tests that pass their own GIT_CONFIG_* keep it.
    if "GIT_CONFIG_COUNT" not in os.environ:
        os.environ.update({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.autocrlf", "GIT_CONFIG_VALUE_0": "false"})
