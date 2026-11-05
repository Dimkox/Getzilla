"""Empty one identity-bound private directory; deliberately retain its root inode."""
from __future__ import annotations

import argparse
import errno
import inspect
import json
import os
from pathlib import Path
import shutil
import stat


def identity_matches(observed, expected: dict[str, str]) -> bool:
    return (stat.S_ISDIR(observed.st_mode)
            and (str(observed.st_dev), str(observed.st_ino), str(observed.st_uid))
            == (expected['dev'], expected['ino'], expected['uid']))


def cleanup_owned_directory(directory: Path, expected: dict[str, str]) -> dict:
    report = {'schema_version': 1, 'directory': str(directory), 'identity': expected,
              'contents_cleaned': False, 'root_removed': False, 'path_state': 'unknown',
              'reason': 'fd-cleanup-unavailable'}
    descriptor = None
    try:
        if (os.name != 'posix' or not shutil.rmtree.avoids_symlink_attacks
                or 'dir_fd' not in inspect.signature(shutil.rmtree).parameters
                or not all(hasattr(os, name) for name in ('O_DIRECTORY', 'O_NOFOLLOW', 'O_NONBLOCK'))):
            return report
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
                             | getattr(os, 'O_CLOEXEC', 0))
        observed = os.fstat(descriptor)
        if (not identity_matches(observed, expected) or observed.st_uid != os.getuid()
                or stat.S_IMODE(observed.st_mode) & 0o077):
            report['reason'] = 'identity-or-private-owner-mismatch'
            return report
        retained_root = False

        def retain_only_final_root(function, name, error):
            nonlocal retained_root
            # Only POSIX's exact final rmdir('.') refusal is accepted. Child errors abort.
            if function is os.rmdir and name == '.' and error.errno == errno.EINVAL:
                retained_root = True
                return
            raise error

        # Never reopen the original pathname after acquiring its verified descriptor.
        if 'onexc' in inspect.signature(shutil.rmtree).parameters:
            shutil.rmtree('.', dir_fd=descriptor, onexc=retain_only_final_root)
        else:
            shutil.rmtree('.', dir_fd=descriptor,
                          onerror=lambda function, name, exception: retain_only_final_root(function, name, exception[1]))
        with os.scandir(descriptor) as children:
            empty = next(children, None) is None
        if not retained_root or not empty:
            report['reason'] = 'empty-retained-root-not-confirmed'
            return report
        report.update(contents_cleaned=True, reason='contents-cleaned-root-retained')
    except OSError as error:
        report['reason'] = 'cleanup-refused-' + errno.errorcode.get(error.errno, 'OSERROR')
    except (ValueError, NotImplementedError):
        report['reason'] = 'cleanup-refused-invalid-or-unsupported-operation'
    finally:
        try:
            try:
                report['path_state'] = 'owned' if identity_matches(directory.lstat(), expected) else 'changed'
            except FileNotFoundError:
                report['path_state'] = 'absent'
            except OSError:
                report['path_state'] = 'unknown'
        finally:
            if descriptor is not None:
                os.close(descriptor)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', required=True, type=Path)
    for name in ('dev', 'ino', 'uid'):
        parser.add_argument('--' + name, required=True, type=int)
    options = parser.parse_args()
    expected = {name: str(getattr(options, name)) for name in ('dev', 'ino', 'uid')}
    print(json.dumps(cleanup_owned_directory(options.directory, expected)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
