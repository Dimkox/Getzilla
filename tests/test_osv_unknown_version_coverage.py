"""Schema-valid unknown version coverage is data, never an absence decision."""
from contextlib import ExitStack, contextmanager
from datetime import date
import copy
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import known_vulns as legacy  # noqa: E402
from getzilla import security_osv_snapshot as snapshot  # noqa: E402
from getzilla import security_data as data  # noqa: E402


def row(name='owned', **fields):
    return {'package': {'ecosystem': 'PyPI', 'name': name}, **fields}


def record(identifier, *rows):
    return {'id': identifier, 'affected': list(rows)}


def archive(records):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as bundle:
        for index, value in enumerate(records):
            bundle.writestr(zipfile.ZipInfo(f'owned-{index}.json', (2026, 1, 1, 0, 0, 0)), json.dumps(value))
    return output.getvalue()


@contextmanager
def denied_effects():
    def denied(*args, **kwargs):
        raise AssertionError('unmocked outside fixture effect')

    with ExitStack() as stack:
        for target in ('builtins.open', 'io.open', 'os.open', 'subprocess.Popen', 'os.system', 'os.fork',
                       'os.posix_spawn', 'socket.socket', 'socket.create_connection', 'ctypes.CDLL', 'ctypes.PyDLL'):
            stack.enter_context(patch(target, denied, create=True))
        yield


@contextmanager
def owned_query_ports(module, payload):
    """Only the owned archive port and synthetic dependency/config are permitted."""
    original_zip = zipfile.ZipFile

    def opened(value, *args, **kwargs):
        if isinstance(value, Path):
            if value != Path('/owned-db/PyPI/all.zip'):
                raise AssertionError('outside owned archive')
            value = io.BytesIO(payload)
        return original_zip(value, *args, **kwargs)

    def owned_file(path):
        if path != Path('/owned-db/PyPI/all.zip'):
            raise AssertionError('outside owned archive metadata')
        return True

    with ExitStack() as stack:
        stack.enter_context(patch.object(zipfile, 'ZipFile', side_effect=opened))
        if module is snapshot:
            def read_owned(database, source, **kwargs):
                if database != Path('/owned-db') or source != 'osv:PyPI':
                    raise AssertionError('outside owned snapshot')
                data.osv_coverage(payload, 'PyPI')
                return payload, {}
            stack.enter_context(patch.object(snapshot, 'read_snapshot', side_effect=read_owned))
        else:
            stack.enter_context(patch.object(Path, 'is_file', owned_file))
        stack.enter_context(denied_effects())
        yield


class UnknownVersionCoverageTests(unittest.TestCase):
    def query(self, module, records, version='1.0.0', *, waiver=False):
        payload = archive(records)
        dependency = module.Dependency('PyPI', 'owned', version, 'owned.lock')
        with owned_query_ports(module, payload), ExitStack() as stack:
            if not waiver:
                return module.query_offline([dependency], Path('/owned-db'))
            stack.enter_context(patch.object(module, 'load_config', return_value={
                'exclude': [], 'accept': [{'id': 'OSV-KNOWN', 'expires': '2099-01-01'},
                                           {'id': 'OSV-UNKNOWN', 'expires': '2099-01-01'}]}))
            stack.enter_context(patch.object(module, 'collect_dependencies', return_value=([dependency], ['owned.lock'])))
            return module.scan(Path('/owned-project'), environ={'GETZILLA_OSV_DB': '/owned-db'}, today=date(2026, 11, 17))

    def test_transport_retains_unknown_rows_and_exact_archive_bytes(self):
        records = [record('OSV-KNOWN', row(versions=['1.0.0'])), record('OSV-UNKNOWN', row('other'))]
        before = copy.deepcopy(records)
        payload = archive(records)
        with denied_effects():
            self.assertEqual(data.osv_coverage(payload, 'PyPI')['record_count'], 2)
        with zipfile.ZipFile(io.BytesIO(payload)) as bundle:
            self.assertEqual([json.loads(bundle.read(name)) for name in bundle.namelist()], before)
        self.assertEqual(payload, archive(before))
        self.assertEqual(records, before)

    def test_unrelated_unknown_row_coexists_with_known_match_in_both_queries(self):
        records = [record('OSV-UNKNOWN', row('other')), record('OSV-KNOWN', row(versions=['1.0.0']))]
        for module in (legacy, snapshot):
            finding, = self.query(module, records)
            self.assertEqual(finding.vuln_id, 'OSV-KNOWN', module.__name__)
            self.assertEqual(finding.dependency.name, 'owned')

    def test_matching_unknown_is_error_at_every_version_in_both_queries(self):
        for module in (legacy, snapshot):
            for version in ('0.0.0', '1.0.0', '999.0.0'):
                with self.assertRaisesRegex(module.VulnerabilityError, 'version coverage is unknown'):
                    self.query(module, [record('OSV-UNKNOWN', row())], version)

    def test_matching_known_record_cannot_hide_a_matching_unknown_record(self):
        records = [record('OSV-KNOWN', row(versions=['1.0.0'])), record('OSV-UNKNOWN', row())]
        for module in (legacy, snapshot):
            for ordered in (records, list(reversed(records))):
                with self.assertRaisesRegex(module.VulnerabilityError, 'version coverage is unknown'):
                    self.query(module, ordered)

    def test_matching_known_row_cannot_hide_unknown_row_in_same_record(self):
        for module in (legacy, snapshot):
            for rows in ((row(versions=['1.0.0']), row()), (row(), row(versions=['1.0.0']))):
                with self.assertRaisesRegex(module.VulnerabilityError, 'version coverage is unknown'):
                    self.query(module, [record('OSV-KNOWN', *rows)])

    def test_ordinary_waiver_cannot_hide_matching_unknown_in_either_scan(self):
        for module in (legacy, snapshot):
            with self.assertRaisesRegex(module.VulnerabilityError, 'version coverage is unknown'):
                self.query(module, [record('OSV-KNOWN', row(versions=['1.0.0'])),
                                    record('OSV-UNKNOWN', row())], waiver=True)

    def test_malformed_versions_and_ranges_remain_global_refusals(self):
        for fields in ({'versions': None}, {'versions': '1'}, {'versions': [None]}, {'versions': ['']},
                       {'ranges': None}, {'ranges': {}}, {'ranges': [None]}):
            payload = archive([record('OSV-KNOWN', row(versions=['1.0.0'])),
                               record('OSV-UNRELATED', row('other', **fields))])
            with denied_effects(), self.assertRaisesRegex(data.SecurityDataError, 'malformed OSV (versions|ranges)'):
                data.osv_coverage(payload, 'PyPI')

    def test_empty_explicit_bounds_are_unknown_not_all_versions(self):
        records = [record('OSV-UNKNOWN', row(versions=[], ranges=[]))]
        payload = archive(records)
        with denied_effects():
            self.assertEqual(data.osv_coverage(payload, 'PyPI')['record_count'], 1)
        for module in (legacy, snapshot):
            with self.assertRaisesRegex(module.VulnerabilityError, 'version coverage is unknown'):
                self.query(module, records)
