"""A healthy network response alone never proves a PostgreSQL server safe."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from getzilla import security_postgresql as pg


class PostgreSQLServerTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 11, 25, tzinfo=timezone.utc)
        baseline = json.loads(Path(pg.__file__).with_name("postgresql17_advisory_baseline.json").read_bytes())
        self.rows = []
        for cve, (component, fixed) in baseline.items():
            link = f'<a href="/support/security/{cve}/">{cve}</a>'
            self.rows.append(f"<tr><td>{link}</td><td>17</td><td>{fixed}</td>"
                             f"<td>{component}<br/>5.0</td><td>{link}</td></tr>")
        header = "".join(f"<th>{title}</th>" for title in pg.HEADERS)
        self.prefix = ("<html><h3>Known PostgreSQL Security Vulnerabilities in PostgreSQL 17</h3>"
                       f"<table><thead><tr>{header}</tr></thead><tbody>")
        self.suffix = "</tbody></table><table></table></html>"

    def assess(self, version="17.12", *, body=None, binary=None, hours=0):
        body = self.prefix + "".join(self.rows) + self.suffix if body is None else body
        return pg.assess(version, binary or version, body.encode(), self.now - timedelta(hours=hours), self.now)

    def test_exact_server_advisories_and_fixed_release(self):
        affected = self.assess("17.11")
        self.assertEqual(affected["status"], "fail")
        self.assertIn("CVE-2026-120154", affected["cves"])
        fixed = self.assess()
        self.assertEqual((fixed["version"], fixed["status"], fixed["cves"]), ("17.12", "pass", []))
        self.assertEqual(fixed["data_date"], self.now.isoformat())

    def test_old_future_unknown_or_conflicting_version(self):
        for changes in (dict(hours=73), dict(hours=-1), dict(version="17.99"), dict(binary="17.11")):
            with self.subTest(changes=changes), self.assertRaises(pg.PostgresRefusal):
                self.assess(**changes)

    def test_missing_row_changed_fix_or_component_and_truncated_html(self):
        raw = self.prefix + "".join(self.rows) + self.suffix
        for body in (raw.replace(self.rows[0], ""), raw.replace("17.12", "17.11", 1),
                     raw.replace("core server", "client", 1), raw.replace("Affected", "Impacted"),
                     raw[:-7], self.prefix + self.suffix):
            with self.assertRaises(pg.PostgresRefusal):
                self.assess(body=body)

    def test_binary_marker_crosses_oci_chunk_boundary(self):
        from getzilla.security_oci import _component_row
        from io import BytesIO
        import tarfile
        from unittest.mock import Mock
        member = tarfile.TarInfo(pg.SERVER_PATH)
        member.mode = 0o755
        payload = b"\x7fELF" + b"x" * 65524 + b"\x00postgres (PostgreSQL) 17.12\n\x00"
        member.size = len(payload)
        row = _component_row(member, Mock(extractfile=lambda _: BytesIO(payload)), False, Mock())
        self.assertEqual(row["postgres_version"], "17.12")
        payload += b"\x00postgres (PostgreSQL) 17.11\n\x00"
        member.size = len(payload)
        row = _component_row(member, Mock(extractfile=lambda _: BytesIO(payload)), False, Mock())
        self.assertNotIn("postgres_version", row)

    def test_advisory_transport_refuses_a_redirect(self):
        with patch("urllib.request.build_opener") as opener:
            response = opener.return_value.open.return_value.__enter__.return_value
            response.status = 200
            response.geturl.return_value = "https://example.org/"
            with self.assertRaises(ValueError):
                pg.fetch()
