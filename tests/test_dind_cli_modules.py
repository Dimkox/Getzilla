import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import security_dind_cli_modules as modules


class DockerCliModulesTests(unittest.TestCase):
    def test_exact_package_coverage_and_no_other_advisory_accepted(self):
        from getzilla.security_acquisition import TRIVY_VERSION
        from getzilla.security_dind_exception import CVE
        bom, expected = modules.source_packages(ROOT)
        self.assertEqual(len(bom['components']), 96)
        rows = [dict(Name=n, Version=v) for n, v in expected]
        hit = dict(VulnerabilityID=CVE, PkgName='github.com/docker/distribution', InstalledVersion='v2.8.3+incompatible')
        result = dict(Type='gobinary', Class='lang-pkgs', Packages=rows, Vulnerabilities=[hit])
        report = dict(SchemaVersion=2, ArtifactType='cyclonedx', Trivy={'Version': TRIVY_VERSION},
                      ArtifactName='cli.json', Results=[result])
        self.assertEqual(modules.validate_report(report, expected), [hit])
        for key, value in [('PkgName', 'other'), ('VulnerabilityID', 'CVE-2026-41567')]:
            result['Vulnerabilities'] = [dict(hit, **{key:value})]
            with self.assertRaises(modules.CliCoverageRefusal):
                modules.validate_report(report, expected)
        result['Packages'] = rows[:-1]
        with self.assertRaises(modules.CliCoverageRefusal):
            modules.validate_report(report, expected)

    def test_upstream_manifest_changed(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as directory:
            p = Path(directory) / modules.FILE
            p.parent.mkdir(parents=True)
            p.write_text(json.dumps({'components': []}))
            with self.assertRaises(modules.CliCoverageRefusal):
                modules.source_packages(Path(directory))
