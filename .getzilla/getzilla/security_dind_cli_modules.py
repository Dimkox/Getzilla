"""Scan the exact upstream Docker CLI vendor manifest omitted by its GOPATH build."""
import hashlib
from pathlib import Path
import tempfile
from urllib.parse import quote

from . import security_dind_exception as dind
from . import security_tools as tools_api
from .security_acquisition import TRIVY_VERSION
from .security_artifacts import read_file
from .security_oci import ImageSecurityRefusal, canonical

FILE = '.getzilla/config/docker-cli-29.10.1-modules.txt'
VENDOR_SHA = 'd658a91e424c51e4dd1ff6bdd1a142a7bb15a38c0b2dd1c53c8104dfead0c6bc'
COMMIT = 'c48360f51c53d2029ab6721ad4d012f9e14df846'
KNOWN = (dind.CVE, 'github.com/docker/distribution', 'v2.8.3+incompatible')


class CliCoverageRefusal(ImageSecurityRefusal):
    report_kind = 'image-component-vulnerability'


def source_packages(root):
    raw = read_file(root, FILE, 32768)
    if hashlib.sha256(raw).hexdigest() != VENDOR_SHA:
        raise CliCoverageRefusal('unverified-docker-cli-vendor-manifest')
    # All module headers in the pinned upstream vendor/modules.txt are name/version
    # pairs with no replacements. Root identity and toolchain come from go version -m
    # on the exact released amd64 executable in the reviewed Docker archive.
    pairs = [tuple(line[2:].split()) for line in raw.decode().splitlines() if line.startswith('# ')]
    pairs.extend([('github.com/docker/cli', 'v29.10.1+incompatible'), ('stdlib', 'v1.27.4')])
    components = []
    for name, version in pairs:
        purl = 'pkg:golang/' + quote(name, safe='/') + '@' + quote(version, safe='')
        components.append(dict(type='library', name=name, version=version, purl=purl, **{'bom-ref': purl}))
    return dict(bomFormat='CycloneDX', specVersion='1.5', version=1, components=components), pairs


def validate_report(report, expected):
    results = report.get('Results')
    if (report.get('SchemaVersion') != 2 or report.get('ArtifactType') != 'cyclonedx'
            or report.get('ArtifactName') != 'cli.json' or report.get('Trivy', {}).get('Version') != TRIVY_VERSION
            or not isinstance(results, list) or len(results) != 1):
        raise CliCoverageRefusal('incomplete-docker-cli-module-scan')
    result = results[0]
    packages = [(r['Name'], r['Version']) for r in result['Packages']]
    if (result['Class'] != 'lang-pkgs' or result['Type'] != 'gobinary'
            or sorted(packages) != sorted(expected)):
        raise CliCoverageRefusal('incomplete-docker-cli-module-scan')
    findings = result.get('Vulnerabilities')
    if not isinstance(findings, list) or not findings:
        raise CliCoverageRefusal('known-docker-cli-advisory-missing')
    other = [dict(cve=r['VulnerabilityID'], package=r['PkgName'], version=r['InstalledVersion'])
             for r in findings if (r['VulnerabilityID'], r['PkgName'], r['InstalledVersion']) != KNOWN]
    if other:
        raise CliCoverageRefusal('additional-docker-cli-vulnerabilities', manifest=dind.MANIFEST,
                                 executable_sha256=dind.CLI['executable_sha256'], findings=other)
    return findings


def scan(image, root, trivy, tools):
    # Only the independently reported CVE can proceed to the mandatory file-removal check.
    with tempfile.TemporaryDirectory(prefix='cli-modules-', dir=tools) as directory:
        scratch = Path(directory)
        try:
            before = tools_api.trivy_database_source(tools)
            bom, packages = source_packages(root)
            (scratch / 'cli.json').write_bytes(canonical(bom))
            output = scratch / 'report.json'
            command = [str(trivy), 'sbom', '--scanners', 'vuln', '--offline-scan', '--skip-db-update',
                       '--skip-java-db-update', '--skip-version-check', '--skip-vex-repo-update', '--list-all-pkgs',
                       '--show-suppressed', '--cache-dir', str(tools / 'cache'), *tools_api.trivy_options(scratch),
                       '--format', 'json', '--output', str(output), 'cli.json']
            process = tools_api._process(command, scratch, scratch, timeout=image.remaining_seconds())
            report = tools_api._process_report(output, process)
            hits = validate_report(report, packages)
            if tools_api.trivy_database_source(tools) != before:
                raise CliCoverageRefusal('docker-cli-module-database-changed')
        except ImageSecurityRefusal:
            raise
        except (OSError, ValueError, TypeError, KeyError, RuntimeError) as error:
            raise CliCoverageRefusal('docker-cli-module-scan-unavailable', step=type(error).__name__) from error
        return packages, dict(upstream_commit=COMMIT, vendor_sha256=VENDOR_SHA, packages=len(packages),
                              database_sha256=before['content_sha256'], cves=sorted({r['VulnerabilityID'] for r in hits}),
                              report_sha256=hashlib.sha256(canonical(report)).hexdigest())
