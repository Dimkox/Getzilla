"""Official PostgreSQL 17 server advisories for the verified Linux image corpus."""
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import hashlib
from html.parser import HTMLParser
import http.client
import json
from pathlib import Path
import re
import time
import urllib.request

from .security_acquisition import _NoQueryRedirects
from .security_oci import ImageSecurityRefusal

URL = "https://www.postgresql.org/support/security/17/"
MAX_BYTES = 1024 * 1024
HEADERS = ["Reference", "Affected", "Fixed", "Component & CVSS v3 Base Score", "Description"]
VERSION = re.compile(r"17\.(0|[1-9][0-9]{0,3})")
CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,9}")
SERVER_PATH = "usr/local/bin/postgres"
# Independent held-image observations bind each version marker to the whole executable.
BINARY_DIGESTS = {
    "17.11": "b65c19ceb9ae7e18f6e271e08dda64557a92d5a7bf46b76257d58d8c95678555",
    "17.12": "64f09db53daa65ca5a760517963b691e5cc293df7fc711e8ae34e6450089e0a3",
}


class PostgresRefusal(ImageSecurityRefusal):
    report_kind = "postgresql-server-check"


class _Tables(HTMLParser):
    """Require explicit, balanced table sections, rows and cells before using any values."""
    def __init__(self):
        super().__init__()
        self.tables = []
        self.stack = []
        self.cell = []
        self.links = []
        self.headings = []
        self.heading = None
        self.finished = False

    def handle_starttag(self, tag, attrs):
        if tag == "h3":
            self.heading = []
        if tag == "table":
            if self.stack:
                raise ValueError("nested advisory table")
            self.tables.append([])
            self.stack.append(tag)
        elif self.stack:
            if tag in {"thead", "tbody", "tr", "th", "td"}:
                parent = self.stack[-1]
                expected = {"thead": {"table"}, "tbody": {"table"}, "tr": {"thead", "tbody"},
                            "th": {"tr"}, "td": {"tr"}}
                if parent not in expected[tag] or tag in {"th", "td"} and self.stack[1] != (
                        "thead" if tag == "th" else "tbody"):
                    raise ValueError("unexpected advisory table structure")
                self.stack.append(tag)
                if tag == "tr":
                    self.tables[-1].append([])
                elif tag in {"td", "th"}:
                    self.cell, self.links = [], []
            elif tag == "a":
                self.links.append(dict(attrs).get("href"))
            elif tag == "br":
                self.cell.append("\n")

    def handle_data(self, data):
        if self.heading is not None:
            self.heading.append(data)
        if self.stack and self.stack[-1] in {"td", "th"}:
            self.cell.append(data)

    def handle_endtag(self, tag):
        if tag == "html":
            self.finished = True
        if tag == "h3" and self.heading is not None:
            self.headings.append(" ".join("".join(self.heading).split()))
            self.heading = None
        if tag in {"table", "thead", "tbody", "tr", "td", "th"}:
            if not self.stack or self.stack.pop() != tag:
                raise ValueError("incomplete advisory table")
            if tag in {"td", "th"}:
                self.tables[-1][-1].append(("".join(self.cell).strip(), tuple(self.links)))


def _advisories(body):
    if not 0 < len(body) <= MAX_BYTES:
        raise ValueError("advisory body size")
    page = _Tables()
    page.feed(body.decode("utf-8"))
    page.close()
    if (not page.finished or page.stack or len(page.tables) != 2
            or "Known PostgreSQL Security Vulnerabilities in PostgreSQL 17" not in page.headings):
        raise ValueError("incomplete PostgreSQL 17 page")
    table = page.tables[0]
    if not 2 <= len(table) <= 4097 or [v for v, _ in table[0]] != HEADERS:
        raise ValueError("unknown advisory columns")
    result = {}
    for cells in table[1:]:
        if len(cells) != 5:
            raise ValueError("unknown advisory row")
        (reference, links), (affected, _), (fixed, _), (score, _), (description, details) = cells
        cve = reference.split()[0] if reference else ""
        path = "/support/security/" + cve + "/"
        if not CVE.fullmatch(cve) or cve in result or not links or links[0] != path or details != (path,) or not description:
            raise ValueError("invalid advisory identifier or reference")
        majors, releases = affected.split(", "), fixed.split(", ")
        if (any(not re.fullmatch(r"[1-9][0-9]?", m) for m in majors) or len(set(majors)) != len(majors)
                or "17" not in majors or len(releases) != len(majors)
                or any(not re.fullmatch(m + r"\.(0|[1-9][0-9]{0,3})", v) for m, v in zip(majors, releases))):
            raise ValueError("unproved affected or fixed branch")
        component = score.split("\n")[0].strip()
        if component not in {"client", "contrib module", "core server"}:
            raise ValueError("unknown advisory component")
        result[cve] = [component, releases[majors.index("17")]]
    return result


def fetch():
    deadline = time.monotonic() + 20
    request = urllib.request.Request(URL, headers={"Accept-Encoding": "identity", "Cache-Control": "no-cache"})
    with urllib.request.build_opener(_NoQueryRedirects()).open(request, timeout=5) as response:
        def header(name, default=None):
            values = response.headers.get_all(name, [])
            if len(values) > 1:
                raise ValueError("ambiguous advisory metadata")
            return values[0] if values else default
        length = header("Content-Length")
        age = header("Age", "0")
        if (response.status != 200 or response.geturl() != URL or header("Content-Encoding", "identity") != "identity"
                or response.headers.get_content_type() != "text/html"
                or length is not None and (not re.fullmatch(r"[0-9]{1,8}", length) or int(length) > MAX_BYTES)
                or not re.fullmatch(r"[0-9]{1,10}", age)):
            raise ValueError("unexpected advisory response")
        stamp = parsedate_to_datetime(header("Date", ""))
        body = bytearray()
        while time.monotonic() < deadline:
            chunk = response.read1(min(65536, MAX_BYTES + 1 - len(body)))
            if len(body) > MAX_BYTES or time.monotonic() >= deadline:
                break
            if not chunk:
                if length is not None and len(body) != int(length):
                    raise ValueError("short advisory response")
                now = datetime.now(timezone.utc)
                if not stamp.tzinfo or stamp > now:
                    raise ValueError("invalid advisory response date")
                return bytes(body), min(stamp, now - timedelta(seconds=int(age)))
            body.extend(chunk)
        raise ValueError("advisory response exceeded bounds")


def assess(version, binary_version, body, stamp, now):
    if not VERSION.fullmatch(version) or binary_version != version:
        raise PostgresRefusal("postgres-version-unproved")
    if not stamp.tzinfo or not timedelta() <= now - stamp <= timedelta(hours=72):
        raise PostgresRefusal("postgres-advisories-stale")
    try:
        rows = _advisories(body)
        baseline = json.loads(Path(__file__).with_name("postgresql17_advisory_baseline.json").read_bytes())
        if any(rows.get(cve) != entry for cve, entry in baseline.items()) or not baseline:
            raise ValueError("previously reviewed advisories missing or changed")
        if version not in {entry[1] for entry in rows.values()}:
            raise ValueError("minor release absent from selected security page")
    except (ValueError, IndexError, TypeError) as error:
        raise PostgresRefusal("postgres-advisories-unproved") from error
    minor = int(version.split(".")[1])
    cves = sorted(cve for cve, (component, fixed) in rows.items()
                  if component == "core server" and minor < int(fixed.split(".")[1]))
    return dict(status="fail" if cves else "pass", version=version, source=URL, data_date=stamp.isoformat(),
                page_sha256=hashlib.sha256(body).hexdigest(), cves=cves)


def check_image(image, files, pages):
    from . import security_oci as oci
    from .security_artifacts import read_file
    config = read_file(image.layout, "blobs/sha256/" + image.config_digest[7:], oci.LIMITS["max_manifest_bytes"])
    if hashlib.sha256(config).hexdigest() != image.config_digest[7:]:
        raise PostgresRefusal("postgres-config-identity")
    env = oci.document(config).get("config", {}).get("Env", [])
    versions = [value[11:] for value in env if value.startswith("PG_VERSION=")]
    _, binary = files.resolve(SERVER_PATH)
    if not versions and binary is None and not image.reference.startswith("postgres@"):
        return None
    if (len(versions) != 1 or binary is None or not binary.get("elf") or not binary.get("executable")
            or not VERSION.fullmatch(versions[0]) or versions[0] != binary.get("postgres_version")
            or BINARY_DIGESTS.get(versions[0]) != binary["sha256"]):
        raise PostgresRefusal("postgres-version-unproved", manifest=image.manifest_digest)
    try:
        if URL not in pages:
            pages[URL] = fetch()
        body, stamp = pages[URL]
        result = assess(versions[0], binary["postgres_version"], body, stamp, datetime.now(timezone.utc))
    except PostgresRefusal:
        raise
    except (OSError, ValueError, RuntimeError, http.client.HTTPException, OverflowError) as error:
        raise PostgresRefusal("postgres-advisories-unavailable", manifest=image.manifest_digest) from error
    result.update(config=image.config_digest, manifest=image.manifest_digest,
                  binary_sha256=binary["sha256"], layer=binary["layer"])
    if result["cves"]:
        raise PostgresRefusal("postgres-server-cve", postgresql_server=result)
    return result
