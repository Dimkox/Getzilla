"""Bounded public source data for the two checker tools; no execution or LIVE authority."""

from __future__ import annotations

import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import time
from urllib.parse import unquote, urlsplit

from . import security_go_tool_inputs as reader
from .security_go_contracts import MODULES_KEY
from .security_artifacts import ArtifactError, MAX_ARTIFACT_BYTES, MAX_INDEX_BYTES, MAX_METADATA_BYTES, read_file
from .security_data import MAX_AGE_SECONDS, _clock, _json
from .security_license_acquisition import MAX_BATCH_BYTES, _write
from .manifest import _open_root

SOURCE_TRANSFER_BYTES = 1024**3
DEADLINE_SECONDS = 600
ROOT_NAME = "checker-tools"


def fail(code, message):
    raise ArtifactError(code, message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def descriptor(body, prefix="objects"):
    sha = hashlib.sha256(body).hexdigest()
    return dict(path=prefix + "/" + sha, sha256=sha)


def _allowed(url, *, redirect_from=None):
    if type(url) is not str or len(url) > 8192 or any(ord(char) < 32 for char in url):
        return False
    value = urlsplit(url)
    if (
        value.scheme != "https"
        or value.username is not None
        or value.password is not None
        or value.port not in (None, 443)
        or value.fragment
        or any(part in {".", ".."} for part in unquote(value.path).split("/"))
    ):
        return False
    if redirect_from is not None:
        original = urlsplit(redirect_from)
        if (
            original.hostname == "proxy.golang.org"
            and value.hostname == "storage.googleapis.com"
            and value.path.startswith("/proxy-golang-org-prod/")
        ):
            return True
        if (
            original.hostname == "github.com"
            and value.hostname == "release-assets.githubusercontent.com"
            and (
                value.path.startswith("/github-production-release-asset/")
                or value.path.startswith("/github-production-release-asset-")
            )
        ):
            return True
        return url == redirect_from
    if value.query:
        return False
    if value.hostname == "github.com":
        return url in {spec["url"] for spec in reader.PIN_SPECS.values()}
    if value.hostname == "api.github.com":
        return bool(
            re.fullmatch(
                r"/repos/(?:aquasecurity/trivy|moby/buildkit|opencontainers/runc)/(?:releases/tags/v[0-9]+\.[0-9]+\.[0-9]+|git/(?:commits|trees|blobs)/[0-9a-f]{40})",
                value.path,
            )
        )
    if value.hostname == "raw.githubusercontent.com":
        return bool(re.fullmatch(r"/golang/go/go[0-9]+\.[0-9]+\.[0-9]+/(?:LICENSE|PATENTS)", value.path))
    if value.hostname == "proxy.golang.org":
        return bool(re.fullmatch(r"/[A-Za-z0-9_.!~+/-]+/@v/v[A-Za-z0-9_.!+~-]+\.zip", value.path))
    return False


def fetch_public(url, maximum, *, deadline=None):
    """Fixed anonymous origins; environment proxies, credentials and raw redirects are not persisted."""
    if type(maximum) is not int or not 0 < maximum <= MAX_ARTIFACT_BYTES or not _allowed(url):
        fail("go-source-origin", "unsupported public source origin or byte bound")
    deadline = time.monotonic() + DEADLINE_SECONDS if deadline is None else deadline
    current = url
    for redirect in range(4):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            fail("go-source-timeout", "public source deadline expired")
        parsed = urlsplit(current)
        connection = http.client.HTTPSConnection(parsed.hostname, timeout=min(15, remaining))
        try:
            target = parsed.path + ("?" + parsed.query if parsed.query else "")
            connection.request(
                "GET", target, headers={"User-Agent": "Getzilla-Go-Source/1", "Accept-Encoding": "identity"}
            )
            response = connection.getresponse()
            if response.status in {301, 302, 303, 307, 308}:
                location = response.getheader("Location")
                if redirect == 3 or not _allowed(location, redirect_from=url):
                    fail("go-source-origin", "public source redirect is outside its fixed origin")
                current = location
                continue
            if response.status != 200:
                error = ArtifactError("go-source-http", "public source returned a non-success status")
                error.http_status = response.status
                raise error
            length = response.getheader("Content-Length")
            if length is not None and (not length.isdecimal() or not 0 < int(length) <= maximum):
                fail("artifact-size", "public source length exceeds its bound")
            if response.getheader("Content-Encoding") not in (None, "identity"):
                fail("go-source-transport", "public source content encoding is unsupported")
            chunks, size = [], 0
            while True:
                if time.monotonic() >= deadline:
                    fail("go-source-timeout", "public source deadline expired")
                block = response.read1(min(65536, maximum + 1 - size))
                if not block:
                    break
                chunks.append(block)
                size += len(block)
                if size > maximum:
                    fail("artifact-size", "public source body exceeds its bound")
            if not size or length is not None and size != int(length):
                fail("artifact-size", "public source body is empty or truncated")
            return b"".join(chunks), dict(requested_url=url, fetched_at=time.time(), status=200)
        except (OSError, http.client.HTTPException) as original:
            error = ArtifactError("go-source-transport", "public source transport unavailable")
            error.errno = getattr(original, "errno", None)
            raise error from None
        finally:
            connection.close()
    fail("go-source-origin", "public source redirect count exceeded")


class Store:
    """Owned immutable source objects and original-clock receipts below one namespace."""

    def __init__(self, root, *, now=None, fetch=None, byte_budget=None, cache_only=False):
        self.root = Path(root)
        self._now = now
        self.deadline = time.monotonic() + DEADLINE_SECONDS
        self.fetch = fetch or (lambda url, maximum: fetch_public(url, maximum, deadline=self.deadline))
        self.budget = MAX_BATCH_BYTES if byte_budget is None else byte_budget
        if type(self.budget) is not int or not 0 < self.budget <= MAX_BATCH_BYTES:
            fail("artifact-size", "invalid shared retained-source budget")
        self.cache_only = cache_only
        self.fd = None
        self.facts = []
        self.generated = []
        self.failures = {}
        self.transferred = 0
        self.retained_bytes = 0

    def __enter__(self):
        if not self.cache_only:
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root, self.fd = _open_root(self.root)
        if type(self.fd) is not int:
            fail("artifact-platform", "qualified POSIX source store required")
        return self

    def __exit__(self, *_):
        if self.fd is not None:
            os.close(self.fd)

    @property
    def now(self):
        return _clock(self._now)

    def save(self, body, *, prefix="objects"):
        if not isinstance(body, bytes) or not body or len(body) > MAX_ARTIFACT_BYTES:
            fail("artifact-size", "source object is empty or unbounded")
        desc = descriptor(body, prefix)
        if self.cache_only:
            if read_file(self.root, desc["path"], MAX_ARTIFACT_BYTES) != body:
                fail("artifact-hash", "retained generated source proof changed")
        else:
            _write(self.fd, desc["path"], body, immutable=True)
        return desc

    def generated_object(self, body, *, roles):
        if len(body) > MAX_INDEX_BYTES:
            fail("artifact-size", "generated Go metadata exceeds its existing bound")
        desc = descriptor(body)
        previous = next((row for row in self.generated if row["descriptor"] == desc), None)
        additional = set(roles) - set(previous["roles"] if previous else [])
        if self.retained_bytes + len(body) * len(additional) > self.budget:
            fail("artifact-size", "generated checker proof exceeds the shared retained budget")
        self.retained_bytes += len(body) * len(additional)
        self.save(body)
        if previous:
            previous["roles"] = sorted(set(previous["roles"]) | set(roles))
        else:
            self.generated.append(dict(descriptor=desc, roles=sorted(set(roles)), bytes=len(body)))
        return desc

    def _fresh(self, timestamp):
        return type(timestamp) in (int, float) and 0 <= self.now.timestamp() - timestamp <= MAX_AGE_SECONDS

    def request(self, url, maximum):
        if self.retained_bytes >= self.budget:
            fail("artifact-size", "checker source retained budget is exhausted")
        data, observation = self.fetch(url, maximum)
        if (
            not isinstance(data, bytes)
            or not 0 < len(data) <= maximum
            or type(observation) is not dict
            or observation.get("requested_url") != url
            or observation.get("status") != 200
            or not self._fresh(observation.get("fetched_at"))
        ):
            fail("go-source-clock", "source response bytes, origin or original clock are invalid")
        self.transferred += len(data)
        if self.transferred > SOURCE_TRANSFER_BYTES:
            fail("go-source-budget", "Go raw-source transfer exceeds its finite one-GiB calibration")
        return data, observation

    def _fact(self, url, body, receipt, data, *, stage, roles):
        receipt_raw = read_file(self.root, receipt["path"], MAX_METADATA_BYTES)
        if hashlib.sha256(receipt_raw).hexdigest() != receipt["sha256"]:
            fail("artifact-hash", "source fact receipt changed")
        saved = _json(receipt_raw)
        fact = dict(
            url=url,
            body=body,
            receipt=receipt,
            bytes=len(data),
            fetched_at=saved["fetched_at"],
            stage=stage,
            roles=sorted(set(roles)),
        )
        previous = next((row for row in self.facts if row["url"] == url and row["stage"] == stage), None)
        additional = set(roles) - set(previous["roles"] if previous else [])
        cost = (len(data) + len(receipt_raw)) * len(additional)
        if self.retained_bytes + cost > self.budget:
            fail("artifact-size", "retained checker sources exceed the shared byte budget")
        self.retained_bytes += cost
        if previous:
            if any(previous[key] != fact[key] for key in ("body", "receipt", "bytes", "fetched_at")):
                fail("go-source-cache", "one source URL changed during preparation")
            previous["roles"] = sorted(set(previous["roles"]) | set(roles))
            fact = previous
        else:
            self.facts.append(fact)
        return fact

    def get(self, url, maximum, *, stage, roles):
        if time.monotonic() >= self.deadline:
            fail("go-source-timeout", "checker source preparation deadline expired")
        key = ("raw", url)
        if key in self.failures:
            raise self.failures[key]
        try:
            return self._get(url, maximum, stage=stage, roles=roles)
        except (ArtifactError, OSError, ValueError, KeyError, TypeError) as error:
            self.failures[key] = error
            raise

    def _get(self, url, maximum, *, stage, roles):
        if not _allowed(url):
            fail("go-source-origin", "unsupported public source origin")
        key = "cache/" + hashlib.sha256(url.encode()).hexdigest()
        try:
            os.stat(key, dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError:
            cached = None
        else:
            cached = _json(read_file(self.root, key, MAX_METADATA_BYTES))
        if cached is not None:
            receipt_raw = read_file(self.root, cached["path"], MAX_METADATA_BYTES)
            if hashlib.sha256(receipt_raw).hexdigest() != cached["sha256"]:
                fail("artifact-hash", "source cache receipt changed")
            saved = _json(receipt_raw)
            if (
                set(saved) != {"schema_version", "url", "body", "fetched_at", "status"}
                or type(saved["schema_version"]) is not int
                or saved["schema_version"] != 1
                or saved["url"] != url
                or saved["status"] != 200
            ):
                fail("go-source-cache", "source cache belongs to another origin")
            data = read_file(self.root, saved["body"]["path"], maximum)
            if hashlib.sha256(data).hexdigest() != saved["body"]["sha256"]:
                fail("artifact-hash", "source cache bytes changed")
            if self._fresh(saved["fetched_at"]):
                return data, self._fact(url, dict(saved["body"]), cached, data, stage=stage, roles=roles)
            if self.cache_only:
                fail("go-source-stale", "source cache is stale or future-dated")
        if self.cache_only:
            fail("go-source-missing", "required source is not retained")
        data, observation = self.request(url, maximum)
        body = self.save(data)
        receipt = self.save(
            canonical(dict(schema_version=1, url=url, body=body, fetched_at=observation["fetched_at"], status=200)),
            prefix="receipts",
        )
        _write(self.fd, key, canonical(receipt))
        return data, self._fact(url, dict(body), receipt, data, stage=stage, roles=roles)

    def module(self, required, *, roles):
        if time.monotonic() >= self.deadline:
            fail("go-source-timeout", "checker source preparation deadline expired")
        key = ("module", required["path"], required["version"], required["h1"])
        if key in self.failures:
            raise self.failures[key]
        try:
            return self._module(required, roles=roles)
        except (ArtifactError, OSError, ValueError, KeyError, TypeError) as error:
            self.failures[key] = error
            raise

    def _module(self, required, *, roles):
        path, version, checksum = (required[key] for key in ("path", "version", "h1"))

        def escape(value):
            return "".join("!" + char.lower() if char.isupper() else char for char in value)

        url = "https://proxy.golang.org/" + escape(path) + "/@v/" + escape(version) + ".zip"
        key = "cache/module-" + hashlib.sha256((url + "\n" + checksum).encode()).hexdigest()
        try:
            os.stat(key, dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError:
            pointer = None
        else:
            pointer = _json(read_file(self.root, key, MAX_METADATA_BYTES))
        if pointer is not None:
            receipt_raw = read_file(self.root, pointer["path"], MAX_METADATA_BYTES)
            if hashlib.sha256(receipt_raw).hexdigest() != pointer["sha256"]:
                fail("artifact-hash", "module cache receipt changed")
            saved = _json(receipt_raw)
            if (
                set(saved) != {"schema_version", "url", "body", "fetched_at", "status"}
                or type(saved["schema_version"]) is not int
                or saved["schema_version"] != 1
                or saved["url"] != url
                or saved["status"] != 200
            ):
                fail("go-source-cache", "module cache belongs to another source response")
            raw = read_file(self.root, saved["body"]["path"], MAX_INDEX_BYTES)
            if hashlib.sha256(raw).hexdigest() != saved["body"]["sha256"] or saved["url"] != url:
                fail("artifact-hash", "module cache body or origin changed")
            proof = _json(raw)
            reader.verify_module_proof(proof, path, version, checksum)
            if (
                type(proof.get("origin")) is not dict
                or proof["origin"].get("requested_url") != url
                or proof["origin"].get("fetched_at") != saved["fetched_at"]
            ):
                fail("go-source-cache", "module source clock differs from original cache receipt")
            if self._fresh(saved["fetched_at"]):
                return proof, self._fact(url, saved["body"], pointer, raw, stage="module", roles=roles)
            if self.cache_only:
                fail("go-source-stale", "module source is stale or future-dated")
        if self.cache_only:
            fail("go-source-missing", "required module source is not retained")
        payload, observation = self.request(url, MAX_ARTIFACT_BYTES)
        proof = reader.module_proof(payload, path, version, checksum)
        proof["origin"] = dict(requested_url=url, fetched_at=observation["fetched_at"])
        raw = canonical(proof)
        if len(raw) > MAX_INDEX_BYTES:
            fail("artifact-size", "compact module proof exceeds its metadata bound")
        body = self.save(raw)
        receipt = self.save(
            canonical(dict(schema_version=1, url=url, body=body, fetched_at=observation["fetched_at"], status=200)),
            prefix="receipts",
        )
        _write(self.fd, key, canonical(receipt))
        return proof, self._fact(url, body, receipt, raw, stage="module", roles=roles)


def _gap(error, *, role, stage, module=None):
    code = getattr(error, "code", "go-source-unavailable")
    if type(code) is not str or not re.fullmatch("[a-z][a-z0-9-]{0,79}", code):
        code = "go-source-unavailable"
    return dict(
        role=role,
        stage=stage,
        code=code,
        **({"module": module} if module else {}),
        errno=getattr(error, "errno", None),
        http_status=getattr(error, "http_status", None),
    )


def _source_lock(store, repository, revision, *, roles):
    if repository not in {"moby/buildkit", "opencontainers/runc", "aquasecurity/trivy"} or not re.fullmatch(
        "[0-9a-f]{40}", revision
    ):
        fail("go-source-lock", "exact accepted source repository and revision are required")
    api = "https://api.github.com/repos/" + repository + "/git/"

    def get(kind, sha):
        body, fact = store.get(api + kind + "/" + sha, MAX_INDEX_BYTES, stage="source-lock", roles=roles)
        return _json(body), fact["body"]

    commit, commit_desc = get("commits", revision)
    tree, tree_desc = get("trees", commit["tree"]["sha"])
    rows = reader._git_node(tree)
    vendor, vendor_desc = get("trees", rows["vendor"]["sha"])
    vendor_rows = reader._git_node(vendor)
    blobs = {}
    for path in ("go.sum", "vendor/modules.txt", "LICENSE"):
        row = vendor_rows["modules.txt"] if path == "vendor/modules.txt" else rows[path]
        _, blobs[path] = get("blobs", row["sha"])
    proof = dict(
        schema_version=1,
        kind="go-git-source-lock/v1",
        repository=repository,
        revision=revision,
        commit=commit_desc,
        root_tree=tree_desc,
        vendor_tree=vendor_desc,
        blobs=blobs,
    )
    desc = store.generated_object(canonical(proof), roles=roles)
    lock, files, evidence = reader.verify_source_lock(store.root, desc, repository, revision)
    return desc, lock, files, evidence


def _assemble(checker, inventory, declarations, store):
    gaps, archives, releases, observations = [], {}, {}, {}
    for declaration in declarations:
        role = declaration["role"]
        repository = "aquasecurity/trivy" if role == "trivy" else "moby/buildkit"
        index = "https://api.github.com/repos/" + repository + "/releases/tags/v" + declaration["version"]
        try:
            payload, fact = store.get(declaration["reference"], MAX_ARTIFACT_BYTES, stage="archive", roles=[role])
            observed, legal = reader.observe_archive(payload, declaration)
            archives[role] = (fact["body"], len(payload), legal)
            observations[role] = observed
        except (ArtifactError, OSError, ValueError, KeyError, TypeError) as error:
            gaps.append(_gap(error, role=role, stage="archive"))
        try:
            raw, fact = store.get(index, MAX_INDEX_BYTES, stage="release", roles=[role])
            release = _json(raw)
            expected_name = declaration["reference"].rsplit("/", 1)[-1]
            assets = [
                row for row in release.get("assets", []) if isinstance(row, dict) and row.get("name") == expected_name
            ]
            if (
                release.get("tag_name") != "v" + declaration["version"]
                or len(assets) != 1
                or assets[0].get("browser_download_url") != declaration["reference"]
                or assets[0].get("digest") != "sha256:" + declaration["archive_sha256"]
                or role in archives
                and assets[0].get("size") != archives[role][1]
            ):
                fail("artifact-origin", "release metadata differs from exact checker artifact")
            releases[role] = fact["body"]
        except (ArtifactError, OSError, ValueError, KeyError, TypeError) as error:
            gaps.append(_gap(error, role=role, stage="release"))
    locks, lock_descs, lock_files, attempted_locks = {}, {}, {}, set()
    for role, observed in observations.items():
        for executable in observed["executables"].values():
            info = executable["buildinfo"]
            need_lock = role == "buildkit" or any(not dep.get("replace", dep)["h1"] for dep in info["dependencies"])
            if not need_lock:
                continue
            repository = info["main"]["path"].removeprefix("github.com/")
            revision = info["settings"].get("vcs.revision", "")
            key = repository + "@" + revision
            if key in attempted_locks:
                continue
            attempted_locks.add(key)
            try:
                desc, lock, files, _ = _source_lock(store, repository, revision, roles=[role])
                locks[key], lock_descs[key], lock_files[key] = lock, desc, files
            except (ArtifactError, OSError, ValueError, KeyError, TypeError) as error:
                gaps.append(_gap(error, role=role, stage="source-lock", module=key))
    try:
        required, checksum_gaps = reader.module_requirements(observations, locks)
        gaps.extend(
            dict(role=row["role"], stage="module-requirements", code=row["code"], module=row["module"])
            for row in checksum_gaps
        )
    except (ArtifactError, OSError, ValueError, KeyError, TypeError) as error:
        required = {}
        gaps.extend(_gap(error, role=role, stage="module-requirements") for role in observations)
    modules = {}
    for key, requirement in required.items():
        roles = sorted({use["role"] for use in requirement["uses"]})
        try:
            proof, fact = store.module(requirement, roles=roles)
            modules[key] = fact["body"]
            terms = reader.verify_module_proof(proof, requirement["path"], requirement["version"], requirement["h1"])
            reader.component_from_terms("go-module:" + key, terms)
        except (ArtifactError, OSError, ValueError, KeyError, TypeError) as error:
            gaps.extend(_gap(error, role=role, stage="module", module=key) for role in roles)
    runtime = {}
    for role, observed in observations.items():
        for member, executable in observed["executables"].items():
            info = executable["buildinfo"]
            if info["settings"].get("CGO_ENABLED") != "0":
                gaps.append(dict(role=role, stage="native", code="go-cgo-native-unresolved", member=member))
            version = runtime_version(info["go_version"])
            runtime.setdefault(version, {})
            for name in ("LICENSE", "PATENTS"):
                url = "https://raw.githubusercontent.com/golang/go/" + version + "/" + name
                try:
                    _, fact = store.get(url, MAX_METADATA_BYTES, stage="runtime", roles=[role])
                    runtime[version][name] = {**fact["body"], "url": url}
                except (ArtifactError, OSError, ValueError, KeyError, TypeError) as error:
                    gaps.append(_gap(error, role=role, stage="runtime", module=version + "/" + name))
    records = []
    from .security_artifacts import artifact_context

    for declaration, subject in zip(declarations, inventory["tools"]):
        role = declaration["role"]
        if (
            role not in observations
            or role not in archives
            or role not in releases
            or any(row["role"] == role for row in gaps)
        ):
            continue
        needed, missing = reader.module_requirements({role: observations[role]}, locks)
        if missing or set(needed) - modules.keys():
            continue
        versions = {
            runtime_version(row["buildinfo"]["go_version"]) for row in observations[role]["executables"].values()
        }
        selected_locks = {
            row["buildinfo"]["main"]["path"].removeprefix("github.com/")
            + "@"
            + str(row["buildinfo"]["settings"].get("vcs.revision"))
            for row in observations[role]["executables"].values()
        }
        proof = {
            "schema_version": 1,
            "kind": "go-checker-components/v1",
            "tool_id": declaration["id"],
            "release": releases[role],
            MODULES_KEY: {key: modules[key] for key in needed},
            "source_locks": {key: lock_descs[key] for key in selected_locks if key in lock_descs},
            "runtime": {version: runtime[version] for version in versions},
            "expressions": {},
        }
        raw = canonical(proof)
        desc = store.generated_object(raw, roles=[role])
        acquired = min(row["fetched_at"] for row in store.facts if role in row["roles"])
        archive, size, _ = archives[role]
        record = dict(
            schema_version=1,
            kind="tool",
            subject=subject,
            filename=declaration["reference"].rsplit("/", 1)[-1],
            path=archive["path"],
            sha256=archive["sha256"],
            bytes=size,
            context=artifact_context(subject),
            acquired_at=_clock(datetime_from_timestamp(acquired)).isoformat(),
            origin=dict(
                kind="go-checker-release/v1",
                declaration=declaration,
                index_url="https://api.github.com/repos/"
                + ("aquasecurity/trivy" if role == "trivy" else "moby/buildkit")
                + "/releases/tags/v"
                + declaration["version"],
                artifact_url=declaration["reference"],
            ),
            components=desc,
        )
        try:
            reader.verify_family(store.root, record, checker=checker, now=store.now)
            records.append(record)
        except (ArtifactError, OSError, ValueError, KeyError, TypeError) as error:
            gaps.append(_gap(error, role=role, stage="family"))
    return records, gaps, store.generated


def datetime_from_timestamp(value):
    from datetime import datetime, timezone

    return datetime.fromtimestamp(value, timezone.utc)


def runtime_version(value):
    if value.endswith("-X:jsonv2"):
        return value.removesuffix("-X:jsonv2")
    if "-X:" in value:
        fail("go-buildinfo-version", "Go runtime experiment needs a separately supported source profile")
    return value


def _prepare(checker, artifacts, *, inventory_digest, now=None, fetch=None, byte_budget=None, cache_only=False):
    if type(inventory_digest) is not str or not re.fullmatch("[0-9a-f]{64}", inventory_digest):
        fail("artifact-inventory-binding", "parent source inventory digest is required")
    inventory = reader.checker_inventory(checker)
    result = dict(
        schema_version=1,
        kind="go-checker-tools-preparation/v1",
        status="incomplete-source-inputs",
        parent_inventory_sha256=inventory_digest,
        inventory=inventory,
        records=[],
        gaps=[],
        source_facts=[],
    )
    with Store(
        Path(artifacts) / ROOT_NAME, now=now, fetch=fetch, byte_budget=byte_budget, cache_only=cache_only
    ) as store:
        records, gaps, generated = _assemble(checker, inventory, reader.checker_declarations(checker), store)
        result.update(records=records, gaps=gaps, generated=generated)
        result["source_facts"] = store.facts
        acquired = min((row["fetched_at"] for row in store.facts), default=store.now.timestamp())
        catalog = dict(
            schema_version=1,
            inventory_digest=inventory["digest"],
            last_verified_sync_utc=datetime_from_timestamp(acquired).isoformat(),
            records=records,
            gaps=gaps,
        )
        raw = canonical(catalog)
        if store.retained_bytes + len(raw) > store.budget:
            fail("artifact-size", "joined checker catalog exceeds the shared retained budget")
        if not cache_only:
            _write(store.fd, "manifest.json", raw)
        result["catalog"] = dict(path=ROOT_NAME + "/manifest.json", sha256=hashlib.sha256(raw).hexdigest())
        result["source_bytes"] = store.retained_bytes
        result["bound_bytes"] = store.retained_bytes + len(raw)
        if len(records) == 2 and not gaps:
            result["status"] = "complete-source-inputs"
    return result


def prepare_tools(checker, artifacts, tools=None, *, inventory_digest, now=None, fetch=None, byte_budget=None):
    """Retain data for both source-owned uses; no namespace or policy authority is created."""
    return _prepare(
        checker, artifacts, inventory_digest=inventory_digest, now=now, fetch=fetch, byte_budget=byte_budget
    )


def validate_preparation(artifacts, report, *, inventory_digest, now=None, byte_budget=None, checker=None):
    """Reobserve fixed source/cache facts without writes or network; never publish raw inventory rows."""
    from .security_tools import TRUSTED_ROOT
    from .security_data import _timestamp

    checker = TRUSTED_ROOT if checker is None else checker
    budget = MAX_BATCH_BYTES if byte_budget is None else byte_budget
    if type(budget) is not int or not 0 < budget <= MAX_BATCH_BYTES:
        fail("artifact-size", "invalid remaining shared source budget")
    expected = {
        "schema_version",
        "kind",
        "status",
        "parent_inventory_sha256",
        "inventory",
        "records",
        "gaps",
        "source_facts",
        "generated",
        "catalog",
        "bound_bytes",
        "source_bytes",
    }
    if (
        type(report) is not dict
        or set(report) != expected
        or type(report["schema_version"]) is not int
        or report["schema_version"] != 1
        or report["kind"] != "go-checker-tools-preparation/v1"
        or report["parent_inventory_sha256"] != inventory_digest
    ):
        fail("go-source-provider", "Go source report differs from its complete parent inventory")
    observed = _prepare(checker, artifacts, inventory_digest=inventory_digest, now=now, cache_only=True)
    for field in ("inventory", "records", "source_facts", "generated", "status"):
        if report[field] != observed[field]:
            fail("go-source-provider", "Go source report omits or changes independently reobserved facts")
    catalog = report["catalog"]
    if (
        type(catalog) is not dict
        or set(catalog) != {"path", "sha256"}
        or catalog["path"] != ROOT_NAME + "/manifest.json"
    ):
        fail("go-source-provider", "Go source catalog leaves its fixed auxiliary namespace")
    raw = read_file(artifacts, catalog["path"], MAX_INDEX_BYTES)
    if hashlib.sha256(raw).hexdigest() != catalog["sha256"]:
        fail("artifact-hash", "joined checker catalog changed")
    bundle = _json(raw)
    if (
        type(bundle) is not dict
        or set(bundle) != {"schema_version", "inventory_digest", "last_verified_sync_utc", "records", "gaps"}
        or type(bundle["schema_version"]) is not int
        or bundle["schema_version"] != 1
        or bundle["inventory_digest"] != observed["inventory"]["digest"]
        or bundle["records"] != observed["records"]
        or bundle["gaps"] != report["gaps"]
    ):
        fail("go-source-provider", "joined checker catalog drops or swaps an actual tool context")

    def gap_contexts(rows):
        if type(rows) is not list:
            fail("go-source-provider", "checker source gaps must retain their closed contexts")
        contexts = []
        for row in rows:
            if (
                type(row) is not dict
                or not {"role", "stage", "code"} <= set(row)
                or set(row) - {"role", "stage", "code", "module", "member", "errno", "http_status"}
                or row["role"] not in {"trivy", "buildkit"}
                or row["stage"]
                not in {
                    "archive",
                    "release",
                    "source-lock",
                    "module-requirements",
                    "module",
                    "native",
                    "runtime",
                    "family",
                }
                or any(
                    value is not None and (type(value) is not int or not 0 <= value <= 65535)
                    for value in (row.get("errno"), row.get("http_status"))
                )
                or type(row["code"]) is not str
                or not re.fullmatch("[a-z][a-z0-9-]{0,79}", row["code"])
            ):
                fail("go-source-provider", "checker source gap has unsupported diagnostic fields")
            contexts.append(tuple(row.get(key) for key in ("role", "stage", "module", "member")))
        return contexts

    if gap_contexts(report["gaps"]) != gap_contexts(observed["gaps"]):
        fail("go-source-provider", "checker source report omits an independently required gap context")
    age = (_clock(now) - _timestamp(bundle["last_verified_sync_utc"])).total_seconds()
    if not 0 <= age <= MAX_AGE_SECONDS:
        fail("go-source-stale", "joined checker catalog is stale or future-dated")
    bound = observed["source_bytes"] + len(raw)
    if bound > budget:
        fail("artifact-size", "checker source facts exceed the remaining shared retained budget")
    return dict(records=[], gaps=observed["gaps"], bound_bytes=bound)
