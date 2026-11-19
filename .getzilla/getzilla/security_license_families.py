"""Closed consistency checks for the existing byte-bound family findings."""

from __future__ import annotations

import hashlib
from pathlib import PurePosixPath
from .security_license_texts import _ANCILLARY_FILES, _REVIEWED_BUNDLES
from .security_artifacts import (
    MAX_ARTIFACT_BYTES,
    MAX_INDEX_BYTES,
    MAX_MEMBERS,
    artifact_context,
    family_identity,
    safe_parts,
)
from .security_data import _json


def _term_identifiers(item, *, reference=False):
    base = {'path', 'sha256'} if reference else {'path', 'sha256', 'bytes', 'validation'}
    if set(item) == base | {'recognized_license'} and type(item['recognized_license']) is str:
        return {item['recognized_license']}
    if (set(item) == base | {'recognized_licenses'} and type(item['recognized_licenses']) is list
            and item['sha256'] in _REVIEWED_BUNDLES
            and item['recognized_licenses'] == list(_REVIEWED_BUNDLES[item['sha256']])):
        return set(item['recognized_licenses'])
    return None


def finding_consistent(finding, allowed, select_expression):
    """Rejoin the retained record and component proof; never grant source authority."""
    if (isinstance(finding, dict) and isinstance(finding.get('family_record'), dict)
            and finding['family_record'].get('kind') == 'image'
            and isinstance(finding['family_record'].get('origin'), dict)
            and finding['family_record'].get('origin', {}).get('kind') == 'held-oci-components/v1'):
        from .security_image_licenses import finding_consistent as held_image_consistent
        return held_image_consistent(finding, allowed, select_expression)
    fields = {
        "kind",
        "reference",
        "status",
        "selected_expression",
        "distribution",
        "artifact_id",
        "artifact_sha256",
        "artifact_size",
        "subject",
        "context",
        "proofs",
        "license_files",
        "notice_files",
        "obligations",
        "family_record",
        "component_inventory_json",
    }
    try:
        if (
            type(finding) is not dict
            or set(finding) != fields
            or finding["status"] != "pass"
            or finding["distribution"] != "internal"
        ):
            return False
        record = finding["family_record"]
        if (
            family_identity(record) != finding["artifact_id"]
            or any(
                finding[left] != record[right]
                for left, right in (
                    ("kind", "kind"),
                    ("subject", "subject"),
                    ("context", "context"),
                    ("artifact_sha256", "sha256"),
                    ("artifact_size", "bytes"),
                )
            )
            or finding["reference"] != record["subject"]["reference"]
            or finding["context"] != artifact_context(finding["subject"])
            or finding["obligations"] != "internal use; exact source/component/license evidence retained"
        ):
            return False
        raw = finding["component_inventory_json"]
        if type(raw) is not str or not 1 <= len(raw.encode()) <= MAX_INDEX_BYTES:
            return False
        raw = raw.encode("utf-8")
        descriptor = record["components"]
        if hashlib.sha256(raw).hexdigest() != descriptor["sha256"]:
            return False
        proof = _json(raw)
        if (
            set(proof) != {"schema_version", "kind", "artifact_sha256", "complete", "unresolved", "components"}
            or type(proof["schema_version"]) is not int
            or proof["schema_version"] != 1
            or proof["kind"] != "artifact-component-inventory"
            or proof["artifact_sha256"] != record["sha256"]
            or proof["complete"] is not True
            or proof["unresolved"] != []
            or type(proof["components"]) is not list
            or not 1 <= len(proof["components"]) <= MAX_MEMBERS
        ):
            return False
        wanted, _ = select_expression(finding["selected_expression"], allowed)
        if finding["selected_expression"] != " AND ".join(sorted(set(wanted))):
            return False
        selected = []
        ids = set()
        members = {}
        license_paths = set()
        notice_paths = set()
        owners = {}
        for component in proof["components"]:
            if (
                type(component) is not dict
                or set(component) != {"id", "expression", "requires", "files", "license_paths", "notice_paths"}
                or type(component["id"]) is not str
                or not 1 <= len(component["id"]) <= 1024
                or component["id"] in ids
                or any(type(component[k]) is not list for k in ("requires", "files", "license_paths", "notice_paths"))
                or not component["files"]
            ):
                return False
            ids.add(component["id"])
            chosen, identifiers = select_expression(component["expression"], wanted)
            selected.extend(chosen)
            owned = set()
            for item in component["files"]:
                if type(item) is not dict or set(item) != {"path", "sha256", "bytes"}:
                    return False
                path = item["path"]
                safe_parts(path)
                if (
                    path in members
                    or type(item["bytes"]) is not int
                    or not 0 <= item["bytes"] <= MAX_ARTIFACT_BYTES
                    or type(item["sha256"]) is not str
                    or len(item["sha256"]) != 64
                    or any(c not in "0123456789abcdef" for c in item["sha256"])
                ):
                    return False
                members[path] = item
                owned.add(path)
                owners[path] = (component["id"], component["expression"], identifiers)
            for key, target in (("license_paths", license_paths), ("notice_paths", notice_paths)):
                for path in component[key]:
                    safe_parts(path)
                    if path not in owned:
                        return False
                    target.add(path)
        if (
            len(members) > MAX_MEMBERS
            or any(type(dep) is not str or dep not in ids for c in proof["components"] for dep in c["requires"])
            or finding["selected_expression"] != " AND ".join(sorted(set(selected)))
        ):
            return False
        observed_terms = set()
        observed_notices = set()
        term_records = {}
        ancillary_records = {}
        for key, paths in (("license_files", observed_terms), ("notice_files", observed_notices)):
            values = finding[key]
            if type(values) is not list or len(values) > MAX_MEMBERS:
                return False
            for item in values:
                if type(item) is not dict:
                    return False
                path = item.get("path")
                safe_parts(path)
                member = members.get(path)
                if (
                    member is None
                    or item.get("sha256") != member["sha256"]
                    or item.get("bytes") != member["bytes"]
                    or path in paths
                ):
                    return False
                if key == "license_files":
                    term_ids = _term_identifiers(item)
                    if (
                        not term_ids
                        or not term_ids <= owners[path][2]
                        or not term_ids <= set(allowed)
                        or item["validation"] != "complete-standard-terms-and-retained-bytes"
                    ):
                        return False
                    term_records[path] = item
                elif set(item) != {"path", "sha256", "bytes"}:
                    if set(item) != {
                        "path",
                        "sha256",
                        "bytes",
                        "ancillary_kind",
                        "expression",
                        "validation",
                        "required_files",
                    }:
                        return False
                    contract = _ANCILLARY_FILES.get(item["sha256"])
                    if (
                        contract is None
                        or item["ancillary_kind"] != contract[0]
                        or item["expression"] != contract[1]
                        or item["expression"] != owners[path][1]
                        or item["validation"] != "exact-reviewed-ancillary-with-independent-complete-terms"
                        or type(item["required_files"]) is not list
                    ):
                        return False
                    expected = {str(PurePosixPath(path).parent / name): sha for name, sha in contract[2]}
                    references = {}
                    for reference in item["required_files"]:
                        if type(reference) is not dict or not _term_identifiers(reference, reference=True):
                            return False
                        target = reference["path"]
                        term = term_records.get(target)
                        if (
                            target in references
                            or target == path
                            or term is None
                            or owners[target][0] != owners[path][0]
                            or reference["sha256"] != term["sha256"]
                            or _term_identifiers(reference, reference=True) != _term_identifiers(term)
                        ):
                            return False
                        references[target] = reference["sha256"]
                    if references != expected or not owners[path][2] <= set().union(*(
                        _term_identifiers(term_records[target]) for target in references
                    )):
                        return False
                    ancillary_records[path] = item
                paths.add(path)
        if (
            not license_paths <= observed_terms | set(ancillary_records)
            or not notice_paths <= observed_notices
            or not observed_terms
        ):
            return False
        expected = {descriptor["path"]: descriptor["sha256"]}
        origin = record["origin"]
        if record["kind"] in {"action", "tool"}:
            expected[origin["index_path"]] = origin["index_sha256"]
        if record["kind"] == "action":
            expected[origin["tree_path"]] = origin["tree_sha256"]
        witnesses = finding["proofs"]
        if type(witnesses) is not list or len(witnesses) != len(expected):
            return False
        actual = {}
        for witness in witnesses:
            if (
                type(witness) is not dict
                or set(witness) != {"path", "sha256", "bytes"}
                or type(witness["bytes"]) is not int
                or not 0 < witness["bytes"] <= MAX_INDEX_BYTES
                or witness["path"] in actual
            ):
                return False
            safe_parts(witness["path"])
            actual[witness["path"]] = witness["sha256"]
            if witness["path"] == descriptor["path"] and witness["bytes"] != len(raw):
                return False
        return actual == expected
    except (ValueError, KeyError, TypeError, AttributeError):
        return False
