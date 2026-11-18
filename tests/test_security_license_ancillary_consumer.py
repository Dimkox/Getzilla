"""Ancillary declarations retain bytes but cannot stand in for complete terms."""

import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".getzilla"))
from getzilla import security_licenses as licenses
from getzilla.security_artifacts import ArtifactError

TERMS = json.loads((ROOT / "tests/fixtures/security-license-texts.json").read_bytes())


class AncillaryConsumerTests(unittest.TestCase):
    def actual_cases(self):
        base = ROOT / "tests/fixtures"
        ancillary = json.loads((base / "security-license-frontier-ancillary.json").read_bytes())
        full = json.loads((base / "security-license-frontier-variants.json").read_bytes())
        full += json.loads((base / "security-license-frontier-references.json").read_bytes())
        by_sha = {item["sha256"]: item["text"].encode() for item in full}
        for item in ancillary:
            files = {item["member"]: item["text"].encode()}
            parent = PurePosixPath(item["member"]).parent
            for relative, sha in item["expected"]["required_files"].items():
                self.assertEqual(hashlib.sha256(by_sha[sha]).hexdigest(), sha)
                files[str(parent / relative)] = by_sha[sha]
            metadata = dict(expression=item["expected"]["expression"], license_paths=list(files), classifiers=[])
            chosen, identifiers = licenses._select_expression(metadata["expression"], list(licenses.ALLOWED))
            yield item, files, metadata, chosen, identifiers

    def test_four_actual_retained_ancillary_cases_bind_independent_complete_terms(self):
        count = 0
        for item, files, metadata, chosen, identifiers in self.actual_cases():
            count += 1
            with self.subTest(package=item["package"]):
                terms, notices = licenses._license_evidence(files, metadata, identifiers, chosen)
                self.assertEqual({row["recognized_license"] for row in terms}, identifiers)
                self.assertNotIn(item["member"], {row["path"] for row in terms})
                self.assertEqual(len(notices), 1)
                self.assertEqual(notices[0]["path"], item["member"])
                self.assertEqual(notices[0]["sha256"], item["sha256"])
                self.assertNotIn("recognized_license", notices[0])
        self.assertEqual(count, 4)

    def test_actual_ancillary_cannot_hide_missing_changed_or_name_only_full_terms(self):
        for item, files, metadata, chosen, identifiers in self.actual_cases():
            for reference in set(files) - {item["member"]}:
                for change in ("missing", "changed", "name-only"):
                    with self.subTest(package=item["package"], reference=reference, change=change):
                        altered = dict(files)
                        if change == "missing":
                            altered.pop(reference)
                        if change == "changed":
                            altered[reference] += b"\nRedistribution is prohibited.\n"
                        if change == "name-only":
                            altered[reference] = b"Apache-2.0 OR BSD-3-Clause\n"
                        with self.assertRaises(ArtifactError):
                            licenses._license_evidence(altered, metadata, identifiers, chosen)
            altered = dict(files)
            altered[item["member"]] += b"\nRedistribution is prohibited.\n"
            with self.assertRaises(ArtifactError):
                licenses._license_evidence(altered, metadata, identifiers, chosen)

    def fixture(self, expression="MIT", kind="attribution"):
        names = {"MIT": "LICENSE", "Apache-2.0": "LICENSE.APACHE", "BSD-3-Clause": "LICENSE.BSD"}
        identifiers = expression.split(" OR ")
        files = {"owned.dist-info/licenses/" + names[name]: TERMS[name]["text"].encode() for name in identifiers}
        path = "owned.dist-info/licenses/" + ("AUTHORS.rst" if kind == "attribution" else "LICENSE.DECLARATION")
        files[path] = b"owned exact reviewed ancillary declaration"
        declaration = dict(
            kind=kind,
            expression=expression,
            required_files={
                names[name]: hashlib.sha256(TERMS[name]["text"].encode()).hexdigest() for name in identifiers
            },
        )
        metadata = dict(expression=expression, license_paths=list(files), classifiers=[])
        return files, path, declaration, metadata, set(identifiers)

    def evaluate(self, files, declaration, metadata, identifiers):
        expected = b"owned exact reviewed ancillary declaration"
        with mock.patch.object(
            licenses,
            "reviewed_ancillary",
            create=True,
            side_effect=lambda text: copy.deepcopy(declaration) if text.encode() == expected else None,
        ):
            return licenses._license_evidence(files, metadata, identifiers, [sorted(identifiers)[0]])

    def test_exact_ancillary_retains_bytes_without_full_term_identifier_credit(self):
        for expression, kind in [
            ("MIT", "attribution"),
            ("Apache-2.0", "attribution"),
            ("Apache-2.0 OR BSD-3-Clause", "license-declaration"),
        ]:
            files, path, declaration, metadata, identifiers = self.fixture(expression, kind)
            try:
                terms, notices = self.evaluate(files, declaration, metadata, identifiers)
            except ArtifactError as error:
                self.fail("exact ancillary plus independent complete terms refused: " + error.code)
            self.assertNotIn(path, {item["path"] for item in terms})
            self.assertEqual({item["recognized_license"] for item in terms}, identifiers)
            self.assertEqual([item["path"] for item in notices], [path])
            self.assertNotIn("recognized_license", notices[0])

    def test_missing_altered_name_only_or_wrong_expression_cannot_borrow_ancillary_terms(self):
        files, path, declaration, metadata, identifiers = self.fixture(
            "Apache-2.0 OR BSD-3-Clause", "license-declaration"
        )
        reference = "owned.dist-info/licenses/LICENSE.BSD"
        for variant in ("missing", "altered", "name-only", "ancillary-changed", "wrong-expression"):
            with self.subTest(variant=variant):
                changed = dict(files)
                altered = copy.deepcopy(metadata)
                if variant == "missing":
                    changed.pop(reference)
                if variant == "altered":
                    changed[reference] += b"\nRedistribution forbidden.\n"
                if variant == "name-only":
                    changed[reference] = b"BSD-3-Clause\n"
                if variant == "ancillary-changed":
                    changed[path] += b"\nRedistribution forbidden.\n"
                if variant == "wrong-expression":
                    altered["expression"] = "BSD-3-Clause OR Apache-2.0"
                with self.assertRaises(ArtifactError):
                    self.evaluate(changed, declaration, altered, identifiers)

    def test_reference_hash_and_safe_sibling_paths_are_required_even_with_complete_terms(self):
        files, path, declaration, metadata, identifiers = self.fixture()
        for reference in ("../LICENSE", "/LICENSE", "sub/../../LICENSE", "LICENSE"):
            with self.subTest(reference=reference):
                changed = copy.deepcopy(declaration)
                changed["required_files"] = {reference: "0" * 64}
                with self.assertRaises(ArtifactError):
                    self.evaluate(files, changed, metadata, identifiers)

    def test_full_reference_must_be_independently_recognized(self):
        files, path, declaration, metadata, identifiers = self.fixture()
        with mock.patch.object(licenses, "recognized_license", return_value=None), self.assertRaises(ArtifactError):
            self.evaluate(files, declaration, metadata, identifiers)
