"""Tiny OCI installation/license custody, no native job or package execution."""

import gzip
import hashlib
import io
import json
import tarfile
import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".getzilla"))

from tests import test_offline_oci_import as fixtures
from tests.test_offline_oci_import import LAYER, CONFIG, MANIFEST


from getzilla import security_image_authority as image_authority
class RequestedImageMembersTests(unittest.TestCase):
    setUp = fixtures.OfflineOCIImportTests.setUp
    blob = fixtures.OfflineOCIImportTests.blob
    api = fixtures.OfflineOCIImportTests.api

    def image(self, layers):
        descriptors, diffids = [], []
        for rows in layers:
            raw = io.BytesIO()
            with tarfile.open(fileobj=raw, mode="w") as stream:
                for name, body in rows:
                    info = tarfile.TarInfo(name)
                    if body is None:
                        info.type, info.linkname = tarfile.SYMTYPE, "other"
                        stream.addfile(info)
                    else:
                        info.size = len(body)
                        stream.addfile(info, io.BytesIO(body))
            data = raw.getvalue()
            descriptors.append(self.blob(gzip.compress(data, mtime=0), LAYER))
            diffids.append("sha256:" + hashlib.sha256(data).hexdigest())
        config = self.blob(dict(os="linux", architecture="amd64", rootfs=dict(type="layers", diff_ids=diffids)), CONFIG)
        manifest = self.blob(dict(schemaVersion=2, mediaType=MANIFEST, config=config, layers=descriptors), MANIFEST)
        (self.layout / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
        (self.layout / "index.json").write_text(json.dumps(dict(schemaVersion=2, manifests=[manifest])))
        ref = "example.invalid/owned@" + manifest["digest"]
        self.profile["images"] = [ref]
        inventory = dict(digest="d" * 64, complete=True, gaps=[], images=[dict(reference=ref, platform="linux/amd64")])
        catalog = dict(
            schema_version=1,
            inventory_sha256="d" * 64,
            records=[dict(reference=ref, platform="linux/amd64", layout=str(self.layout))],
        )
        return inventory, catalog

    def reader(self, api):
        self.assertTrue(callable(getattr(api, "read_members", None)), "missing bounded requested-member custody reader")
        return api.read_members

    def test_reads_actual_final_regular_members_and_expires_with_import(self):
        a = self.api()
        read = self.reader(a)
        inv, cat = self.image(
            [
                [("site/pkg.dist-info/WHEEL", b"Tag: py3-none-any\n"), ("site/pkg.dist-info/LICENSE", b"old")],
                [("site/pkg.dist-info/LICENSE", b"new")],
            ]
        )
        with a.import_layouts(cat, inv, self.profile, self.stage) as images:
            image = images[0]
            self.assertEqual(
                read(image, ["site/pkg.dist-info/WHEEL", "site/pkg.dist-info/LICENSE"]),
                {"site/pkg.dist-info/WHEEL": b"Tag: py3-none-any\n", "site/pkg.dist-info/LICENSE": b"new"},
            )
        with self.assertRaises(ValueError):
            read(image, ["site/pkg.dist-info/WHEEL"])

    def test_whiteout_and_opaque_directory_remove_lower_license(self):
        for removal in ("site/pkg.dist-info/.wh.LICENSE", "site/pkg.dist-info/.wh..wh..opq"):
            with self.subTest(removal=removal):
                a = self.api()
                read = self.reader(a)
                inv, cat = self.image([[("site/pkg.dist-info/LICENSE", b"license")], [(removal, b"")]])
                with a.import_layouts(cat, inv, self.profile, self.stage) as images:
                    with self.assertRaisesRegex(ValueError, "missing"):
                        read(images[0], ["site/pkg.dist-info/LICENSE"])

    def test_same_layer_new_file_survives_opaque_whiteout(self):
        a = self.api()
        read = self.reader(a)
        inv, cat = self.image([[("site/LICENSE", b"old")], [("site/LICENSE", b"new"), ("site/.wh..wh..opq", b"")]])
        with a.import_layouts(cat, inv, self.profile, self.stage) as images:
            self.assertEqual(read(images[0], ["site/LICENSE"]), {"site/LICENSE": b"new"})

    def test_selected_links_ancestors_duplicate_members_and_bounds_refuse(self):
        for rows in [
            [("site/LICENSE", None)],
            [("site", None), ("site/LICENSE", b"data")],
            [("site/LICENSE", b"one"), ("site/LICENSE", b"two")],
        ]:
            with self.subTest(rows=rows):
                a = self.api()
                read = self.reader(a)
                inv, cat = self.image([rows])
                with a.import_layouts(cat, inv, self.profile, self.stage) as images:
                    with self.assertRaises(ValueError):
                        read(images[0], ["site/LICENSE"])
        a = self.api()
        read = self.reader(a)
        inv, cat = self.image([[("site/LICENSE", b"x" * 8)]])
        with a.import_layouts(cat, inv, self.profile, self.stage) as images:
            for paths, limit in [(["../LICENSE"], 8), (["site/LICENSE"], 7), (["site/LICENSE"] * 2, 8)]:
                with self.assertRaises(ValueError):
                    read(images[0], paths, member_limit=limit)

    def test_replaced_blob_and_foreign_claim_cannot_supply_custody(self):
        a = self.api()
        read = self.reader(a)
        inv, cat = self.image([[("site/LICENSE", b"license")]])
        with a.import_layouts(cat, inv, self.profile, self.stage) as images:
            image = images[0]
            manifest = json.loads((image.layout / "blobs/sha256" / image.manifest_digest[7:]).read_text())
            path = image.layout / "blobs/sha256" / manifest["layers"][0]["digest"][7:]
            path.write_bytes(b"x" * path.stat().st_size)
            with self.assertRaises(ValueError):
                read(image, ["site/LICENSE"])
        with self.assertRaises(ValueError):
            read(dict(reference="claim"), ["site/LICENSE"])


class CIInstallRecipeTests(unittest.TestCase):
    def setUp(self):
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))

    def test_four_real_recipes_expose_exact_complete_install_file_hashes(self):
        from pathlib import Path
        from getzilla import security_python_target as target
        root = Path(__file__).resolve().parents[1]
        operation = getattr(target, 'ci_install_context', None)
        self.assertTrue(callable(operation), 'missing closed actual install-context adapter')
        for recipe in ('trust-ci/Dockerfile.api', 'trust-ci/Dockerfile.worker',
                       'trust-ci/Dockerfile.test', 'trust-ci/runner.Dockerfile'):
            actual = operation(root, recipe)
            self.assertIsNotNone(actual, recipe)
            profile = 'runner' if 'runner' in recipe else 'test' if 'test' in recipe else 'runtime'
            primary = 'trust-ci/requirements-' + profile + '.txt'
            self.assertEqual({primary}, set(actual['install_requirements']))
            self.assertEqual(primary, actual['requirements'])
            self.assertIn('trust-ci/uv.lock', actual['source_inputs'])
            self.assertIn('trust-ci/lock-profiles.json', actual['source_inputs'])
            for path, digest in actual['install_requirements'].items():
                self.assertEqual(hashlib.sha256((root / path).read_bytes()).hexdigest(), digest)
            self.assertEqual('runner' in recipe, 'trust-ci/requirements-runner.txt' in actual['install_requirements'])
        self.assertIsNone(operation(root, 'arbitrary/Dockerfile'))


    def test_raw_inventory_declares_runner_versions_and_hash_locked_backend(self):
        from pathlib import Path
        from getzilla.security_inventory import collect_inventory, _logical_requirements
        from getzilla import security_python_target as target
        root = Path(__file__).resolve().parents[1]
        inventory = collect_inventory(root)
        runner = {row['name']: row['version'] for row in inventory['dependencies']
                  if row['manifest'] == 'trust-ci/requirements-runner.txt'}
        self.assertEqual(len(runner), 47)
        for name, version in {'coverage':'7.15.4', 'pytest':'9.1.1', 'pytest-xdist':'3.8.0',
                              'pytest-cov':'7.1.0', 'ruff':'0.16.3', 'bandit':'1.9.4', 'tomli':'2.5.0'}.items():
            self.assertEqual(version, runner[name])
        backend = [row for row in inventory['dependencies'] if row['manifest'] == 'trust-ci/requirements-build.txt']
        self.assertEqual([(row['name'], row['version']) for row in backend], [('setuptools', '84.1.0')])
        for path in ('trust-ci/requirements-build.txt', 'trust-ci/requirements-runner.txt'):
            for line in _logical_requirements((root / path).read_text()):
                self.assertRegex(line, r'^[A-Za-z0-9_.-]+(?:\[toml\])?==[^ ;]+(?: ; [^#]+)? --hash=sha256:[a-f0-9]{64}')
        graphs = target.closure_graphs(root, inventory)
        self.assertEqual(graphs['graphs']['trust-ci/pyproject.toml#runtime'], graphs['graphs']['trust-ci/pyproject.toml#build'])
        runner_graph = ['trust-ci/requirements-runner.txt']
        self.assertIn(runner_graph, graphs['graphs']['trust-ci/pyproject.toml#runtime'])
        self.assertIn(runner_graph, graphs['graphs']['trust-ci/pyproject.toml#optional'])

    def test_changed_recipe_cannot_claim_trusted_install_join(self):
        from pathlib import Path
        import tempfile
        from getzilla import security_python_target as target
        source = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('Dockerfile.api', 'pyproject.toml', 'README.md', 'uv.lock', 'lock_profiles.py', 'lock_profile_validation.py',
                         'lock-profiles.json', 'requirements-runtime.txt', 'requirements-test.txt', 'requirements-runner.txt'):
                path = root / 'trust-ci' / name
                path.parent.mkdir(exist_ok=True)
                path.write_bytes((source / 'trust-ci' / name).read_bytes())
            recipe = 'trust-ci/Dockerfile.api'
            self.assertIsNotNone(target.ci_install_context(root, recipe))
            path = root / recipe
            path.write_text(path.read_text().replace('--no-build-isolation', '--build-isolation'))
            self.assertIsNone(target.ci_install_context(root, recipe))


class CIImageTargetBindingTests(unittest.TestCase):
    def setUp(self):
        import sys
        from pathlib import Path

        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".getzilla"))
        from unittest.mock import patch
        from getzilla import security_python_target as target

        self.target = target
        self.source = dict(
            head_sha="a" * 40,
            tree_sha="b" * 40,
            checker_sha="c" * 40,
            checker_tree_sha="d" * 40,
            candidate_clean=True,
            checker_clean=True,
            same_project=True,
        )
        self.run = dict(
            provider="github-actions", repository="Fixture/Repo", run_id="1", run_attempt="1", head_sha="a" * 40
        )
        self.dep = dict(
            ecosystem="PyPI",
            name="owned",
            version="1.0",
            manifest="trust-ci/requirements.txt",
            usage="runtime-and-development",
            extras=[],
        )
        subject = target.digest(target._subject(self.dep))
        image_target = target.observe_target()
        image_target.update(
            python_version="3.12.3",
            abi="cpython-312-x86_64-linux-gnu",
            tags_sha256=target.digest(["cp312-cp312-manylinux_2_17_x86_64"]),
            tag_count=1,
        )
        image_target["marker_environment"].update(python_version="3.12", python_full_version="3.12.3")
        consumer = dict(
            recipe="trust-ci/Dockerfile.api",
            recipe_sha256="e" * 64,
            build_sha256="f" * 64,
            image="getzilla.local/build@sha256:" + "1" * 64,
            requirements="trust-ci/requirements.txt",
            requirements_sha256="2" * 64,
            install_requirements={"trust-ci/requirements.txt": "2" * 64},
            distribution="internal",
            purpose="isolated-public-ci",
            image_target_observed=True,
            base="python@sha256:" + "3" * 64,
            target=image_target,
            supported_tags=["cp312-cp312-manylinux_2_17_x86_64"],
            site_packages=["usr/local/lib/python3.12/site-packages"],
            dependencies=[self.dep],
            source_pins={
                subject: dict(
                    context_sha256=target._context_key(self.dep),
                    manifest_sha256="2" * 64,
                    hashes=["4" * 64],
                    files=[],
                    marker_active=True,
                )
            },
        )
        self.uses = dict(
            schema_version=1,
            source=self.source,
            run=self.run,
            inventory_sha256="5" * 64,
            closure_graphs_sha256="6" * 64,
            subjects={subject: [0]},
            consumers=[consumer],
        )
        self.guard = ("owned-test-namespace", "nonce", [], {})
        self.live = dict(source=self.source, run=self.run, native_guard=self.guard, ci_uses=self.uses)
        self.patch_native = patch.object(image_authority, "_GUARD", self.guard)
        self.patch_native.start()
        self.addCleanup(self.patch_native.stop)
        self.patch_live = patch.object(image_authority, "_LIVE", self.live)
        self.patch_live.start()
        self.addCleanup(self.patch_live.stop)
        self.parent = dict(
            source=self.source,
            run=self.run,
            profile_sha256="7" * 64,
            inventory_sha256="5" * 64,
            target=target.observe_target(),
            ci_uses=self.uses,
        )

    def inputs(self):
        import importlib.util

        self.assertIsNotNone(
            importlib.util.find_spec("getzilla.security_ci_inputs"), "missing separate live image installation scope"
        )
        from getzilla import security_ci_inputs

        return security_ci_inputs

    def backend_context(self):
        consumer = self.uses['consumers'][0]
        backend = dict(self.dep, name='setuptools', version='84.1.0',
                       manifest='trust-ci/requirements-build.txt')
        project = dict(backend, manifest='trust-ci/pyproject.toml', usage='build')
        consumer['dependencies'].extend([backend, project])
        consumer['install_requirements']['trust-ci/requirements-build.txt'] = '8' * 64
        for dep, manifest_hash, hashes in ((backend, '8' * 64, ['9' * 64]), (project, 'a' * 64, [])):
            consumer['source_pins'][self.target.digest(self.target._subject(dep))] = dict(
                context_sha256=self.target._context_key(dep), manifest_sha256=manifest_hash,
                hashes=hashes, files=[], marker_active=True)
        return project, self.inputs().scope(self.parent, 0)

    def test_backend_project_use_requires_exact_actual_hashed_install_file(self):
        import copy
        project, (inventory, binding) = self.backend_context()
        self.assertEqual(len(inventory['dependencies']), 3)
        selected = binding['source_pins'][self.target.digest(self.target._subject(project))]
        self.assertEqual(['9' * 64], selected['hashes'])
        self.assertIn('trust-ci/requirements-build.txt', binding['ci_uses']['consumers'][0]['install_requirements'])
        consumer = self.uses['consumers'][0]
        original = copy.deepcopy(consumer)
        for failure in ('missing-backend-lock', 'hash-mismatch', 'wrong-version'):
            consumer.clear()
            consumer.update(copy.deepcopy(original))
            if failure == 'missing-backend-lock':
                consumer['install_requirements'].pop('trust-ci/requirements-build.txt')
            elif failure == 'hash-mismatch':
                consumer['install_requirements']['trust-ci/requirements-build.txt'] = 'f' * 64
            else:
                consumer['dependencies'][1]['version'] = '84.1.1'
            with self.subTest(failure=failure), self.assertRaises(ValueError):
                self.inputs().scope(self.parent, 0)

    def test_ci_evaluation_seal_rejects_json_copy_changes_and_wrong_entry(self):
        import copy
        api = self.inputs()
        _project, (inventory, binding) = self.backend_context()
        output = dict(status='pass', gaps=[], inventory_digest=inventory['digest'],
                      policy_digest='b' * 64, details=[])
        with self.assertRaises(ValueError):
            api.seal_evaluation(binding, output)
        api.seal_evaluation(binding, output, _entry=api._EVALUATION_ENTRY)
        self.assertEqual(api.validated_evaluation(binding, output), self.uses['consumers'][0])
        with self.assertRaises(ValueError):
            api.validated_evaluation(binding, copy.deepcopy(output))
        output['details'].append({'changed': True})
        with self.assertRaises(ValueError):
            api.validated_evaluation(binding, output)

    def test_image_scope_selects_its_actual_cp312_wheel_without_host_substitution(self):
        api = self.inputs()
        inventory, binding = api.scope(self.parent, 0)
        self.assertEqual(inventory["dependencies"][0]["distribution"], "internal")
        self.assertEqual(binding["target"]["python_version"], "3.12.3")
        self.assertEqual(self.parent["target"], self.target.observe_target())
        filename = "owned-1.0-cp312-cp312-manylinux_2_17_x86_64.whl"
        index = dict(
            urls=[
                dict(
                    packagetype="bdist_wheel",
                    yanked=False,
                    requires_python=">=3.12",
                    filename=filename,
                    digests=dict(sha256="4" * 64),
                    url="https://files.pythonhosted.org/packages/owned.whl",
                )
            ]
        )
        from unittest.mock import patch

        with patch.object(self.target, "_facts", side_effect=AssertionError("host target must not be read")):
            selected = self.target.select_dependency(index, inventory["dependencies"][0], binding)
        self.assertEqual(selected["artifact_filename"], filename)

    def test_image_binding_rejects_target_pin_image_and_guard_tamper(self):
        import copy

        api = self.inputs()
        inventory, binding = api.scope(self.parent, 0)
        for field in ("target", "source_pins"):
            altered = copy.deepcopy(binding)
            if field == "target":
                altered[field]["python_version"] = "3.13.1"
            else:
                next(iter(altered[field].values()))["hashes"] = ["8" * 64]
            with self.assertRaises(ValueError):
                self.target._binding(altered)
        image_authority._GUARD = None
        with self.assertRaises(ValueError):
            api.scope(self.parent, 0)
        image_authority._GUARD = self.guard
        altered = copy.deepcopy(self.parent)
        altered["ci_uses"]["consumers"][0]["image"] = "other@sha256:" + "8" * 64
        with self.assertRaises(ValueError):
            api.scope(altered, 0)

    def test_unknown_target_and_inactive_markers_never_receive_image_credit(self):
        api = self.inputs()
        self.uses["consumers"][0]["image_target_observed"] = False
        with self.assertRaises(ValueError):
            api.scope(self.parent, 0)
        self.uses["consumers"][0]["image_target_observed"] = True
        next(iter(self.uses["consumers"][0]["source_pins"].values()))["marker_active"] = False
        with self.assertRaises(ValueError):
            api.scope(self.parent, 0)

    def test_observer_payload_is_closed_nonce_tag_and_site_data(self):
        import copy

        api = self.inputs()
        self.assertTrue(
            callable(getattr(api, "base_observation", None)), "missing closed immutable-base observation parser"
        )
        consumer = self.uses["consumers"][0]
        raw = dict(
            nonce="a" * 32,
            target=consumer["target"],
            supported_tags=consumer["supported_tags"],
            site_packages=consumer["site_packages"],
        )
        observed = api.base_observation(raw, "a" * 32)
        self.assertEqual(observed["target"], consumer["target"])
        for value in [
            dict(raw, nonce="b" * 32),
            dict(raw, claim=True),
            dict(raw, site_packages=["../site"]),
            dict(raw, supported_tags=["cp313-cp313-manylinux_2_17_x86_64"]),
        ]:
            with self.assertRaises(ValueError):
                api.base_observation(value, "a" * 32)
        altered = copy.deepcopy(raw)
        altered["target"]["tag_count"] = 2
        with self.assertRaises(ValueError):
            api.base_observation(altered, "a" * 32)

    def test_final_custody_requires_exact_wheel_license_and_live_image(self):
        from unittest.mock import patch

        api = self.inputs()
        inventory, binding = api.scope(self.parent, 0)
        files = {
            "owned-1.0.dist-info/WHEEL": b"Tag: cp312-cp312-manylinux_2_17_x86_64\n",
            "owned-1.0.dist-info/licenses/LICENSE": b"license bytes",
        }
        prefix = "usr/local/lib/python3.12/site-packages/"
        actual = {prefix + k: v for k, v in files.items()}
        with patch("getzilla.security_image_authority.ci_member_evidence", return_value=actual):
            proof = api.verify_custody(
                binding, inventory["dependencies"][0], files, ["owned-1.0.dist-info/licenses/LICENSE"]
            )
        self.assertEqual(len(proof["members"]), 2)
        for altered in [dict(actual, **{prefix + "owned-1.0.dist-info/licenses/LICENSE": b"altered"}), {}]:
            with patch("getzilla.security_image_authority.ci_member_evidence", return_value=altered):
                with self.assertRaises(ValueError):
                    api.verify_custody(
                        binding, inventory["dependencies"][0], files, ["owned-1.0.dist-info/licenses/LICENSE"]
                    )

    def test_actual_image_scope_acquisition_is_separate_bounded_and_reobserved(self):
        import tempfile
        import zipfile
        from pathlib import Path

        api = self.inputs()
        self.assertTrue(callable(getattr(api, "prepare", None)), "missing separate CI artifact producer")
        wheel = io.BytesIO()
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr(
                "owned-1.0.dist-info/WHEEL",
                "Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: cp312-cp312-manylinux_2_17_x86_64\n",
            )
            archive.writestr(
                "owned-1.0.dist-info/METADATA",
                "Metadata-Version: 2.4\nName: owned\nVersion: 1.0\nLicense-Expression: MIT\n",
            )
        payload = wheel.getvalue()
        sha = hashlib.sha256(payload).hexdigest()
        next(iter(self.uses["consumers"][0]["source_pins"].values()))["hashes"] = [sha]
        filename = "owned-1.0-cp312-cp312-manylinux_2_17_x86_64.whl"
        url = "https://files.pythonhosted.org/packages/owned/" + filename
        index = json.dumps(
            dict(
                info=dict(name="owned", version="1.0"),
                urls=[
                    dict(
                        filename=filename,
                        url=url,
                        packagetype="bdist_wheel",
                        yanked=False,
                        digests=dict(sha256=sha),
                        requires_python=">=3.12",
                    )
                ],
            )
        ).encode()
        calls = []

        def fetch(wanted, maximum):
            calls.append(wanted)
            return payload if wanted == url else index

        from unittest.mock import patch

        wheel_body = b"Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: cp312-cp312-manylinux_2_17_x86_64\n"
        actual = {"usr/local/lib/python3.12/site-packages/owned-1.0.dist-info/WHEEL": wheel_body}
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch("getzilla.security_image_authority.ci_member_evidence", return_value=actual),
        ):
            root = Path(temporary)
            (root / "manifest.json").write_text(json.dumps(dict(records=[])))
            observed = api.prepare(root, self.parent, fetch=fetch)
            self.assertEqual(len(observed), 1)
            self.assertEqual(observed[0]["inventory"]["dependencies"][0]["delivery_kind"], "installed-package")
            self.assertFalse((root / "objects" / sha).exists())
            self.assertTrue((observed[0]["root"] / "objects" / sha).is_file())
            self.assertEqual(len(calls), 2)
            with self.assertRaises(ValueError):
                api.prepare(root, self.parent, fetch=fetch, byte_budget=1)

    def test_closed_base_observer_uses_owned_completion_and_actual_oci_output(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        from getzilla import security_image_backend as native, security_oci as oci

        api = self.inputs()
        self.assertTrue(callable(getattr(api, "observe_base", None)))
        fixture = RequestedImageMembersTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        nonce = "9" * 32
        consumer = self.uses["consumers"][0]
        body = json.dumps(
            dict(
                nonce=nonce,
                target=consumer["target"],
                supported_tags=consumer["supported_tags"],
                site_packages=consumer["site_packages"],
            )
        ).encode()
        fixture.image([[("getzilla-observer-" + nonce + ".json", body)]])
        builder = object.__new__(native.BuildKit)
        builder.guard = self.guard
        calls = []

        def build(recipe, context, output, **kwargs):
            text = (context / "Dockerfile").read_text()
            calls.append((recipe, text, kwargs))
            self.assertIn("FROM python@sha256:" + "3" * 64, text)
            self.assertIn(nonce, text)
            self.assertNotIn("COPY src", text)
            with tarfile.open(output, "w") as stream:
                for path in sorted(fixture.layout.rglob("*")):
                    if path.is_file():
                        stream.add(path, arcname=str(path.relative_to(fixture.layout)))
            return native._ACTIVE

        budget = oci._Budget(fixture.profile)
        with (
            patch.object(builder, "build", side_effect=build),
            patch("uuid.uuid4", return_value=SimpleNamespace(hex=nonce)),
        ):
            observed = api.observe_base(builder, consumer["base"], fixture.root, budget)
        self.assertEqual(observed["target"], consumer["target"])
        self.assertEqual(observed["base"], consumer["base"])
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0][2]["offline_control"])
        self.assertGreater(budget.totals["unpacked"], 0)
        def foreign_completion(*args, **kwargs):
            build(*args, **kwargs)
            return object()

        with patch.object(builder, "build", side_effect=foreign_completion), patch(
            "uuid.uuid4", return_value=SimpleNamespace(hex=nonce)
        ):
            with self.assertRaises(ValueError):
                api.observe_base(builder, consumer["base"], fixture.root, budget)
        with self.assertRaises(ValueError):
            api.observe_base(object(), consumer["base"], fixture.root, budget)

    def test_current_source_consumer_joins_live_base_target_and_pins(self):
        import tempfile
        import shutil
        from unittest.mock import patch
        from getzilla import security_image_producer as producer
        from getzilla.security_inventory import collect_inventory

        consumer = self.uses["consumers"][0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            recipe = "trust-ci/Dockerfile.api"
            requirements = "trust-ci/requirements-runtime.txt"
            (root / "trust-ci").mkdir()
            source = Path(__file__).resolve().parents[1]
            for name in ('Dockerfile.api', 'pyproject.toml', 'README.md', 'uv.lock', 'lock_profiles.py', 'lock_profile_validation.py',
                         'lock-profiles.json', 'requirements-runtime.txt', 'requirements-test.txt', 'requirements-runner.txt'):
                shutil.copyfile(source / 'trust-ci' / name, root / 'trust-ci' / name)
            inventory = collect_inventory(root)
            row = dict(dockerfile=recipe, recipe_sha256=hashlib.sha256((root / recipe).read_bytes()).hexdigest(),
                build_sha256=consumer["build_sha256"], manifest="trust-ci/compose.build.yaml",
                line=1, source_reference="${IMAGE}")
            inventory.update(builds=[row], images=[dict(manifest=row["manifest"], line=1,
                source_reference="${IMAGE}", reference=consumer["image"])])
            graphs = self.target.closure_graphs(root, inventory)
            self.live.update(build_inputs=[row], builds={row["build_sha256"]: consumer["image"]},
                base_targets={row["recipe_sha256"]: {key: consumer[key] for key in
                    ("base", "target", "supported_tags", "site_packages")}})
            with patch("getzilla.security_cli.validate_selection_authority"):
                observed = producer.ci_use_observations(root, inventory, self.source, self.run, graphs)
            actual = observed["consumers"][0]
            self.assertTrue(actual["image_target_observed"])
            self.assertEqual(actual["requirements"], requirements)
            self.assertEqual(set(actual["install_requirements"]), {requirements})
            expected = [dep for dep in inventory['dependencies'] if dep['manifest']==requirements
                or dep['manifest']=='trust-ci/pyproject.toml' and dep['usage'] in {'runtime','build'}]
            self.assertEqual(actual['dependencies'], expected)
            self.assertTrue(any(dep['name']=='setuptools' and dep['manifest']==requirements
                for dep in actual['dependencies']))
            self.assertTrue(any(dep['name']=='setuptools' and dep['usage']=='build'
                and dep['manifest']=='trust-ci/pyproject.toml' for dep in actual['dependencies']))
            parent = dict(self.parent, ci_uses=observed, inventory_sha256=inventory['digest'])
            derived, binding = self.inputs().scope(parent, 0)
            self.assertIn('cryptography', {dep['name'] for dep in derived['dependencies']})
            self.assertIn('setuptools', {dep['name'] for dep in derived['dependencies']})
            self.target._binding(binding)

    def test_project_runtime_uses_keep_actual_consumer_lock_hash_fence(self):
        api = self.inputs()
        consumer = self.uses["consumers"][0]
        project = dict(self.dep, manifest="trust-ci/pyproject.toml", usage="runtime")
        consumer["dependencies"].append(project)
        consumer["source_pins"][self.target.digest(self.target._subject(project))] = dict(
            context_sha256=self.target._context_key(project),
            manifest_sha256="a" * 64,
            hashes=[],
            files=[],
            marker_active=True,
        )
        inventory, binding = api.scope(self.parent, 0)
        derived = next(d for d in inventory["dependencies"] if d["manifest"] == project["manifest"])
        index = dict(
            urls=[
                dict(
                    filename="owned-1.0-cp312-cp312-manylinux_2_17_x86_64.whl",
                    url="https://files.pythonhosted.org/packages/unlocked.whl",
                    digests=dict(sha256="8" * 64),
                    requires_python=">=3.12",
                    packagetype="bdist_wheel",
                    yanked=False,
                )
            ]
        )
        with self.assertRaises(ValueError):
            self.target.select_dependency(index, derived, binding)

    def test_proved_ci_installation_evaluates_license_without_host_or_runtime_claim(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from tests import test_security_licenses as fixtures
        from getzilla import security_licenses as licenses, security_tools

        api = self.inputs()
        wheel_body = b"Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: cp312-cp312-manylinux_2_17_x86_64\n"
        payload = fixtures.wheel(name="owned", version="1.0", extra_files={"owned-1.0.dist-info/WHEEL": wheel_body})
        sha = hashlib.sha256(payload).hexdigest()
        next(iter(self.uses["consumers"][0]["source_pins"].values()))["hashes"] = [sha]
        filename = "owned-1.0-cp312-cp312-manylinux_2_17_x86_64.whl"
        url = "https://files.pythonhosted.org/packages/owned/" + filename
        index = json.dumps(
            dict(
                info=dict(name="owned", version="1.0"),
                urls=[
                    dict(
                        filename=filename,
                        url=url,
                        packagetype="bdist_wheel",
                        yanked=False,
                        digests=dict(sha256=sha),
                        requires_python=">=3.12",
                    )
                ],
            )
        ).encode()

        def fetch(wanted, maximum):
            return payload if wanted == url else index

        root = "usr/local/lib/python3.12/site-packages/"
        actual = {
            root + "owned-1.0.dist-info/WHEEL": wheel_body,
            root + "owned-1.0.dist-info/licenses/LICENSE": fixtures.LICENSE_TEXT.encode(),
        }
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch("getzilla.security_image_authority.ci_member_evidence", return_value=actual),
        ):
            artifacts = Path(temporary)
            (artifacts / "manifest.json").write_text(json.dumps(dict(records=[])))
            item = api.prepare(artifacts, self.parent, fetch=fetch)[0]
            policy = licenses.load_policy(security_tools.TRUSTED_ROOT)
            result = licenses.evaluate_artifacts(
                item["inventory"], item["root"], policy, target_binding=item["binding"]
            )
            self.assertEqual(result["status"], "pass", result["gaps"])
            self.assertEqual(result["details"][0]["distribution"], "internal")
            self.assertIn("no final runtime integrity", result["details"][0]["delivery"]["assurance"])
            self.assertEqual(self.parent["target"], self.target.observe_target())
            actual[root + "owned-1.0.dist-info/licenses/LICENSE"] = b"changed"
            result = licenses.evaluate_artifacts(
                item["inventory"], item["root"], policy, target_binding=item["binding"]
            )
            self.assertEqual(result["status"], "fail")
            self.assertTrue(any(g["code"] == "artifact-target-use-unobserved" for g in result["gaps"]))

    def test_live_member_facts_rehash_graph_and_never_restore_json(self):
        from unittest.mock import patch
        from getzilla import security_oci as oci, security_image_producer as producer

        fixture = RequestedImageMembersTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        paths = [
            "usr/local/lib/python3.12/site-packages/owned-1.0.dist-info/WHEEL",
            "usr/local/lib/python3.12/site-packages/owned-1.0.dist-info/licenses/LICENSE",
        ]
        inv, cat = fixture.image([[(paths[0], b"wheel"), (paths[1], b"license")]])
        with oci.import_layouts(cat, inv, fixture.profile, fixture.stage) as images:
            image = images[0]
            self.uses["consumers"][0]["image"] = image.reference
            self.live["images"] = {image.reference: image}
            with patch.object(oci, "_parse_layer", wraps=oci._parse_layer) as parse:
                actual = producer.ci_member_evidence(self.uses, self.source, self.run, 0, paths)
                self.assertEqual(actual, {paths[0]: b"wheel", paths[1]: b"license"})
                calls = parse.call_count
                producer.ci_member_evidence(self.uses, self.source, self.run, 0, [paths[1]])
                self.assertEqual(parse.call_count, calls)
                self.live["member_facts"] = {image.reference: {paths[1]: b"forged JSON"}}
                actual = producer.ci_member_evidence(self.uses, self.source, self.run, 0, [paths[1]])
                self.assertEqual(actual[paths[1]], b"license")
            manifest = json.loads((image.layout / "blobs/sha256" / image.manifest_digest[7:]).read_text())
            blob = image.layout / "blobs/sha256" / manifest["layers"][0]["digest"][7:]
            blob.write_bytes(b"x" * blob.stat().st_size)
            with self.assertRaises(ValueError):
                producer.ci_member_evidence(self.uses, self.source, self.run, 0, [paths[1]])
        with self.assertRaises(ValueError):
            producer.ci_member_evidence(self.uses, self.source, self.run, 0, [paths[1]])

    def test_ci_pass_keeps_original_production_scope_unknown(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from tests import test_security_licenses as fixtures
        from getzilla import security_licenses as licenses, security_tools
        from getzilla.security_license_acquisition import acquire_pypi

        api = self.inputs()
        native_wheel = b"Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: cp312-cp312-manylinux_2_17_x86_64\n"
        universal_wheel = b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        native = fixtures.wheel(name="owned", version="1.0", extra_files={"owned-1.0.dist-info/WHEEL": native_wheel})
        universal = fixtures.wheel(
            name="owned", version="1.0", extra_files={"owned-1.0.dist-info/WHEEL": universal_wheel}
        )
        hashes = [hashlib.sha256(p).hexdigest() for p in (native, universal)]
        subject = self.target.digest(self.target._subject(self.dep))
        self.uses["consumers"][0]["source_pins"][subject]["hashes"] = hashes
        graphs = dict(schema_version=1, inventory_sha256="5" * 64, graphs={}, evidence={})
        self.uses["closure_graphs_sha256"] = self.target.digest(graphs)
        parent = dict(self.parent, closure_graphs=graphs, source_pins=self.uses["consumers"][0]["source_pins"])

        def fetch_for(payload, filename):
            url = "https://files.pythonhosted.org/packages/owned/" + filename
            index = json.dumps(
                dict(
                    info=dict(name="owned", version="1.0"),
                    urls=[
                        dict(
                            filename=filename,
                            url=url,
                            packagetype="bdist_wheel",
                            yanked=False,
                            digests=dict(sha256=hashlib.sha256(payload).hexdigest()),
                            requires_python=">=3.9",
                        )
                    ],
                )
            ).encode()

            def fetch(wanted, maximum):
                return payload if wanted == url else index

            return fetch

        root = "usr/local/lib/python3.12/site-packages/"
        actual = {
            root + "owned-1.0.dist-info/WHEEL": native_wheel,
            root + "owned-1.0.dist-info/licenses/LICENSE": fixtures.LICENSE_TEXT.encode(),
        }
        original = dict(digest="5" * 64, complete=True, gaps=[], dependencies=[dict(self.dep)], tools=[], images=[])
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch("getzilla.security_image_authority.ci_member_evidence", return_value=actual),
        ):
            artifacts = Path(temporary)
            acquire_pypi(
                [self.dep],
                artifacts,
                inventory_digest=original["digest"],
                target_binding=parent,
                fetch=fetch_for(universal, "owned-1.0-py3-none-any.whl"),
            )
            api.prepare(artifacts, parent, fetch=fetch_for(native, "owned-1.0-cp312-cp312-manylinux_2_17_x86_64.whl"))
            policy = licenses.load_policy(security_tools.TRUSTED_ROOT)
            result = licenses.evaluate_artifacts(original, artifacts, policy, target_binding=parent)
            self.assertEqual(result["status"], "fail")
            self.assertTrue(any(g["code"] == "license-scope-unknown" for g in result["gaps"]))
            self.assertEqual(len(result["details"]), 1)
            self.assertEqual(result["details"][0]["distribution"], "internal")
            self.assertNotIn("distribution", original["dependencies"][0])
            frozen = licenses.artifact_catalog_source(original, artifacts, policy, target_binding=parent)
            self.assertGreater(frozen["payload_size"], 0)
            actual[root + "owned-1.0.dist-info/licenses/LICENSE"] = b"changed"
            with self.assertRaises(ValueError):
                licenses.artifact_catalog_source(original, artifacts, policy, target_binding=parent)
