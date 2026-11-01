from __future__ import annotations

import copy
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tests.json_schema_subset import SubsetValidator

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/media-design"


def load_example():
    path = EXAMPLE / "dry_run.py"
    if not path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("media_design_example", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MediaDesignTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.media = load_example()

    def setUp(self):
        self.assertIsNotNone(self.media, "bounded media design example is not implemented")

    def inputs(self, case="promo"):
        return self.media.load_case(case)

    def plan(self, case="promo"):
        return self.media.compile_plan(self.inputs(case))

    def rehash_graph(self, plan):
        for node in plan["graph"]["nodes"]:
            node["planning_key"] = self.media.node_key(plan["input_digest"], node)
        plan["graph"]["digest"] = self.media.graph_digest(plan["graph"])

    def test_both_complete_cases_use_supported_schema_and_exact_frames(self):
        schema = self.media.load_schema()
        independent = SubsetValidator(schema)
        for case, count, frames in (("promo", 9, 2760), ("webinar", 50, 81900)):
            with self.subTest(case=case):
                plan = self.plan(case)
                self.media.validate_plan(plan)
                independent.validate(plan)
                segments = plan["inputs"]["segments"]
                self.assertEqual(len(segments), count)
                self.assertEqual(segments[-1]["out_frame"], frames)
                self.assertEqual(sum(s["out_frame"] - s["in_frame"] for s in segments), frames)
                self.assertEqual(plan["inputs"]["fps"], {"numerator": 30, "denominator": 1})
                self.assertTrue(all(n["state"] == "planned_not_run" and n["output_digest"] is None
                                    for n in plan["graph"]["nodes"]))

    def test_deterministic_bytes_and_conservative_input_identity(self):
        original = self.inputs()
        before = copy.deepcopy(original)
        first = self.media.compile_plan(original)
        self.assertEqual(self.media.canonical(first), self.media.canonical(self.media.compile_plan(original)))
        self.assertEqual(original, before)
        changed = copy.deepcopy(original)
        changed["source"]["revision"] += 1
        revised = self.media.compile_plan(changed)
        self.assertNotEqual(first["input_digest"], revised["input_digest"])
        self.assertTrue(all(a["planning_key"] != b["planning_key"]
                            for a, b in zip(first["graph"]["nodes"], revised["graph"]["nodes"])))
        self.assertNotEqual(first["graph"]["digest"], revised["graph"]["digest"])
        self.assertTrue(self.media.canonical({"z": 1, "a": "\u00e9"}).endswith(b"\n"))
        self.assertIn(b"\\u00e9", self.media.canonical({"a": "\u00e9"}))

    def test_distinct_input_node_graph_hash_domains(self):
        value = {"same": "payload"}
        digests = {self.media.digest(domain, value) for domain in
                   ("media-input.v1", "media-node.v1", "media-graph.v1")}
        self.assertEqual(len(digests), 3)

    def test_closed_scalar_contract_and_non_execution_constants(self):
        mutations = [
            (("execution", "enabled"), True), (("execution", "enabled"), 0),
            (("execution", "network"), True), (("execution", "paid_calls"), True),
            (("execution", "paid_calls"), 1), (("execution", "cap_micro_usd"), 1),
            (("execution", "provider"), "vendor"), (("execution", "model"), "model"),
            (("fps", "numerator"), 30.0), (("fps", "denominator"), 0),
            (("source", "revision"), True), (("unknown",), "unrecognized"),
        ]
        schema = self.media.load_schema()
        independent = SubsetValidator(schema["$defs"]["inputs"])
        for keys, value in mutations:
            with self.subTest(keys=keys, value=value):
                invalid = self.inputs()
                target = invalid
                for key in keys[:-1]:
                    target = target[key]
                target[keys[-1]] = value
                with self.assertRaises(ValueError):
                    self.media.compile_plan(invalid)
                with self.assertRaises(ValueError):
                    independent.validate(invalid)

    def test_approval_assets_and_outputs_cannot_be_fabricated(self):
        for section, key, value in (("gates", "status", "approved"),
                                    ("gates", "approval_digest", "a" * 64),
                                    ("assets", "binary_digest", "b" * 64),
                                    ("profiles", "output_digest", "c" * 64)):
            with self.subTest(section=section, key=key):
                invalid = self.inputs()
                invalid[section][0][key] = value
                with self.assertRaises(ValueError):
                    self.media.compile_plan(invalid)
        plan = self.plan()
        plan["graph"]["nodes"][0]["state"] = "succeeded"
        with self.assertRaises(ValueError):
            self.media.validate_plan(plan)

    def test_rejects_duplicate_unknown_and_unsorted_references(self):
        changes = [
            lambda x: x["segments"][1].update(id=x["segments"][0]["id"]),
            lambda x: x["assets"][1].update(id=x["assets"][0]["id"]),
            lambda x: x["segments"][0].update(asset_ids=["missing"]),
            lambda x: x["segments"][0].update(asset_ids=["asset-002", "asset-001"]),
            lambda x: x["gates"].pop(),
            lambda x: x["gates"][0].update(owner_role="wrong_owner"),
        ]
        for mutate in changes:
            with self.subTest(mutate=mutate):
                invalid = self.inputs()
                mutate(invalid)
                invalid["source"]["content_digest"] = self.media.source_digest(invalid)
                with self.assertRaisesRegex(ValueError, "identity|reference|order|gate"):
                    self.media.compile_plan(invalid)

    def test_timeline_gaps_overlaps_ordinals_and_transition_handles(self):
        for key, value in (("in_frame", 1), ("in_frame", -1), ("out_frame", 0),
                           ("ordinal", 2), ("transition_frames", 999)):
            with self.subTest(key=key):
                invalid = self.inputs()
                invalid["segments"][0][key] = value
                invalid["source"]["content_digest"] = self.media.source_digest(invalid)
                with self.assertRaises(ValueError):
                    self.media.compile_plan(invalid)
        invalid = self.inputs()
        invalid["segments"][1]["in_frame"] -= 1
        invalid["source"]["content_digest"] = self.media.source_digest(invalid)
        with self.assertRaisesRegex(ValueError, "timeline"):
            self.media.compile_plan(invalid)

    def test_profile_dimensions_audio_subtitles_duration_and_edit_lists(self):
        mutations = [
            (0, "width", 1080), (0, "duration_frames", 2759),
            (1, "audio", "aac_stereo"), (1, "subtitles", "sidecar"),
            (2, "count", 0), (2, "duration_frames", 90000),
            (2, "edit_list", ["unapproved-cut"]),
        ]
        for index, key, value in mutations:
            with self.subTest(index=index, key=key):
                invalid = self.inputs()
                invalid["profiles"][index][key] = value
                with self.assertRaises(ValueError):
                    self.media.compile_plan(invalid)

    def test_required_gate_edges_rejected_after_all_hashes_are_recomputed(self):
        for gate in ("scope", "rights", "paid_action", "identity_brand",
                     "storyboard_timing", "final", "publication"):
            with self.subTest(gate=gate):
                plan = self.plan()
                gate_id = "gate." + gate
                target = next(n for n in plan["graph"]["nodes"] if gate_id in n["depends_on"])
                target["depends_on"].remove(gate_id)
                plan["graph"]["edges"] = [e for e in plan["graph"]["edges"]
                                         if not (e["from"] == gate_id and e["to"] == target["id"])]
                plan["graph"]["order"] = self.media.topological(plan["graph"]["nodes"])
                self.rehash_graph(plan)
                with self.assertRaisesRegex(ValueError, "graph semantics"):
                    self.media.validate_plan(plan)

    def test_required_gate_ancestors_are_present(self):
        plan = self.plan()
        by_id = {n["id"]: n for n in plan["graph"]["nodes"]}
        def ancestors(identifier):
            result = set()
            pending = list(by_id[identifier]["depends_on"])
            while pending:
                current = pending.pop()
                if current not in result:
                    result.add(current)
                    pending.extend(by_id[current]["depends_on"])
            return result
        self.assertTrue({"gate.scope", "gate.rights", "gate.paid_action"} <= ancestors("asset.asset-001"))
        self.assertTrue({"gate.identity_brand", "gate.storyboard_timing"} <= ancestors("assembly"))
        self.assertTrue({"gate.final", "gate.publication"} <= ancestors("publication"))

    def test_wrong_node_kind_or_input_reference_rejected_after_rehash(self):
        for key, value in (("kind", "qa"), ("input_refs", ["assets:missing"])):
            with self.subTest(key=key):
                plan = self.plan()
                node = next(n for n in plan["graph"]["nodes"] if n["kind"] == "asset")
                node[key] = value
                self.rehash_graph(plan)
                with self.assertRaisesRegex(ValueError, "graph semantics"):
                    self.media.validate_plan(plan)

    def test_graph_cycles_missing_nodes_duplicates_edges_and_bad_digest(self):
        for mode in ("cycle", "missing", "duplicate", "edge", "digest"):
            with self.subTest(mode=mode):
                plan = self.plan()
                nodes = plan["graph"]["nodes"]
                if mode == "cycle":
                    nodes[0]["depends_on"] = [nodes[0]["id"]]
                elif mode == "missing":
                    nodes[-1]["depends_on"].append("missing")
                elif mode == "duplicate":
                    nodes.append(copy.deepcopy(nodes[0]))
                elif mode == "edge":
                    plan["graph"]["edges"].pop()
                else:
                    plan["graph"]["digest"] = "0" * 64
                with self.assertRaises(ValueError):
                    self.media.validate_plan(plan)

    def test_strict_json_byte_depth_unicode_duplicate_and_nonfinite_bounds(self):
        invalid = (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":1.5}',
                   b'[' * 17 + b'0' + b']' * 17, b'{"a":"e\\u0301"}',
                   b" " * (1048576 + 1), b"\xff", b'{"a":')
        for raw in invalid:
            with self.subTest(raw_prefix=raw[:25]):
                with self.assertRaises(ValueError):
                    self.media.parse_bytes(raw)
        self.assertEqual(self.media.parse_bytes(b'{"a":"[not nesting]"}'), {"a": "[not nesting]"})

    def test_fixed_limits_cannot_be_raised_and_counts_are_bounded(self):
        invalid = self.inputs()
        invalid["limits"]["nodes"] = 501
        with self.assertRaises(ValueError):
            self.media.compile_plan(invalid)
        for section, count in (("segments", 61), ("assets", 65), ("profiles", 25)):
            with self.subTest(section=section):
                invalid = self.inputs()
                invalid[section] = [copy.deepcopy(invalid[section][0]) for _ in range(count)]
                with self.assertRaises(ValueError):
                    self.media.compile_plan(invalid)

    def test_bounded_reader_rejects_non_regular_and_oversized_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ValueError):
                self.media.read_json(root)
            large = root / "large.json"
            large.write_bytes(b" " * (1048576 + 1))
            with self.assertRaisesRegex(ValueError, "size"):
                self.media.read_json(large)
            link = root / "link.json"
            try:
                link.symlink_to(large)
            except (OSError, NotImplementedError):
                return
            with self.assertRaises(ValueError):
                self.media.read_json(link)

    def test_planning_has_no_network_process_or_write_effects(self):
        active = [False]
        effects = []
        def audit(event, args):
            if not active[0]:
                return
            if event == "open":
                _, mode, flags = args
                if (isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)
                        or isinstance(mode, str) and any(c in mode for c in "wax+")):
                    effects.append(event)
                    raise AssertionError("planning attempted a write")
            if event in {"socket.connect", "socket.getaddrinfo", "subprocess.Popen", "os.system",
                         "os.mkdir", "os.remove", "os.rename"}:
                effects.append(event)
                raise AssertionError("planning attempted an effect")
        sys.addaudithook(audit)
        hashes = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in EXAMPLE.glob("*.json")}
        active[0] = True
        try:
            self.media.validate_plan(self.plan("webinar"))
            self.media.benchmark(1)
        finally:
            active[0] = False
        self.assertEqual(effects, [])
        self.assertEqual(hashes, {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in hashes})

    def test_cli_from_unrelated_directory_is_stdout_only(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, str(EXAMPLE / "dry_run.py"), "--case", "both"],
                                    cwd=directory, capture_output=True, text=True, timeout=30, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
            self.assertEqual(len(json.loads(result.stdout)["plans"]), 2)
            self.assertEqual(list(Path(directory).iterdir()), [])
            for arguments in (["--input", "foreign.json"], ["--case", "foreign"], ["--benchmark", "21"]):
                denied = subprocess.run([sys.executable, str(EXAMPLE / "dry_run.py"), *arguments],
                                        cwd=directory, capture_output=True, text=True, timeout=30, check=False)
                self.assertNotEqual(denied.returncode, 0)
                self.assertEqual(denied.stdout, "")

    def test_benchmark_is_bounded_and_outside_semantic_identity(self):
        before = self.media.canonical(self.plan())
        measured = self.media.benchmark(2)
        self.assertEqual(measured["iterations"], 2)
        self.assertEqual(len(measured["samples_ns"]), 2)
        self.assertTrue(all(type(value) is int and value > 0 for value in measured["samples_ns"]))
        self.assertEqual(measured["provider_calls"], 0)
        self.assertEqual(before, self.media.canonical(self.plan()))
        for count in (0, 21, True):
            with self.assertRaises(ValueError):
                self.media.benchmark(count)

    def test_cli_rejects_invalid_fixture_without_raw_payload_or_traceback(self):
        invalid = self.inputs()
        invalid["case"] = "SYNTHETIC_PRIVATE_SENTINEL"
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(self.media, "load_case", return_value=invalid):
            with redirect_stdout(output), redirect_stderr(errors):
                try:
                    status = self.media.main(["--case", "promo"])
                except ValueError:
                    status = None
        self.assertEqual(status, 2, "invalid fixture must become a bounded CLI refusal")
        self.assertEqual(output.getvalue(), "")
        self.assertNotIn("SYNTHETIC_PRIVATE_SENTINEL", errors.getvalue())
        self.assertNotIn("Traceback", errors.getvalue())
        self.assertIn("invalid", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
