"""Bounded, source-only synthetic media planning. This module executes no plan."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time
import unicodedata

# The example must not create bytecode beside its inputs, including in an archive.
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / ".getzilla"))
from getzilla.spec import validate_schema

LIMITS = {"bytes": 1048576, "segments": 60, "assets": 64, "families": 24,
          "nodes": 500, "edges": 4000, "depth": 16}
CASES = {"promo": (9, 2760), "webinar": (50, 81900)}
OWNERS = {"scope": "brief_owner", "rights": "rights_owner", "paid_action": "budget_owner",
          "identity_brand": "creative_owner", "storyboard_timing": "creative_owner",
          "final": "creative_owner", "publication": "publication_owner"}


def _bounded(value):
    """Bound in-memory values before recursive schema/canonical processing."""
    pending = [(value, 1)]
    seen = 0
    while pending:
        item, depth = pending.pop()
        seen += 1
        if depth > LIMITS["depth"] or seen > 40000:
            raise ValueError("structure bound exceeded")
        if isinstance(item, dict):
            if not all(isinstance(key, str) for key in item):
                raise ValueError("object key must be a string")
            pending.extend((key, depth + 1) for key in item)
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            if len(item) > 2048 or unicodedata.normalize("NFC", item) != item:
                raise ValueError("string length or NFC bound")
        elif item is not None and type(item) not in (int, bool):
            raise ValueError("only integer semantic numbers are supported")
        elif type(item) is int and abs(item) > 2**63 - 1:
            raise ValueError("integer bound exceeded")


def canonical(value):
    _bounded(value)
    return (json.dumps(value, ensure_ascii=True, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")


def digest(domain, value):
    return hashlib.sha256(domain.encode("ascii") + b"\0" + canonical(value)).hexdigest()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _nonfinite(_value):
    raise ValueError("nonfinite number")


def parse_bytes(raw):
    if not isinstance(raw, bytes) or len(raw) > LIMITS["bytes"]:
        raise ValueError("input size bound")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("input encoding") from error
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > LIMITS["depth"]:
                raise ValueError("input depth bound")
        elif char in "]}":
            depth -= 1
    try:
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_nonfinite)
    except (json.JSONDecodeError, RecursionError) as error:
        raise ValueError("invalid JSON") from error
    _bounded(value)
    return value


class ReaderUnavailable(ValueError):
    """The platform cannot admit a no-follow, nonblocking file open."""


def read_json(path):
    """Read one fixed local fixture/schema; the CLI does not accept path input."""
    path = Path(path)
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("input must be a regular non-link file")
        if before.st_size > LIMITS["bytes"]:
            raise ValueError("input size bound")
        required = (getattr(os, "O_NOFOLLOW", None), getattr(os, "O_NONBLOCK", None))
        if any(type(flag) is not int or flag <= 0 for flag in required):
            raise ReaderUnavailable("safe reader unavailable on this platform")
        # Do not wait for a FIFO writer before checking the opened descriptor.
        flags = os.O_RDONLY | required[0] | required[1] | getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise ValueError("input changed or is not regular")
            stream = os.fdopen(descriptor, "rb")
            descriptor = None  # The stream owns it only after fdopen succeeds.
            with stream:
                raw = stream.read(LIMITS["bytes"] + 1)
                after = os.fstat(stream.fileno())
        finally:
            if descriptor is not None:
                os.close(descriptor)
        if (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError("input changed while reading")
    except OSError as error:
        raise ValueError("input unavailable") from error
    return parse_bytes(raw)


def load_schema():
    return read_json(HERE / "media-plan-v1.schema.json")


def load_case(case):
    if case not in CASES:
        raise ValueError("unknown built-in case")
    return read_json(HERE / (case + ".json"))


def source_digest(inputs):
    source = {key: inputs[key] for key in ("case", "segments", "assets")}
    return hashlib.sha256(canonical(source)).hexdigest()


def _unique_sorted(values, label):
    if values != sorted(set(values)):
        raise ValueError(label + " identity/order")


def _validate_inputs(inputs, schema):
    _bounded(inputs)
    if len(canonical(inputs)) > LIMITS["bytes"]:
        raise ValueError("input size bound")
    validate_schema(inputs, schema["$defs"]["inputs"], schema)
    if inputs["limits"] != LIMITS:
        raise ValueError("fixed limits")
    count, duration = CASES[inputs["case"]]
    if len(inputs["segments"]) != count or inputs["duration_frames"] != duration:
        raise ValueError("case timeline dimensions")
    asset_ids = [asset["id"] for asset in inputs["assets"]]
    _unique_sorted(asset_ids, "asset")
    segment_ids = [segment["id"] for segment in inputs["segments"]]
    if len(set(segment_ids)) != len(segment_ids):
        raise ValueError("segment identity")
    cursor = 0
    segments = inputs["segments"]
    for index, segment in enumerate(segments):
        if segment["ordinal"] != index + 1 or segment["in_frame"] != cursor or segment["out_frame"] <= cursor:
            raise ValueError("segment timeline or ordinal")
        _unique_sorted(segment["asset_ids"], "asset reference")
        if not set(segment["asset_ids"]) <= set(asset_ids):
            raise ValueError("unknown asset reference")
        length = segment["out_frame"] - cursor
        handle = segment["transition_frames"]
        next_length = (segments[index + 1]["out_frame"] - segments[index + 1]["in_frame"]
                       if index + 1 < count else 0)
        if handle > min(length, next_length) // 2:
            raise ValueError("transition timeline handles")
        cursor = segment["out_frame"]
    if cursor != duration:
        raise ValueError("main timeline coverage")
    profiles = inputs["profiles"]
    if [profile["id"] for profile in profiles] != ["main", "muted", "vertical", "square"]:
        raise ValueError("profile identity/order")
    for profile in profiles:
        name = profile["id"]
        dimensions = {"main": (1920, 1080), "muted": (1920, 1080),
                      "vertical": (1080, 1920), "square": (1080, 1080)}[name]
        audio, subtitles = ("none", "burn_in") if name == "muted" else (
            "aac_stereo", "sidecar" if name == "main" else "burn_in")
        if (profile["width"], profile["height"]) != dimensions:
            raise ValueError("profile dimensions")
        if (profile["audio"], profile["subtitles"]) != (audio, subtitles):
            raise ValueError("profile audio/subtitles")
        if profile["duration_frames"] > duration:
            raise ValueError("profile duration")
        if name in {"main", "muted"} and (profile["duration_frames"], profile["count"]) != (duration, 1):
            raise ValueError("main profile duration/count")
    gates = inputs["gates"]
    if [gate["id"] for gate in gates] != sorted(OWNERS):
        raise ValueError("gate identity/order")
    if any(gate["owner_role"] != OWNERS[gate["id"]] for gate in gates):
        raise ValueError("gate owner role")
    _unique_sorted(inputs["unresolved"], "unresolved")
    if inputs["source"]["content_digest"] != source_digest(inputs):
        raise ValueError("source content digest")


def node_key(input_digest, node):
    return digest("media-node.v1", {"input_digest": input_digest,
                                    **{key: node[key] for key in ("id", "kind", "depends_on", "input_refs")}})


def graph_digest(graph):
    return digest("media-graph.v1", {key: value for key, value in graph.items() if key != "digest"})


def topological(nodes):
    if len(nodes) > LIMITS["nodes"]:
        raise ValueError("node count bound")
    by_id = {node["id"]: node for node in nodes}
    if len(by_id) != len(nodes):
        raise ValueError("duplicate node identity")
    if sum(len(node["depends_on"]) for node in nodes) > LIMITS["edges"]:
        raise ValueError("edge count bound")
    for node in nodes:
        _unique_sorted(node["depends_on"], "dependency")
        if not set(node["depends_on"]) <= by_id.keys():
            raise ValueError("missing dependency")
    remaining = set(by_id)
    order = []
    completed = set()
    while remaining:
        ready = sorted(identifier for identifier in remaining if set(by_id[identifier]["depends_on"]) <= completed)
        if not ready:
            raise ValueError("graph cycle")
        # One-at-a-time lexical Kahn order is deterministic across unrelated inventories.
        current = ready[0]
        order.append(current)
        completed.add(current)
        remaining.remove(current)
    return order


def _graph(inputs, input_digest):
    nodes = []
    def add(identifier, kind, dependencies, refs):
        node = {"id": identifier, "kind": kind, "depends_on": sorted(dependencies), "input_refs": sorted(refs),
                "state": "planned_not_run", "output_digest": None}
        node["planning_key"] = node_key(input_digest, node)
        nodes.append(node)
    add("source", "source", [], ["source"])
    add("gate.scope", "gate", ["source"], ["gates:scope"])
    add("gate.rights", "gate", ["source"], ["gates:rights"])
    add("gate.paid_action", "gate", ["gate.scope", "gate.rights"], ["gates:paid_action"])
    for asset in inputs["assets"]:
        add("asset." + asset["id"], "asset", ["gate.paid_action"], ["assets:" + asset["id"]])
    for segment in inputs["segments"]:
        add("voice." + segment["id"], "voice", ["gate.paid_action"], ["segments:" + segment["id"]])
    prepared = ["asset." + a["id"] for a in inputs["assets"]] + ["voice." + s["id"] for s in inputs["segments"]]
    add("gate.identity_brand", "gate", prepared, ["gates:identity_brand"])
    for segment in inputs["segments"]:
        add("layout." + segment["id"], "layout",
            ["gate.identity_brand", *("asset." + key for key in segment["asset_ids"])],
            ["segments:" + segment["id"]])
    storyboard_inputs = ["voice." + s["id"] for s in inputs["segments"]] + ["layout." + s["id"] for s in inputs["segments"]]
    add("gate.storyboard_timing", "gate", storyboard_inputs, ["gates:storyboard_timing"])
    for segment in inputs["segments"]:
        add("segment." + segment["id"], "segment",
            ["gate.storyboard_timing", "voice." + segment["id"], "layout." + segment["id"]],
            ["segments:" + segment["id"]])
    add("assembly", "assembly", ["segment." + s["id"] for s in inputs["segments"]], ["segments"])
    for profile in inputs["profiles"]:
        add("variant." + profile["id"], "variant", ["assembly"], ["profiles:" + profile["id"]])
    add("qa", "qa", ["variant." + p["id"] for p in inputs["profiles"]], ["profiles"])
    add("gate.final", "gate", ["qa"], ["gates:final"])
    add("gate.publication", "gate", ["gate.final", "gate.rights"], ["gates:publication"])
    add("publication", "publication", ["gate.publication", "qa"], ["profiles"])
    nodes.sort(key=lambda node: node["id"])
    edges = sorted(({"from": dependency, "to": node["id"]} for node in nodes for dependency in node["depends_on"]),
                   key=lambda edge: (edge["from"], edge["to"]))
    graph = {"nodes": nodes, "edges": edges, "order": topological(nodes)}
    graph["digest"] = graph_digest(graph)
    return graph


def compile_plan(inputs):
    schema = load_schema()
    _validate_inputs(inputs, schema)
    schema_digest = hashlib.sha256(canonical(schema)).hexdigest()
    input_digest = digest("media-input.v1", {"schema_digest": schema_digest, "inputs": inputs})
    plan = {"schema_version": "media-design-plan.v1", "schema_digest": schema_digest,
            "input_digest": input_digest, "inputs": copy.deepcopy(inputs), "graph": _graph(inputs, input_digest)}
    validate_plan(plan, schema)
    return plan


def validate_plan(plan, schema=None):
    _bounded(plan)
    if len(canonical(plan)) > LIMITS["bytes"]:
        raise ValueError("plan size bound")
    schema = load_schema() if schema is None else schema
    validate_schema(plan, schema)
    _validate_inputs(plan["inputs"], schema)
    schema_digest = hashlib.sha256(canonical(schema)).hexdigest()
    input_digest = digest("media-input.v1", {"schema_digest": schema_digest, "inputs": plan["inputs"]})
    graph = plan["graph"]
    order = topological(graph["nodes"])
    if order != graph["order"]:
        raise ValueError("graph topological order")
    expected = _graph(plan["inputs"], input_digest)
    # Semantic checks precede digest rejection: recomputing hashes cannot remove gates.
    def semantic_nodes(nodes):
        return [{key: value for key, value in node.items() if key != "planning_key"} for node in nodes]
    if semantic_nodes(graph["nodes"]) != semantic_nodes(expected["nodes"]) or graph["edges"] != expected["edges"]:
        raise ValueError("graph semantics: required dependencies, kinds or input references")
    if plan["schema_digest"] != schema_digest or plan["input_digest"] != input_digest:
        raise ValueError("input/schema digest")
    if graph != expected:
        raise ValueError("node or graph digest")


def benchmark(iterations):
    if type(iterations) is not int or not 1 <= iterations <= 20:
        raise ValueError("benchmark iterations must be 1..20")
    samples = []
    for _ in range(iterations):
        started = time.perf_counter_ns()
        for case in CASES:
            compile_plan(load_case(case))
        samples.append(time.perf_counter_ns() - started)
    ordered = sorted(samples)
    middle = len(ordered) // 2
    median = ordered[middle] if len(ordered) % 2 else (ordered[middle - 1] + ordered[middle]) // 2
    return {"scope": "pair of fixed synthetic JSON/schema/timeline/DAG compilations; no rendering",
            "iterations": iterations, "samples_ns": samples, "median_ns": median,
            "p95_nearest_rank_ns": ordered[(95 * len(ordered) + 99) // 100 - 1],
            "python": sys.version, "platform": sys.platform, "provider_calls": 0,
            "paid_provider_micro_usd": 0, "total_cost": None,
            "rss": None, "rss_reason": "not measured; portable example uses monotonic wall time only"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=("promo", "webinar", "both"), default="both")
    parser.add_argument("--benchmark", type=int, choices=range(1, 21))
    args = parser.parse_args(argv)
    cases = list(CASES) if args.case == "both" else [args.case]
    try:
        result = {"plans": [compile_plan(load_case(case)) for case in cases]}
        if args.benchmark is not None:
            result["benchmark"] = benchmark(args.benchmark)
        payload = canonical(result)
    except ReaderUnavailable:
        print("media-design: safe reader unavailable on this platform", file=sys.stderr)
        return 2
    except ValueError:
        print("media-design: invalid built-in input or plan", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
