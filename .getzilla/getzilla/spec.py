from __future__ import annotations

import hashlib
import copy
import json
import os
import re
import stat
import subprocess
import unicodedata
from pathlib import Path
from typing import Any
from . import STACK_DIR

from . import fsx

SCHEMA_PATH = STACK_DIR.parent / "schemas" / "change-spec.schema.json"
LEGACY_SCHEMA_PATH = STACK_DIR.parent / "schemas" / "change-spec-v1.schema.json"
UNKNOWN_TOKEN = "UNKNOWN"  # nosec B105
MAX_SPEC_BYTES = 1_000_000
MAX_STRING_LENGTH = 65_536
MAX_DEPTH = 64
MAX_NODES = 20_000
MAX_RULE_REFERENCES = 512
ALLOWED_SCHEMA_KEYS = {
    "$schema",
    "$id",
    "$defs",
    "$ref",
    "description",
    "type",
    "properties",
    "required",
    "additionalProperties",
    "enum",
    "const",
    "pattern",
    "minLength",
    "maxLength",
    "minItems",
    "maxItems",
    "minimum",
    "maximum",
    "items",
    "uniqueItems",
    "minProperties",
    "maxProperties",
}
JSON_SCHEMA_TYPE_NAMES = frozenset(
    {"object", "array", "string", "integer", "boolean", "null"}
)

RISK_MAP = {"low": "green", "medium": "yellow", "high": "red"}


class SpecError(ValueError):
    def __init__(self, message: str, *, code: str = "invalid") -> None:
        super().__init__(message)
        self.code = code


def _schema_preflight(schema: Any, path: str = "$") -> None:
    if isinstance(schema, dict):
        extra = set(schema) - ALLOWED_SCHEMA_KEYS
        if extra:
            raise SpecError(f"{path}: unsupported schema keywords: {sorted(extra)}", code="schema")
        if "type" in schema:
            _validate_type_declaration(schema["type"])
        for key, value in schema.items():
            if key in {"properties", "$defs"}:
                if not isinstance(value, dict):
                    raise SpecError(f"{path}.{key}: expected object", code="schema")
                for name, child in value.items():
                    _schema_preflight(child, f"{path}.{key}.{name}")
            elif key == "items":
                _schema_preflight(value, f"{path}.items")


def load_schema(path: Path | None = None, *, anchor=None) -> dict[str, Any]:
    target = path or SCHEMA_PATH
    data = json.loads(anchor.read('schemas/change-spec.schema.json', MAX_SPEC_BYTES, private=False, source=True)
                      if anchor is not None and path is None else target.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SpecError("schema root must be an object")
    _schema_preflight(data)
    return data


def parse_yaml_subset(text: str, *, rules_profile: bool = False) -> Any:
    if type(rules_profile) is not bool:
        raise SpecError("unknown YAML profile")
    if rules_profile:
        return _parse_rules_yaml(text)
    if not text.strip():
        raise SpecError("empty YAML")
    if "\t" in text:
        raise SpecError("tabs are not allowed")
    if re.search(r"(^|\s)!!", text):
        raise SpecError("YAML tags are not allowed")
    if re.search(r"(^|\s)<<:", text):
        raise SpecError("YAML merge keys are not allowed")
    if re.search(r"(^|\s)[&*]", text) or re.search(r":\s*[&*]", text):
        raise SpecError("YAML anchors and aliases are not allowed")
    lines = text.replace("\r\n", "\n").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    value, index = _parse_block(lines, 0, 0)
    leftover = _skip_blank(lines, index)
    if leftover < len(lines):
        raise SpecError(f"unexpected content at line {leftover + 1}")
    return value


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _skip_blank(lines: list[str], index: int) -> int:
    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped or stripped.startswith("#"):
            index += 1
            continue
        return index
    return index


def _parse_block(lines: list[str], index: int, indent: int, *, _rules=None, _depth=0) -> tuple[Any, int]:
    if _rules is not None:
        _rules.node(_depth)
    index = _skip_blank(lines, index)
    if index >= len(lines):
        raise SpecError("unexpected end of YAML")
    line = lines[index]
    if _indent_of(line) != indent:
        raise SpecError(f"bad indent at line {index + 1}")
    stripped = line.lstrip(" ")
    if stripped.startswith("- "):
        return _parse_list(lines, index, indent, _rules=_rules, _depth=_depth)
    return _parse_map(lines, index, indent, _rules=_rules, _depth=_depth)


def _parse_map(lines: list[str], index: int, indent: int, *, _rules=None, _depth=0) -> tuple[dict[str, Any], int]:
    result: dict[str, Any] = {}
    while index < len(lines):
        index = _skip_blank(lines, index)
        if index >= len(lines):
            break
        line = lines[index]
        current = _indent_of(line)
        if current < indent:
            break
        if current != indent:
            raise SpecError(f"bad indent at line {index + 1}")
        stripped = line[indent:]
        if stripped.startswith("- "):
            raise SpecError(f"expected mapping key at line {index + 1}")
        if ":" not in stripped:
            raise SpecError(f"expected mapping at line {index + 1}")
        key, rest = stripped.split(":", 1)
        key = key.strip()
        if not key or key in result:
            raise SpecError(f"duplicate or empty key at line {index + 1}")
        rest = rest.strip()
        index += 1
        if _rules is not None:
            _rules.key(key, _depth + 1)
            result[key], index = _rules.value(lines, index, indent, rest, key, _depth + 1)
            continue
        if rest == "":
            nxt = _skip_blank(lines, index)
            if nxt >= len(lines) or _indent_of(lines[nxt]) <= indent:
                result[key] = None
            else:
                value, index = _parse_block(lines, nxt, _indent_of(lines[nxt]))
                result[key] = value
        else:
            result[key] = _parse_scalar(rest, index)
    return result, index


def _parse_list(lines: list[str], index: int, indent: int, *, _rules=None, _depth=0) -> tuple[list[Any], int]:
    items: list[Any] = []
    while index < len(lines):
        index = _skip_blank(lines, index)
        if index >= len(lines):
            break
        line = lines[index]
        current = _indent_of(line)
        if current < indent:
            break
        if current != indent:
            raise SpecError(f"bad indent at line {index + 1}")
        stripped = line[indent:]
        if not stripped.startswith("- "):
            break
        rest = stripped[2:]
        index += 1
        if rest.strip() == "":
            if _rules is not None:
                value, index = _rules.value(lines, index, indent, '', None, _depth + 1)
                items.append(value)
                continue
            nxt = _skip_blank(lines, index)
            if nxt >= len(lines) or _indent_of(lines[nxt]) <= indent:
                items.append(None)
            else:
                value, index = _parse_block(lines, nxt, _indent_of(lines[nxt]))
                items.append(value)
        elif ":" in rest and not rest.strip().startswith(('"', "'")):
            inline_key, inline_rest = rest.split(":", 1)
            mapping: dict[str, Any] = {}
            key = inline_key.strip()
            if not key:
                raise SpecError(f"empty list mapping key at line {index}")
            inline_rest = inline_rest.strip()
            if _rules is not None:
                _rules.node(_depth + 1)
                _rules.key(key, _depth + 2)
                mapping[key], index = _rules.value(lines, index, indent, inline_rest, key, _depth + 2)
            elif inline_rest == "":
                nxt = _skip_blank(lines, index)
                if nxt < len(lines) and _indent_of(lines[nxt]) > indent:
                    value, index = _parse_block(lines, nxt, _indent_of(lines[nxt]))
                    mapping[key] = value
                else:
                    mapping[key] = None
            else:
                mapping[key] = _parse_scalar(inline_rest, index)
            child_indent = indent + 2
            peek = _skip_blank(lines, index)
            if peek < len(lines) and _indent_of(lines[peek]) == child_indent and not lines[peek].lstrip(" ").startswith("- "):
                nested, index = _parse_map(lines, peek, child_indent, _rules=_rules, _depth=_depth + 1)
                for nested_key, nested_value in nested.items():
                    if nested_key in mapping:
                        raise SpecError(f"duplicate key {nested_key}")
                    mapping[nested_key] = nested_value
            items.append(mapping)
        else:
            items.append(_rules.scalar(rest.strip(), _depth + 1) if _rules is not None else _parse_scalar(rest.strip(), index))
    return items, index


class _RuleYamlContext:
    """Rules-only bounded data resolution; never a global config/authority mode."""

    def __init__(self):
        self.nodes = self._source_bytes = self.references = 0
        self.anchors = {}
        self.active = set()

    def node(self, depth):
        self.nodes += 1
        if depth > MAX_DEPTH or self.nodes > MAX_NODES:
            raise SpecError('rules YAML limit')

    def string(self, value):
        size = len(value.encode('utf-8'))
        self._source_bytes += size
        if size > MAX_STRING_LENGTH or self._source_bytes > MAX_SPEC_BYTES:
            raise SpecError('rules YAML limit')
        return value

    def key(self, value, depth):
        self.node(depth)
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*', value) or value == '<<':
            raise SpecError('unsupported rules YAML key')
        self.string(value)

    def reference(self):
        self.references += 1
        if self.references > MAX_RULE_REFERENCES:
            raise SpecError('rules YAML reference limit')

    def value(self, lines, index, indent, rest, key, depth):
        if rest.startswith('&'):
            match = re.fullmatch(r'&([A-Za-z][A-Za-z0-9_-]{0,63})', rest)
            if key != 'pattern-sources' or not match or match[1] in self.anchors or match[1] in self.active:
                raise SpecError('unsupported rules YAML anchor')
            self.reference()
            name = match[1]
            self.active.add(name)
            try:
                value, index = self.value(lines, index, indent, '', key, depth)
                if not isinstance(value, list):
                    raise SpecError('rules anchor must be a completed list')
                self.anchors[name] = (value, self.metrics(value))
                return value, index
            finally:
                self.active.remove(name)
        if rest.startswith('*'):
            match = re.fullmatch(r'\*([A-Za-z][A-Za-z0-9_-]{0,63})', rest)
            if key != 'pattern-sources' or not match or match[1] in self.active or match[1] not in self.anchors:
                raise SpecError('unsupported rules YAML alias')
            self.reference()
            value, (nodes, size, height) = self.anchors[match[1]]
            # Charge the complete expansion BEFORE copying. Never reset per alias.
            if self.nodes + nodes > MAX_NODES or self._source_bytes + size > MAX_SPEC_BYTES or depth + height > MAX_DEPTH:
                raise SpecError('rules YAML expansion limit')
            self.nodes += nodes
            self._source_bytes += size
            return copy.deepcopy(value), index
        if not rest:
            nxt = _skip_blank(lines, index)
            if nxt >= len(lines) or _indent_of(lines[nxt]) <= indent:
                return self.scalar('null', depth), index
            return _parse_block(lines, nxt, _indent_of(lines[nxt]), _rules=self, _depth=depth)
        return self.scalar(rest, depth), index

    @staticmethod
    def metrics(value):
        nodes = size = height = 0
        pending = [(value, 0)]
        while pending:
            item, depth = pending.pop()
            nodes += 1
            height = max(height, depth)
            if isinstance(item, str):
                size += len(item.encode('utf-8'))
            elif isinstance(item, dict):
                pending.extend((child, depth + 1) for pair in item.items() for child in pair)
            elif isinstance(item, list):
                pending.extend((child, depth + 1) for child in item)
        return nodes, size, height

    @staticmethod
    def split_flow(raw, separator):
        parts, stack, quote, escaped, start, index = [], [], None, False, 0, 0
        while index < len(raw):
            char = raw[index]
            if quote:
                if escaped:
                    escaped = False
                elif quote == '"' and char == '\\':
                    escaped = True
                elif char == quote:
                    if quote == "'" and index + 1 < len(raw) and raw[index + 1] == "'":
                        index += 1
                    else:
                        quote = None
            elif char in "'\"":
                quote = char
            elif char in '[{':
                stack.append(']' if char == '[' else '}')
            elif char in ']}':
                if not stack or stack.pop() != char:
                    raise SpecError('unsupported rules flow value')
            elif char == separator and not stack:
                parts.append(raw[start:index].strip())
                start = index + 1
            index += 1
        if quote or stack:
            raise SpecError('unsupported rules flow value')
        parts.append(raw[start:].strip())
        return parts

    def scalar(self, raw, depth):
        self.node(depth)
        if len(raw.encode('utf-8')) > MAX_STRING_LENGTH or not raw:
            raise SpecError('rules YAML scalar limit')
        if raw.startswith('"'):
            value = json.loads(raw)
            if not isinstance(value, str):
                raise SpecError('unsupported rules scalar')
            return self.string(value)
        if raw.startswith("'"):
            if not raw.endswith("'") or "'" in raw[1:-1].replace("''", ''):
                raise SpecError('unsupported rules scalar')
            return self.string(raw[1:-1].replace("''", "'"))
        if raw.startswith(('[', '{')):
            if not raw.endswith(']' if raw[0] == '[' else '}'):
                raise SpecError('unsupported rules flow value')
            inner = raw[1:-1]
            parts = self.split_flow(inner, ',') if inner.strip() else []
            if any(not part for part in parts):
                raise SpecError('unsupported rules flow value')
            if raw[0] == '[':
                return [self.scalar(part, depth + 1) for part in parts]
            result = {}
            for part in parts:
                pair = self.split_flow(part, ':')
                if len(pair) != 2 or pair[0] in result:
                    raise SpecError('duplicate or unsupported rules flow key')
                self.key(pair[0], depth + 1)
                result[pair[0]] = self.scalar(pair[1], depth + 1)
            return result
        if (raw[0] in '&*!|>%@`]},' or raw.startswith('<<') or '#' in raw
                or re.match(r'^[-?:](?:\s|$)', raw) or re.search(r':(?:\s|$)', raw)
                or re.fullmatch(r'[-+]?(?:[0-9]+\.[0-9]*|\.[0-9]+)(?:[eE][-+]?[0-9]+)?', raw)
                or re.fullmatch(r'[-+]?[0-9]+[eE][-+]?[0-9]+', raw)
                or raw.lower() in {'.inf', '+.inf', '-.inf', '.nan'}
                or re.match(r'^[0-9]{4}-[0-9]{2}-[0-9]{2}', raw)):
            raise SpecError('unsupported rules scalar')
        if raw.lower() in {'true', 'false'}:
            return raw.lower() == 'true'
        if raw.lower() == 'null' or raw == '~':
            return None
        if re.fullmatch(r'-?(?:0|[1-9][0-9]*)', raw):
            return int(raw)
        if re.fullmatch(r'[-+]?[0-9]+', raw):
            raise SpecError('ambiguous rules integer')
        return self.string(raw)


def _parse_rules_yaml(text):
    try:
        if not isinstance(text, str) or not 0 < len(text.encode('utf-8')) <= MAX_SPEC_BYTES or '\t' in text:
            raise SpecError('rules YAML input limit')
        lines = text.replace('\r\n', '\n').split('\n')
        context = _RuleYamlContext()
        value, index = _parse_block(lines, 0, 0, _rules=context)
        if (_skip_blank(lines, index) < len(lines) or not isinstance(value, dict) or set(value) != {'rules'}
                or not isinstance(value['rules'], list) or not value['rules']
                or len(json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8')) > MAX_SPEC_BYTES):
            raise SpecError('unsupported or oversized rules YAML')
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise SpecError('unsupported or oversized rules YAML') from None


def _parse_scalar(raw: str, line_no: int) -> Any:
    if raw.startswith(("!!", "&", "*")) or raw.startswith("<<"):
        raise SpecError(f"forbidden YAML construct at line {line_no}")
    if (raw.startswith('"') and raw.endswith('"')) or (raw.startswith("'") and raw.endswith("'")):
        return raw[1:-1]
    if raw == "[]":
        return []
    if raw == "{}":
        return {}
    if raw in {"null", "~"}:
        return None
    if raw in {"true", "True"}:
        return True
    if raw in {"false", "False"}:
        return False
    if re.fullmatch(r"-?\d+", raw):
        return int(raw)
    if "#" in raw:
        raise SpecError(f"unquoted # at line {line_no}")
    return raw


def dump_yaml_subset(data: Any, indent: int = 0) -> str:
    return "\n".join(_dump_yaml(data, indent)) + "\n"


def _needs_quotes(value: str) -> bool:
    return (":" in value) or ("#" in value) or value == "" or value in {"true", "false", "null", "True", "False"}


def _dump_yaml(data: Any, indent: int) -> list[str]:
    pad = "  " * indent
    if isinstance(data, dict):
        if not data:
            return []
        lines: list[str] = []
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                nested = _dump_yaml(value, indent + 1)
                if not nested:
                    empty = "[]" if isinstance(value, list) else "{}"
                    lines.append(f"{pad}{key}: {empty}")
                else:
                    lines.append(f"{pad}{key}:")
                    lines.extend(nested)
            else:
                lines.append(f"{pad}{key}: {_format_scalar(value)}")
        return lines
    if isinstance(data, list):
        if not data:
            return []
        lines = []
        for item in data:
            if isinstance(item, dict):
                if not item:
                    lines.append(f"{pad}- {{}}")
                    continue
                first = True
                for key, value in item.items():
                    prefix = f"{pad}- " if first else f"{pad}  "
                    first = False
                    if isinstance(value, (dict, list)):
                        nested = _dump_yaml(value, indent + 2)
                        if not nested:
                            empty = "[]" if isinstance(value, list) else "{}"
                            lines.append(f"{prefix}{key}: {empty}")
                        else:
                            lines.append(f"{prefix}{key}:")
                            lines.extend(nested)
                    else:
                        lines.append(f"{prefix}{key}: {_format_scalar(value)}")
            else:
                lines.append(f"{pad}- {_format_scalar(item)}")
        return lines
    return [f"{pad}{_format_scalar(data)}"]


def _format_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    text = str(value)
    if _needs_quotes(text):
        return json.dumps(text, ensure_ascii=False)
    return text


def resolve_ref(schema: dict[str, Any], root: dict[str, Any]) -> dict[str, Any]:
    ref = schema.get("$ref")
    if not ref:
        return schema
    if not isinstance(ref, str) or not ref.startswith("#/$defs/"):
        raise SpecError("only local #/$defs refs are allowed")
    name = ref[len("#/$defs/"):]
    defs = root.get("$defs")
    if not isinstance(defs, dict) or name not in defs:
        raise SpecError(f"unknown $ref {ref}")
    target = defs[name]
    if not isinstance(target, dict):
        raise SpecError(f"invalid $ref target {ref}")
    return target


def validate_schema(
    instance: Any,
    schema: dict[str, Any],
    root: dict[str, Any] | None = None,
    *,
    path: str = "$",
) -> None:
    root = root or schema
    schema = resolve_ref(schema, root)
    extra = set(schema) - ALLOWED_SCHEMA_KEYS
    if extra:
        raise SpecError(f"{path}: unsupported schema keywords: {sorted(extra)}")
    if "const" in schema and instance != schema["const"]:
        raise SpecError(f"{path}: expected const {schema['const']!r}")
    if "enum" in schema and instance not in schema["enum"]:
        raise SpecError(f"{path}: value {instance!r} not in enum")
    expected = schema.get("type")
    if "type" in schema:
        if not _type_matches(instance, expected):
            raise SpecError(f"{path}: expected type {expected}")
    if expected == "object" or ("properties" in schema and isinstance(instance, dict)):
        if not isinstance(instance, dict):
            raise SpecError(f"{path}: expected object")
        additional = schema.get("additionalProperties", True)
        props = schema.get("properties", {})
        if additional is False:
            extra_keys = set(instance) - set(props)
            if extra_keys:
                raise SpecError(f"{path}: additional properties not allowed: {sorted(extra_keys)}")
        if "minProperties" in schema and len(instance) < schema["minProperties"]:
            raise SpecError(f"{path}: object has fewer than minProperties")
        if "maxProperties" in schema and len(instance) > schema["maxProperties"]:
            raise SpecError(f"{path}: object has more than maxProperties")
        for key in schema.get("required", []):
            if key not in instance:
                raise SpecError(f"{path}: missing required property {key}")
        for key, value in instance.items():
            if key in props:
                validate_schema(value, props[key], root, path=f"{path}.{key}")
    if "items" in schema:
        if not isinstance(instance, list):
            raise SpecError(f"{path}: expected array")
        for index, item in enumerate(instance):
            validate_schema(item, schema["items"], root, path=f"{path}[{index}]")
    if isinstance(instance, str):
        if "pattern" in schema and re.search(schema["pattern"], instance) is None:
            raise SpecError(f"{path}: string does not match pattern")
        if "minLength" in schema and len(instance) < schema["minLength"]:
            raise SpecError(f"{path}: string shorter than minLength")
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            raise SpecError(f"{path}: string longer than maxLength")
    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            raise SpecError(f"{path}: array shorter than minItems")
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            raise SpecError(f"{path}: array longer than maxItems")
        if schema.get("uniqueItems"):
            encoded = [json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=False) for item in instance]
            if len(encoded) != len(set(encoded)):
                raise SpecError(f"{path}: array items must be unique")
    if isinstance(instance, int) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            raise SpecError(f"{path}: below minimum")
        if "maximum" in schema and instance > schema["maximum"]:
            raise SpecError(f"{path}: above maximum")


def _validate_type_declaration(expected: Any) -> None:
    if isinstance(expected, list):
        if not expected or any(not isinstance(item, str) for item in expected):
            raise SpecError("schema type array must contain type names")
        for item in expected:
            _validate_type_declaration(item)
        return
    if not isinstance(expected, str):
        raise SpecError("schema type must be a string or array of strings")
    if expected not in JSON_SCHEMA_TYPE_NAMES:
        raise SpecError(f"unsupported type {expected}")


def _type_matches(instance: Any, expected: Any) -> bool:
    _validate_type_declaration(expected)
    if isinstance(expected, list):
        return any(_type_matches(instance, item) for item in expected)
    mapping = {
        "object": dict,
        "array": list,
        "string": str,
        "integer": int,
        "boolean": bool,
        "null": type(None),
    }
    cls = mapping[expected]
    if expected == "integer":
        return isinstance(instance, int) and not isinstance(instance, bool)
    return isinstance(instance, cls)


def _reject_constant(value: str) -> None:
    raise SpecError(f"non-finite JSON number is forbidden: {value}", code="parse")


def _pairs_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SpecError(f"duplicate JSON key: {key}", code="parse")
        result[key] = value
    return result


def _bounded_walk(value: Any, depth: int = 0, counter: list[int] | None = None) -> None:
    if counter is None:
        counter = [0]
    counter[0] += 1
    if counter[0] > MAX_NODES:
        raise SpecError("spec node limit exceeded", code="limit")
    if depth > MAX_DEPTH:
        raise SpecError("spec nesting limit exceeded", code="limit")
    if isinstance(value, str):
        if len(value) > MAX_STRING_LENGTH:
            raise SpecError("spec string limit exceeded", code="limit")
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise SpecError("unpaired Unicode surrogate is forbidden", code="parse")
    if isinstance(value, dict):
        for key, item in value.items():
            _bounded_walk(key, depth + 1, counter)
            _bounded_walk(item, depth + 1, counter)
    elif isinstance(value, list):
        for item in value:
            _bounded_walk(item, depth + 1, counter)


def _read_regular_bytes(path: Path, limit: int = MAX_SPEC_BYTES) -> bytes:
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or path.is_symlink():
            raise SpecError(f"{path}: spec must be a regular non-symlink file", code="io")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise SpecError(f"{path}: spec changed while opening", code="io")
            if opened.st_size > limit:
                raise SpecError(f"{path}: spec byte limit exceeded", code="limit")
            data = os.read(fd, limit + 1)
            after = os.fstat(fd)
        finally:
            os.close(fd)
    except SpecError:
        raise
    except OSError as exc:
        raise SpecError(f"{path}: cannot read spec: {exc}", code="io") from exc
    if len(data) > limit or after.st_size != len(data):
        raise SpecError(f"{path}: spec byte limit or concurrent write detected", code="limit")
    return data


def _parse_canonical_json(data: bytes, path: Path) -> dict[str, Any]:
    if data.startswith(b"\xef\xbb\xbf"):
        raise SpecError(f"{path}: UTF-8 BOM is forbidden", code="parse")
    try:
        text = data.decode("utf-8", errors="strict")
        value = json.loads(text, object_pairs_hook=_pairs_object, parse_constant=_reject_constant)
    except SpecError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise SpecError(f"{path}: invalid canonical JSON: {exc}", code="parse") from exc
    if not isinstance(value, dict):
        raise SpecError(f"{path}: spec root must be an object", code="parse")
    _bounded_walk(value)
    return value


def load_spec(path: Path, *, allow_legacy: bool = True) -> dict[str, Any]:
    data = _read_regular_bytes(path)
    try:
        return _parse_canonical_json(data, path)
    except SpecError as canonical_error:
        if not allow_legacy:
            raise canonical_error
    try:
        text = data.decode("utf-8", errors="strict")
        value = parse_yaml_subset(text)
    except (UnicodeDecodeError, SpecError) as exc:
        raise SpecError(f"{path}: invalid historical v1 spec", code="parse") from exc
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise SpecError(f"{path}: legacy decoder accepts schema_version 1 only", code="version")
    _bounded_walk(value)
    return value


def dump_canonical_spec(spec: dict[str, Any]) -> str:
    return json.dumps(spec, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"


def canonical_spec_digest(spec: dict[str, Any]) -> str:
    payload = json.dumps(spec, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


canonical_digest = canonical_spec_digest


def _evidence_value(evidence: dict[str, Any]) -> str:
    if set(evidence) == {"kind", "ref"}:
        return str(evidence["ref"])
    if len(evidence) != 1:
        return ""
    return str(next(iter(evidence.values())))


def criterion_coverage(spec: dict[str, Any]) -> dict[str, Any]:
    category_fields = ("acceptance_criteria", "invariants", "forbidden_outcomes")
    categories: dict[str, dict[str, Any]] = {}
    mapped_all: list[str] = []
    unmapped_all: list[str] = []
    counts = {key: 0 for key in ("test", "receipt", "production_signal", "attestation")}
    for collection in category_fields:
        items = spec.get(collection) if isinstance(spec.get(collection), list) else []
        mapped: list[str] = []
        unmapped: list[str] = []
        for item in items:
            criterion_id = str(item.get("id", "")) if isinstance(item, dict) else ""
            evidence = item.get("evidence") if isinstance(item, dict) else None
            if isinstance(evidence, list) and evidence:
                mapped.append(criterion_id)
                if collection == "acceptance_criteria":
                    for ref in evidence:
                        if isinstance(ref, dict) and set(ref) == {"kind", "ref"}:
                            legacy_kind = str(ref.get("kind"))
                            if legacy_kind in counts:
                                counts[legacy_kind] += 1
                        elif isinstance(ref, dict) and len(ref) == 1:
                            key = next(iter(ref))
                            if key in counts:
                                counts[key] += 1
            else:
                unmapped.append(criterion_id)
        categories[collection] = {
            "criterion_total": len(items),
            "criterion_mapped": len(mapped),
            "mapped_ids": sorted(mapped),
            "unmapped_ids": sorted(unmapped),
        }
        mapped_all.extend(mapped)
        unmapped_all.extend(unmapped)
    ac_coverage = categories["acceptance_criteria"]
    ac_projection = {
        "spec_count": 1,
        "criterion_total": ac_coverage["criterion_total"],
        "criterion_mapped": ac_coverage["criterion_mapped"],
        "unmapped_ids": ac_coverage["unmapped_ids"],
    }
    return {
        "spec_count": 1,
        # These four fields remain the AC-only projection used by existing UI
        # and Trust CI v1 compatibility adapters.
        "criterion_total": ac_coverage["criterion_total"],
        "criterion_mapped": ac_coverage["criterion_mapped"],
        "mapped_ids": ac_coverage["mapped_ids"],
        "unmapped_ids": ac_coverage["unmapped_ids"],
        "evidence_counts": counts,
        "attestation_ac": ac_projection,
        "categories": categories,
        "all_criterion_total": sum(item["criterion_total"] for item in categories.values()),
        "all_criterion_mapped": sum(item["criterion_mapped"] for item in categories.values()),
        "all_mapped_ids": sorted(mapped_all),
        "all_unmapped_ids": sorted(unmapped_all),
    }


def requirement_targets(spec: dict[str, Any]) -> dict[str, Any]:
    """Current typed requirement content, shared by scope and semantic decisions."""
    items = [spec['objective']]
    for name in ('acceptance_criteria', 'invariants', 'forbidden_outcomes'):
        items.extend(spec.get(name, []))
    return {item['id']: item for item in items}


def attestation_criterion_coverage(spec: dict[str, Any]) -> dict[str, Any]:
    """Return the exact AC-only criterion_coverage shape used by Trust CI v1.

    Callers preparing signed v1 attestation payloads must use this adapter,
    never the category-aware local ``criterion_coverage`` result.
    """
    return dict(criterion_coverage(spec)["attestation_ac"])


def _unsafe_path_character(value: str) -> bool:
    return any(unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"} for character in value)


def _safe_contract_path(root: Path, raw: str, *, anchor=None) -> Path | None:
    rel = Path(raw)
    if (
        not raw
        or _unsafe_path_character(raw)
        or rel.is_absolute()
        or "\\" in raw
        or ".." in rel.parts
        or any(part in {"", "."} for part in rel.parts)
    ):
        raise SpecError(f"unsafe contract path: {raw!r}", code="path")
    candidate = root.joinpath(*rel.parts)
    if anchor is not None:
        try:
            with anchor.parent(rel, private=False, source=True) as (parent, name):
                info = fsx.lstat_at(parent, name)
                anchor._regular(info, private=False, source=True, limit=8*1024*1024)
            return candidate
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            raise SpecError(f'unsafe contract path: {raw!r}', code='path') from exc
    try:
        info = candidate.lstat()
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise SpecError(f"unsafe contract path: {raw!r}", code="path") from exc
    if candidate.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise SpecError(f"contract must be a regular non-symlink file: {raw}", code="path")
    try:
        candidate.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise SpecError(f"contract escapes repository: {raw}", code="path") from exc
    return candidate


def _contract_digest(root: Path, raw: str, *, anchor=None) -> str | None:
    rel = Path(raw)
    if (
        not raw
        or _unsafe_path_character(raw)
        or rel.is_absolute()
        or "\\" in raw
        or ".." in rel.parts
        or any(part in {"", "."} for part in rel.parts)
    ):
        raise SpecError(f"unsafe contract path: {raw!r}", code="path")
    if anchor is not None:
        try:
            anchor.check_root(root)
            return hashlib.sha256(anchor.read(raw,MAX_SPEC_BYTES,public_source=True)).hexdigest()
        except FileNotFoundError:
            return None
        except (OSError,ValueError) as exc:
            raise SpecError('native contract input unavailable',code='path') from exc
    descriptors: list[int] = []
    handles: list[fsx.DirHandle] = []
    try:
        current = fsx.open_dir(root.resolve(strict=True))
        handles.append(current)
        for part in rel.parts[:-1]:
            current = fsx.open_dir_at(current, part)
            handles.append(current)
        fd = fsx.open_at(current, rel.parts[-1], os.O_RDONLY | fsx.O_NOFOLLOW)
        descriptors.append(fd)
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > MAX_SPEC_BYTES:
            raise SpecError(f"contract must be a bounded regular non-symlink file: {raw}", code="path")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(fd, 65_536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_SPEC_BYTES:
                raise SpecError(f"contract byte limit exceeded: {raw}", code="limit")
            digest.update(chunk)
        after = os.fstat(fd)
        before_identity = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
        after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        if total != opened.st_size or after_identity != before_identity:
            raise SpecError(f"contract changed while hashing: {raw}", code="path")
        return digest.hexdigest()
    except FileNotFoundError:
        return None
    except SpecError:
        raise
    except (OSError, ValueError) as exc:
        raise SpecError(f"unsafe contract path: {raw!r}: {exc}", code="path") from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        for handle in reversed(handles):
            fsx.close_dir(handle)


def _native_spec_relative(root: Path, path: Path, anchor) -> str:
    anchor.check_root(root)
    candidate = path if path.is_absolute() else Path(anchor.workspace)/path
    try:
        return Path(os.path.abspath(candidate)).relative_to(Path(anchor.workspace)).as_posix()
    except ValueError as exc:
        raise SpecError('native spec path escapes repository',code='path') from exc


def spec_fingerprint(
    root: Path,
    path: Path,
    spec: dict[str, Any],
    route: dict[str, Any] | None = None,
    *,anchor=None,
) -> str:
    contracts: list[dict[str, str]] = []
    for group in (spec.get("contracts") or {}).values():
        for raw in group or []:
            contract_digest = _contract_digest(root, str(raw),anchor=anchor)
            if contract_digest is not None:
                contracts.append({"path": str(raw), "digest": contract_digest})
    head = None
    if anchor is not None:
        head = anchor.git_source()['head']
        spec_path = _native_spec_relative(root,path,anchor)
    else:
        try:
            proc = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, text=True, encoding="utf-8", capture_output=True, timeout=10, check=False)
            head = proc.stdout.strip() if proc.returncode == 0 else None
        except OSError:
            pass
        spec_path = path.resolve().relative_to(root.resolve()).as_posix()
    payload = {
        "spec_path": spec_path,
        "spec_digest": canonical_spec_digest(spec),
        "base_commit": (route or {}).get("base_commit"),
        "git_head": head,
        "contracts": sorted(contracts, key=lambda item: item["path"]),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _semantic_errors(spec: dict[str, Any], *, gate: bool, root: Path | None = None, anchor=None) -> list[str]:
    errors: list[str] = []
    collections = (("acceptance_criteria", "acceptance criterion"), ("invariants", "invariant"), ("forbidden_outcomes", "forbidden outcome"))
    all_ids: list[str] = []
    signals = {str(item.get("id")) for item in spec.get("observability") or [] if isinstance(item, dict)}
    for collection, label in collections:
        ids = [str(item.get("id")) for item in spec.get(collection) or [] if isinstance(item, dict)]
        all_ids.extend(ids)
        if len(ids) != len(set(ids)):
            errors.append(f"duplicate {label} ids")
        for item in spec.get(collection) or []:
            if not isinstance(item, dict):
                continue
            evidence = item.get("evidence") or []
            if gate and not evidence:
                errors.append(f"{label} {item.get('id')} has no evidence")
            for ref in evidence:
                if not isinstance(ref, dict) or len(ref) != 1:
                    errors.append(f"{label} {item.get('id')} evidence must contain exactly one supported key")
                    continue
                kind, value = next(iter(ref.items()))
                if kind == "production_signal" and value not in signals:
                    errors.append(f"{label} {item.get('id')} references unknown production signal {value}")
                if kind == "test" and root is not None:
                    file_part = str(value).split("::", 1)[0]
                    try:
                        target = _safe_contract_path(root, file_part, anchor=anchor)
                    except SpecError as exc:
                        errors.append(str(exc))
                    else:
                        if target is None:
                            errors.append(f"test evidence path does not exist: {file_part}")
    if len(all_ids) != len(set(all_ids)):
        errors.append("stable IDs must be unique across criterion collections")
    if len(signals) != len(spec.get("observability") or []):
        errors.append("duplicate observability signal ids")
    objective_id = str((spec.get("objective") or {}).get("id", ""))
    for signal in spec.get("observability") or []:
        if not isinstance(signal, dict):
            continue
        proves = signal.get("proves")
        if not isinstance(proves, list) or not proves or any(value != objective_id for value in proves):
            errors.append(f"observability signal {signal.get('id')} must prove objective {objective_id}")
    for group in (spec.get("contracts") or {}).values():
        for raw in group or []:
            try:
                if root is not None:
                    target = _safe_contract_path(root, str(raw), anchor=anchor)
                    if target is None:
                        errors.append(f"contract path does not exist: {raw}")
                else:
                    rel = Path(str(raw))
                    if (
                        not str(raw)
                        or _unsafe_path_character(str(raw))
                        or rel.is_absolute()
                        or "\\" in str(raw)
                        or any(part in {"", ".", ".."} for part in rel.parts)
                    ):
                        raise SpecError(f"unsafe contract path: {raw!r}")
            except SpecError as exc:
                errors.append(str(exc))
    if gate:
        objective = spec.get("objective") or {}
        for field in ("success_metric", "target"):
            if objective.get(field) == UNKNOWN_TOKEN:
                errors.append(f"objective.{field} cannot be UNKNOWN at gate")
        if not spec.get("acceptance_criteria"):
            errors.append("gate requires at least one acceptance criterion")
        risk = spec.get("risk") or {}
        if risk.get("tier") == "red":
            if not spec.get("forbidden_outcomes"):
                errors.append("red-risk requires forbidden_outcomes")
            if not (spec.get("approvals") or {}).get("required_scopes"):
                errors.append("red-risk requires approvals.required_scopes")
    return errors


def _validate_document(spec: dict[str, Any], *, gate: bool, root: Path | None = None, anchor=None) -> dict[str, Any]:
    _bounded_walk(spec)
    version = spec.get("schema_version")
    if version != 2:
        raise SpecError("legacy schema_version 1 is compatibility-only and cannot produce current gate evidence", code="version")
    schema = load_schema(anchor=anchor)
    validate_schema(spec, schema, schema)
    errors = _semantic_errors(spec, gate=gate, root=root, anchor=anchor)
    if errors:
        raise SpecError("; ".join(errors), code="incomplete")
    return {"ok": True, "digest": canonical_spec_digest(spec), "change_id": spec.get("change_id")}


def validate_spec(
    root_or_spec: Path | dict[str, Any],
    path_or_schema: Path | dict[str, Any] | None = None,
    *,
    gate: bool = True,
    route: dict[str, Any] | None = None,
    changed: list[str] | None = None,
    schema_only: bool = False,
    anchor=None,
) -> list[str] | dict[str, Any]:
    """Validate either the current path API or the historical in-memory adapter."""
    if isinstance(root_or_spec, dict):
        spec = root_or_spec
        if path_or_schema is not None and isinstance(path_or_schema, dict):
            validate_schema(spec, path_or_schema, path_or_schema)
            if schema_only:
                return {"ok": True, "digest": canonical_spec_digest(spec), "change_id": spec.get("change_id")}
        return _validate_document(spec, gate=gate and not schema_only,anchor=anchor)
    root = Path(root_or_spec)
    if not isinstance(path_or_schema, Path):
        raise TypeError("path must be a Path")
    try:
        if anchor is not None:
            relative = _native_spec_relative(root,path_or_schema,anchor)
            spec = _parse_canonical_json(anchor.read(relative,MAX_SPEC_BYTES),path_or_schema)
        else:
            spec = load_spec(path_or_schema, allow_legacy=False)
        _validate_document(spec, gate=gate, root=root,anchor=anchor)
    except SpecError as exc:
        return [f"{path_or_schema}: {exc}"]
    except (OSError,ValueError) as exc:
        if anchor is None:
            raise
        return [f'{path_or_schema}: native spec input unavailable ({type(exc).__name__})']
    if route and (route.get('context') or {}).get('version') == 2:
        from .state import get_active_change
        active = get_active_change(root, anchor=anchor) or {}
        if path_or_schema == root / str(active.get('path','')) / 'change-spec.yaml':
            try:
                from .intake_publication import require_intake_ready
                require_intake_ready(root,route,operation_class='spec-validation')
            except Exception:
                return ['semantic intake is not current and ready']
    return []


def generate_spec(route: dict[str, Any]) -> dict[str, Any]:
    def route_text(value: Any) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, (dict, list, tuple, bool, int, float)) or value is None:
            return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        return str(value)

    risk_name = route_text(route.get("risk") or "low")
    return {
        "schema_version": 2,
        "change_id": route_text(route.get("change_id") or ""),
        "objective": {"id": "OBJ-001", "statement": route_text(route.get("task") or ""), "success_metric": UNKNOWN_TOKEN, "target": UNKNOWN_TOKEN},
        "risk": {"tier": RISK_MAP.get(risk_name, "green"), "domains": sorted({route_text(item) for item in route.get("domains") or []})},
        "acceptance_criteria": [],
        "invariants": [],
        "forbidden_outcomes": [],
        "contracts": {"openapi": [], "json_schema": [], "events": []},
        "observability": [],
        "rollback": {"strategy": "forward_fix", "maximum_steps": 1},
        "approvals": {"required_scopes": []},
    }


def summarize_spec(spec: dict[str, Any]) -> dict[str, Any]:
    coverage = criterion_coverage(spec)
    return {
        "change_id": spec.get("change_id"),
        "objective": spec.get("objective"),
        "risk": spec.get("risk"),
        "digest": canonical_spec_digest(spec),
        # Preserve the historical count fields; coverage_by_category is the
        # authoritative category-aware coverage view for new consumers.
        "acceptance_criteria": coverage["criterion_total"],
        "invariants": coverage["categories"]["invariants"]["criterion_total"],
        "forbidden_outcomes": coverage["categories"]["forbidden_outcomes"]["criterion_total"],
        "unmapped": coverage["unmapped_ids"],
        "coverage_by_category": coverage["categories"],
        "coverage_all": {
            "criterion_total": coverage["all_criterion_total"],
            "criterion_mapped": coverage["all_criterion_mapped"],
            "unmapped_ids": coverage["all_unmapped_ids"],
        },
    }


def map_evidence(spec: dict[str, Any]) -> dict[str, list[str]]:
    return {str(item.get("id")): [_evidence_value(ev) for ev in item.get("evidence") or []] for item in spec.get("acceptance_criteria") or []}
