"""Strict finite manifests, without include expansion or discovered files."""

import json
from .contracts import Gap, Location
from .names import parse_name
from .parser import SUPPORTED


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Gap("duplicate_manifest_key")
        result[key] = value
    return result


def _name(value, limits):
    if not isinstance(value, str) or len(value) > limits.token_bytes:
        raise Gap("invalid_manifest_name")
    try:
        raw = value.encode("ascii")
    except UnicodeError:
        raise Gap("unsupported_manifest_name_encoding") from None
    return parse_name(raw, (), Location(), absolute=True)


def load_manifest(raw, limits):
    depth, quoted, escaped = 0, False, False
    for value in raw:
        if quoted:
            if escaped:
                escaped = False
            elif value == 92:
                escaped = True
            elif value == 34:
                quoted = False
        elif value == 34:
            quoted = True
        elif value in (91, 123):
            depth += 1
            if depth > limits.nesting:
                raise Gap("manifest_nesting_budget_exceeded")
        elif value in (93, 125):
            depth -= 1
    try:
        text = raw.decode("utf-8")
        doc = json.loads(text, object_pairs_hook=_object,
                         parse_constant=lambda _: (_ for _ in ()).throw(Gap("invalid_json_constant")))
    except json.JSONDecodeError as error:
        prefix = text[:error.pos].encode("utf-8")
        column = len(prefix.rsplit(b"\n", 1)[-1]) + 1
        raise Gap("invalid_manifest_json", Location(0, error.lineno, column, len(prefix))) from None
    except UnicodeDecodeError as error:
        prefix = raw[:error.start]
        raise Gap("invalid_manifest_encoding", Location(0, prefix.count(b"\n") + 1,
                  len(prefix.rsplit(b"\n", 1)[-1]) + 1, error.start)) from None
    except (UnicodeError, ValueError, RecursionError):
        raise Gap("invalid_manifest_json") from None
    expected_keys = {"schema_version", "entry_zone", "zones", "queries"}
    if not isinstance(doc, dict) or set(doc) != expected_keys:
        raise Gap("invalid_manifest_schema")
    if type(doc["schema_version"]) is not int or doc["schema_version"] != 1:
        raise Gap("unsupported_manifest_version")
    entries, queries = doc["zones"], doc["queries"]
    if not isinstance(entries, list) or not entries or len(entries) + 1 > limits.files:
        raise Gap("invalid_or_over_budget_zone_entries")
    if not isinstance(queries, list) or len(queries) > limits.queries:
        raise Gap("invalid_or_over_budget_queries")
    zones, seen = [], set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"origin", "file"}:
            raise Gap("invalid_zone_metadata")
        origin = _name(entry["origin"], limits)
        if origin in seen:
            raise Gap("multiple_snapshots_per_origin_unsupported")
        seen.add(origin)
        if not isinstance(entry["file"], str) or len(entry["file"]) > 4096:
            raise Gap("invalid_zone_metadata")
        zones.append((origin, entry["file"]))
    entry_zone = _name(doc["entry_zone"], limits)
    if entry_zone not in seen:
        raise Gap("missing_entry_zone")
    normalized_queries = []
    for query in queries:
        if not isinstance(query, dict) or set(query) != {"name", "type", "expect"}:
            raise Gap("invalid_query_property")
        kind, expectation = query["type"], query["expect"]
        if (not isinstance(kind, str) or not isinstance(expectation, str)
                or kind not in SUPPORTED or expectation not in ("RESOLVES", "NOT_RESOLVES")):
            raise Gap("unsupported_query_property")
        normalized_queries.append((_name(query["name"], limits), kind, expectation))
    return entry_zone, zones, normalized_queries
