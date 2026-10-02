"""Public read-only review entry point."""

import hashlib
from .contracts import Gap, Ledger, Limits, Location
from .files import Reader
from .manifest import load_manifest
from .model import Model, Zone
from .names import name_id
from .parser import parse_zone


def review_manifest(manifest, *, root, limits=None):
    if limits is None:
        limits = Limits()
    if not isinstance(limits, Limits):
        raise TypeError("Limits_required")
    ledger, sources, queries, reader = Ledger(limits), [], [], None
    try:
        reader = Reader(root, limits)
        raw = reader.read(manifest)
        sources.append({"source_id": 0, "role": "manifest", "bytes": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest()})
        entry, zone_entries, query_entries = load_manifest(raw, limits)
        zones = []
        for source, (origin, path) in enumerate(zone_entries, 1):
            try:
                raw = reader.read(path)
            except (Gap, OSError, UnicodeError) as error:
                ledger.add("OPEN", error.code if isinstance(error, Gap) else "local_file_read_error",
                           Location(source))
                zones.append(Zone(origin, source, [], False))
                continue
            sources.append({"source_id": source, "role": "zone", "bytes": len(raw),
                            "sha256": hashlib.sha256(raw).hexdigest(),
                            "origin_sha256": name_id(origin)})
            records, gap = parse_zone(raw, origin, source, limits)
            if gap:
                ledger.add("OPEN", gap.code, gap.location)
            zones.append(Zone(origin, source, records, gap is None))
        model = Model(zones, ledger, entry)
        model.lint()
        for index, (name, kind, expectation) in enumerate(query_entries, 1):
            queries.append(model.query(entry, name, kind, expectation, index))
    except Gap as gap:
        ledger.add("OPEN", gap.code, gap.location)
    except (OSError, UnicodeError):
        ledger.add("OPEN", "local_file_read_error")
    finally:
        if reader is not None:
            reader.close()
    return ledger.finish(sources, queries)
