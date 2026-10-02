"""Finite asserted-snapshot alias and delegation model, never live DNS."""

from collections import defaultdict
from .contracts import Gap, Location
from .names import name_id, wire, within


class Zone:
    def __init__(self, origin, source, records, complete):
        self.origin = origin
        self.source = source
        self.records = records
        self.complete = complete
        self.valid = True
        self.by_owner = defaultdict(lambda: defaultdict(list))
        self.nodes = {origin}
        self.cuts = {}
        self.dnames = set()
        self.blocked_cuts = set()
        for record in records:
            self.by_owner[record.owner][record.kind].append(record)
            if record.kind == "NS" and within(record.owner, origin, strict=True):
                self.cuts.setdefault(record.owner, []).append(record)
            if record.kind == "DNAME":
                self.dnames.add(record.owner)

    def location(self):
        return Location(self.source)


def ancestors(name, origin):
    return [name[index:] for index in range(len(name) - len(origin), -1, -1)]


class Model:
    def __init__(self, zones, ledger, entry):
        self.zones = {zone.origin: zone for zone in zones}
        self.ledger = ledger
        self.entry = entry

    def fail(self, zone, code, record=None, **details):
        zone.valid = False
        self.ledger.add("FAIL", code, record.location if record else zone.location(), **details)

    def lint(self):
        record_count, node_count = 0, 0
        for zone in self.zones.values():
            node_count += 1
            if node_count > self.ledger.limits.nodes:
                raise Gap("node_budget_exceeded", zone.location())
            record_count += len(zone.records)
            if record_count > self.ledger.limits.records:
                raise Gap("total_record_budget_exceeded", zone.location())
            for record in zone.records:
                self.ledger.step(record.location)
                if not within(record.owner, zone.origin):
                    self.fail(zone, "owner_outside_asserted_zone", record)
                    continue
                for node in ancestors(record.owner, zone.origin):
                    self.ledger.step(record.location)
                    if node not in zone.nodes:
                        zone.nodes.add(node)
                        node_count += 1
                        if node_count > self.ledger.limits.nodes:
                            raise Gap("node_budget_exceeded", record.location)
                if record.kind in ("CNAME", "DNAME") and not within(record.data[0], self.entry):
                    self.ledger.add("OPEN", "external_alias_target", record.location)
                if record.owner and record.owner[0] == b"*":
                    zone.complete = False
                    self.ledger.add("OPEN", "wildcard_semantics_unsupported", record.location)
            apex = zone.by_owner.get(zone.origin, {})
            if zone.complete and len({record.data for record in apex.get("SOA", [])}) != 1:
                self.fail(zone, "exactly_one_apex_soa_required")
            if zone.complete and not apex.get("NS"):
                self.fail(zone, "apex_ns_required")
            for owner, kinds in zone.by_owner.items():
                seen = set()
                for kind, records in kinds.items():
                    ttl_set = {record.ttl for record in records}
                    if len(ttl_set) > 1:
                        self.fail(zone, "rrset_ttl_conflict", records[0])
                    for record in records:
                        self.ledger.step(record.location)
                        key = (kind, record.data)
                        if key in seen:
                            self.ledger.add("INFO", "duplicate_record", record.location)
                        seen.add(key)
                    if kind == "SOA" and owner != zone.origin:
                        self.fail(zone, "soa_not_at_apex", records[0])
                if "CNAME" in kinds:
                    records = kinds["CNAME"]
                    if len({r.data for r in records}) != 1 or len(kinds) != 1:
                        self.fail(zone, "cname_conflicting_rrset", records[0])
                if "DNAME" in kinds:
                    records = kinds["DNAME"]
                    if len({r.data for r in records}) != 1:
                        self.fail(zone, "dname_multiple_targets", records[0])
                    if not owner:
                        zone.complete = False
                        self.ledger.add("OPEN", "root_dname_unsupported", records[0].location)
                    for record in records:
                        if within(record.data[0], owner):
                            self.fail(zone, "dname_target_at_or_below_owner", record)
                    for descendant, descendant_kinds in zone.by_owner.items():
                        self.ledger.step(records[0].location)
                        if within(descendant, owner, strict=True):
                            candidate = next(iter(descendant_kinds.values()))[0]
                            self.fail(zone, "data_occluded_by_dname", candidate)
            self._delegations(zone)
        self._ns_aliases()
        self._cname_cycles()

    def _ns_target_zone(self, target, location):
        """Find authority through entry cuts; parent glue never proves alias absence."""
        if not within(target, self.entry):
            raise Gap("ns_target_outside_entry", location)
        zone = self.zones[self.entry]
        while True:
            self.ledger.step(location)
            if not zone.complete:
                raise Gap("ns_target_authority_incomplete", location)
            child = None
            for ancestor in ancestors(target, zone.origin):
                self.ledger.step(location)
                if ancestor in zone.cuts:
                    if ancestor in zone.blocked_cuts:
                        raise Gap("ns_target_delegation_unresolved", location)
                    child = self.zones.get(ancestor)
                    if child is None:
                        raise Gap("ns_target_delegation_unresolved", location)
                    break
                if ancestor != target and ancestor in zone.dnames:
                    raise Gap("ns_target_dname_projection_unsupported", location)
            if child is None:
                return zone
            # A cut is a strict descendant, so origin depth grows on every iteration.
            zone = child

    def _ns_aliases(self):
        for zone in self.zones.values():
            for record in zone.records:
                if record.kind != "NS" or not within(record.owner, zone.origin):
                    continue
                try:
                    try:
                        source_authority = self._ns_target_zone(zone.origin, record.location)
                    except Gap as gap:
                        if gap.code == "work_budget_exceeded":
                            raise
                        raise Gap("ns_source_zone_unreachable", record.location) from gap
                    if source_authority is not zone:
                        raise Gap("ns_source_zone_unreachable", record.location)
                    authority = self._ns_target_zone(record.data[0], record.location)
                except Gap as gap:
                    # Work exhaustion stops the whole model instead of doing unbounded scans.
                    if gap.code == "work_budget_exceeded":
                        raise
                    self.ledger.add("OPEN", gap.code, gap.location,
                                    target_sha256=name_id(record.data[0]))
                    continue
                aliases = authority.by_owner.get(record.data[0], {}).get("CNAME", [])
                if aliases:
                    alias = aliases[0]
                    self.fail(zone, "ns_target_is_cname", record,
                              target_sha256=name_id(record.data[0]),
                              alias_record_sha256=alias.identity(),
                              alias_location=alias.location.report())

    def _delegations(self, zone):
        for owner, records in zone.cuts.items():
            self.ledger.step(records[0].location)
            higher = []
            for cut in zone.cuts:
                self.ledger.step(records[0].location)
                if within(owner, cut, strict=True):
                    higher.append(cut)
            if higher:
                self.fail(zone, "nested_parent_delegation_data", records[0])
                continue
            targets = {r.data[0] for r in records}
            child = self.zones.get(owner)
            if child is None:
                zone.blocked_cuts.add(owner)
                self.ledger.add("OPEN", "delegated_zone_snapshot_missing", records[0].location)
            elif not child.complete:
                zone.blocked_cuts.add(owner)
                self.ledger.add("OPEN", "delegated_zone_snapshot_incomplete", records[0].location)
            else:
                child_ns = child.by_owner.get(owner, {}).get("NS", [])
                if {r.data[0] for r in child_ns} != targets:
                    zone.blocked_cuts.add(owner)
                    self.fail(zone, "parent_child_ns_set_conflict", records[0])
            for record in records:
                target = record.data[0]
                if within(target, owner):
                    addresses = zone.by_owner.get(target, {})
                    if not addresses.get("A") and not addresses.get("AAAA"):
                        zone.blocked_cuts.add(owner)
                        self.fail(zone, "required_in_domain_glue_missing", record)
            for candidate in zone.records:
                self.ledger.step(candidate.location)
                if within(candidate.owner, owner, strict=True):
                    allowed_glue = candidate.owner in targets and candidate.kind in ("A", "AAAA")
                    if not allowed_glue:
                        self.fail(zone, "non_glue_parent_data_below_cut", candidate)
                elif candidate.owner == owner and candidate.kind not in ("NS", "A", "AAAA"):
                    self.fail(zone, "non_delegation_parent_data_at_cut", candidate)
                elif candidate.owner == owner and candidate.kind in ("A", "AAAA") and owner not in targets:
                    self.fail(zone, "non_glue_parent_data_at_cut", candidate)

    def _cname_cycles(self):
        # A graph of explicit authoritative snapshot edges, not all possible queries.
        edges = {}
        for zone in self.zones.values():
            for owner, kinds in zone.by_owner.items():
                if "CNAME" not in kinds or not within(owner, zone.origin):
                    continue
                hidden = False
                for cut in zone.cuts:
                    self.ledger.step(kinds["CNAME"][0].location)
                    hidden |= within(owner, cut)
                for ancestor in sorted(zone.dnames):
                    self.ledger.step(kinds["CNAME"][0].location)
                    if within(owner, ancestor, strict=True):
                        hidden = True
                if hidden:
                    continue
                record = kinds["CNAME"][0]
                edges[(zone.origin, owner)] = (record.data[0], record)
        done = set()
        for start in edges:
            node, path, positions = start, [], {}
            while node in edges and node not in done:
                self.ledger.step(edges[node][1].location)
                if node in positions:
                    record = edges[node][1]
                    self.ledger.add("FAIL", "explicit_cname_graph_cycle", record.location,
                                    cycle_records=len(path) - positions[node])
                    break
                positions[node] = len(path)
                path.append(node)
                target, _ = edges[node]
                # Stay within the asserted zone: cross-zone reachability belongs to query paths.
                node = (node[0], target)
            done.update(path)

    def query(self, entry, name, kind, expectation, index):
        result = {"query_id": index, "name_sha256": name_id(name), "type": kind,
                  "expect": expectation, "state": "OPEN", "outcome": "UNKNOWN", "path": []}
        seen, zone = set(), self.zones[entry]
        try:
            for _ in range(self.ledger.limits.hops):
                self.ledger.step(zone.location())
                if not within(name, entry):
                    raise Gap("external_query_or_alias_target", zone.location())
                if not zone.complete or not zone.valid:
                    raise Gap("query_zone_incomplete_or_invalid", zone.location())
                state = (zone.origin, name, kind)
                if state in seen:
                    self.ledger.add("FAIL", "query_alias_loop", zone.location(), query_id=index)
                    result["outcome"] = "LOOP"
                    break
                seen.add(state)
                redirect = False
                for ancestor in ancestors(name, zone.origin):
                    self.ledger.step(zone.location())
                    if ancestor in zone.cuts:
                        records = zone.cuts[ancestor]
                        result["path"].append(self._edge("REFERRAL", records[0], name))
                        if ancestor in zone.blocked_cuts:
                            raise Gap("query_delegation_unresolved", records[0].location)
                        zone = self.zones[ancestor]
                        redirect = True
                        break
                    kinds = zone.by_owner.get(ancestor, {})
                    if ancestor != name and "DNAME" in kinds:
                        record = kinds["DNAME"][0]
                        new_name = name[:len(name) - len(ancestor)] + record.data[0]
                        result["path"].append(self._edge("DNAME", record, name))
                        if len(wire(new_name)) > 255:
                            self.ledger.add("FAIL", "dname_substitution_name_overflow", record.location,
                                            query_id=index)
                            result["outcome"] = "YXDOMAIN"
                        elif kind == "CNAME":
                            result["outcome"] = "RESOLVED_SYNTHESIZED_CNAME"
                        else:
                            name, zone = new_name, self.zones[entry]
                            redirect = True
                        break
                if result["outcome"] != "UNKNOWN":
                    break
                if redirect:
                    continue
                kinds = zone.by_owner.get(name, {})
                if "CNAME" in kinds and kind != "CNAME":
                    record = kinds["CNAME"][0]
                    result["path"].append(self._edge("CNAME", record, name))
                    name, zone = record.data[0], self.zones[entry]
                    continue
                if kinds.get(kind):
                    result["path"].append(self._edge("ANSWER", kinds[kind][0], name))
                    result["outcome"] = "RESOLVED"
                else:
                    result["outcome"] = "NODATA" if name in zone.nodes else "NXDOMAIN"
                break
            else:
                raise Gap("query_hop_budget_exceeded", zone.location())
            resolved = result["outcome"] in ("RESOLVED", "RESOLVED_SYNTHESIZED_CNAME")
            matches = resolved == (expectation == "RESOLVES")
            result["state"] = "PASS" if matches else "FAIL"
            self.ledger.add(result["state"], "query_property_satisfied" if matches else
                            "query_property_failed", zone.location(), query_id=index)
        except Gap as gap:
            self.ledger.add("OPEN", gap.code, gap.location, query_id=index)
        return result

    @staticmethod
    def _edge(action, record, name):
        return {"action": action, "record_id": record.index, **record.location.report(),
                "record_sha256": record.identity(), "name_sha256": name_id(name)}
