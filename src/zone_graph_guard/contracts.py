"""Finite review budgets and a source-private diagnostic ledger."""

from dataclasses import dataclass, fields
import json


@dataclass(frozen=True)
class Limits:
    total_bytes: int = 2_097_152
    file_bytes: int = 262_144
    files: int = 32
    records: int = 8192
    tokens: int = 65536
    token_bytes: int = 4096
    nesting: int = 16
    nodes: int = 32768
    queries: int = 256
    hops: int = 64
    steps: int = 200000
    findings: int = 256
    report_bytes: int = 262144

    def __post_init__(self):
        for field in fields(self):
            value = getattr(self, field.name)
            if type(value) is not int or value < 1:
                raise ValueError("positive_integer_limits_required")
        if self.report_bytes < 2048:
            raise ValueError("report_budget_below_minimum")


@dataclass(frozen=True)
class Location:
    source: int = 0
    line: int = 1
    column: int = 1
    byte_offset: int = 0

    def report(self):
        return {"source_id": self.source, "line": self.line,
                "column": self.column, "byte_offset": self.byte_offset}


class Gap(Exception):
    def __init__(self, code, location=None):
        self.code = code
        self.location = location or Location()
        super().__init__(code)


class Ledger:
    def __init__(self, limits):
        self.limits = limits
        self.items = []
        self.failures = 0
        self.gaps = 0
        self.dropped = 0
        self.steps = 0

    def add(self, state, code, location=None, **details):
        self.failures += state == "FAIL"
        self.gaps += state == "OPEN"
        item = {"state": state, "code": code,
                **(location or Location()).report(), **details}
        if len(self.items) < self.limits.findings:
            self.items.append(item)
        else:
            self.dropped += 1

    def step(self, location=None):
        self.steps += 1
        if self.steps > self.limits.steps:
            raise Gap("work_budget_exceeded", location)

    def finish(self, sources, queries):
        if self.dropped:
            self.gaps += 1
        result = {
            "schema_version": 1, "project": "ZoneGraphGuard",
            "status": "FAIL" if self.failures else "OPEN" if self.gaps else "PASS",
            "complete_for_selected_model": not bool(self.gaps),
            "findings": self.items, "failure_count": self.failures,
            "open_count": self.gaps, "omitted_findings": self.dropped,
            "sources": sources, "queries": queries,
            "external": {"live_dns": "OPEN", "all_possible_queries": "OPEN",
                         "multiple_authoritative_servers": "OPEN", "dnssec": "OPEN",
                         "cvp_eligibility": "OPEN"},
        }
        if len(encode_report(result)) > self.limits.report_bytes:
            result.update(status="FAIL" if self.failures else "OPEN",
                          complete_for_selected_model=False, queries=[], sources=[],
                          findings=[{"state": "OPEN", "code": "report_budget_exceeded",
                                     **Location().report()}],
                          open_count=self.gaps + 1,
                          omitted_findings=len(self.items) + self.dropped)
        return result


def encode_report(report):
    return (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode()
