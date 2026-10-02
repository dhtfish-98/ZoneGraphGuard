import copy
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from zone_graph_guard import Limits, review_manifest
from zone_graph_guard.contracts import Gap, Location, encode_report
from zone_graph_guard.names import name_id, parse_name, wire
from zone_graph_guard.parser import parse_zone

BASE = b"""$TTL 1h
@ IN SOA ns hostmaster ( 1 1h 30m 1w 1h )
@ NS ns
ns A 192.0.2.1
www A 192.0.2.2
"""
ROOT = b"""$TTL 60
@ SOA ns. hostmaster. 1 60 60 60 60
@ NS ns.
ns. A 192.0.2.1
"""


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.doc = {"schema_version": 1, "entry_zone": "example.",
                    "zones": [{"origin": "example.", "file": "example.zone"}],
                    "queries": [{"name": "www.example.", "type": "A", "expect": "RESOLVES"}]}
        self.zone = BASE

    def run_review(self, zone=None, doc=None, limits=None):
        (self.root / "example.zone").write_bytes(self.zone if zone is None else zone)
        (self.root / "manifest.json").write_text(json.dumps(self.doc if doc is None else doc))
        before = {p.name: p.read_bytes() for p in self.root.iterdir() if p.is_file() and not p.is_symlink()}
        result = review_manifest("manifest.json", root=str(self.root), limits=limits)
        after = {p.name: p.read_bytes() for p in self.root.iterdir() if p.is_file() and not p.is_symlink()}
        self.assertEqual(before, after)
        return result

    def codes(self, result):
        return {item["code"] for item in result["findings"]}

    def query(self, name, kind="A", expect="RESOLVES"):
        self.doc["queries"] = [{"name": name, "type": kind, "expect": expect}]

    def test_valid_single_snapshot(self):
        report = self.run_review()
        self.assertEqual(report["status"], "PASS")
        self.assertTrue(report["complete_for_selected_model"])
        self.assertEqual(report["queries"][0]["outcome"], "RESOLVED")
        self.assertEqual(report["external"]["live_dns"], "OPEN")

    def test_case_fold_and_decimal_escaped_label(self):
        self.query("WWW.ExAmPlE.")
        self.assertEqual(self.run_review()["status"], "PASS")
        self.query(r"w\046w.example.")
        report = self.run_review(BASE + b"w\\046w A 192.0.2.5\n")
        self.assertEqual(report["status"], "PASS")
        self.assertNotEqual(parse_name(b"w\\046w.example.", (), Location()),
                            parse_name(b"w.w.example.", (), Location()))

    def test_quoted_comments_and_escaped_delimiters(self):
        data = BASE + b'txt TXT "not;comment (x) \\"quoted\\"" "\\059\\040\\041" ;ignored\n'
        self.query("txt.example.", "TXT")
        report = self.run_review(data)
        self.assertEqual(report["status"], "PASS")
        records, error = parse_zone(data, (b"example",), 1, Limits())
        self.assertIsNone(error)
        self.assertEqual(records[-1].data, (b'not;comment (x) "quoted"', b";()"))

    def test_owner_omission_preserves_absolute_previous_owner(self):
        data = BASE + b"multi A 192.0.2.8\n$ORIGIN sub.example.\n  AAAA 2001:db8::8\n"
        self.query("multi.example.", "AAAA")
        self.assertEqual(self.run_review(data)["status"], "PASS")

    def test_relative_origin_and_ttl_order(self):
        data = BASE + b"$ORIGIN sub\nrelative IN 2h30m A 192.0.2.8\nother 60 IN A 192.0.2.9\n"
        self.query("relative.sub.example.")
        self.assertEqual(self.run_review(data)["status"], "PASS")
        records, error = parse_zone(data, (b"example",), 1, Limits())
        self.assertIsNone(error)
        self.assertEqual(records[-2].ttl, 9000)

    def test_explicit_ttl_without_default(self):
        data = BASE.replace(b"$TTL 1h\n", b"").replace(b"@ IN SOA", b"@ 60 IN SOA").replace(
            b"@ NS", b"@ 60 NS").replace(b"ns A", b"ns 60 A").replace(b"www A", b"www 60 A")
        self.assertEqual(self.run_review(data)["status"], "PASS")

    def test_legacy_ttl_inheritance_is_open(self):
        report = self.run_review(BASE.replace(b"$TTL 1h\n", b""))
        self.assertEqual(report["status"], "OPEN")
        self.assertIn("explicit_or_default_ttl_required", self.codes(report))

    def test_crlf_and_byte_offsets(self):
        data = BASE.replace(b"\n", b"\r\n") + b"alias CNAME www\r\n"
        self.query("alias.example.")
        report = self.run_review(data)
        self.assertEqual(report["status"], "PASS")
        edge = report["queries"][0]["path"][0]
        self.assertEqual(edge["byte_offset"], data.index(b"alias"))
        self.assertEqual(edge["line"], 6)

    def test_cname_chain_and_type_queries(self):
        data = BASE + b"a CNAME b\nb CNAME www\n"
        self.query("a.example.")
        report = self.run_review(data)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual([p["action"] for p in report["queries"][0]["path"]], ["CNAME", "CNAME", "ANSWER"])
        self.query("a.example.", "CNAME")
        self.assertEqual(len(self.run_review(data)["queries"][0]["path"]), 1)

    def test_cname_cycle(self):
        self.query("a.example.", expect="NOT_RESOLVES")
        report = self.run_review(BASE + b"a CNAME b\nb CNAME a\n")
        self.assertEqual(report["status"], "FAIL")
        self.assertIn("explicit_cname_graph_cycle", self.codes(report))
        self.assertEqual(report["queries"][0]["outcome"], "LOOP")

    def test_cname_conflicting_records(self):
        self.query("www.example.")
        for suffix in (b"www CNAME ns\n", b"a CNAME www\na CNAME ns\n"):
            with self.subTest(suffix=suffix):
                report = self.run_review(BASE + suffix)
                self.assertEqual(report["status"], "FAIL")
                self.assertIn("cname_conflicting_rrset", self.codes(report))
                self.assertEqual(report["queries"][0]["state"], "OPEN")

    def test_dname_strict_descendant_substitution(self):
        data = BASE + b"old DNAME new\na.new A 192.0.2.8\nold A 192.0.2.9\n"
        self.query("a.old.example.")
        report = self.run_review(data)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["queries"][0]["path"][0]["action"], "DNAME")
        self.query("old.example.")
        self.assertEqual(self.run_review(data)["queries"][0]["path"][0]["action"], "ANSWER")
        self.query("old.example.", "DNAME")
        self.assertEqual(self.run_review(data)["status"], "PASS")

    def test_dname_synthesized_cname(self):
        self.query("a.old.example.", "CNAME")
        report = self.run_review(BASE + b"old DNAME new\n")
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["queries"][0]["outcome"], "RESOLVED_SYNTHESIZED_CNAME")

    def test_dname_cycle(self):
        self.query("x.a.example.", expect="NOT_RESOLVES")
        report = self.run_review(BASE + b"a DNAME b\nb DNAME a\n")
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["queries"][0]["outcome"], "LOOP")

    def test_dname_occluded_and_multiple_targets(self):
        for suffix, code in ((b"old DNAME new\na.old A 192.0.2.9\n", "data_occluded_by_dname"),
                             (b"old DNAME new\nold DNAME other\n", "dname_multiple_targets"),
                             (b"old DNAME sub.old\n", "dname_target_at_or_below_owner")):
            with self.subTest(code=code):
                report = self.run_review(BASE + suffix)
                self.assertEqual(report["status"], "FAIL")
                self.assertIn(code, self.codes(report))

    def test_dname_overflow(self):
        target = b".".join([b"a" * 63, b"b" * 63, b"c" * 63, b"d" * 50]) + b"."
        self.doc["entry_zone"] = self.doc["zones"][0]["origin"] = "."
        self.query("p" * 63 + ".old.", expect="NOT_RESOLVES")
        report = self.run_review(ROOT + b"old. DNAME " + target + b"\n")
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["queries"][0]["outcome"], "YXDOMAIN")

    def test_external_alias_is_open_without_network(self):
        self.query("outside.example.")
        with patch.object(socket, "getaddrinfo", side_effect=AssertionError("network forbidden")):
            report = self.run_review(BASE + b"outside CNAME external.invalid.\n")
        self.assertEqual(report["status"], "OPEN")
        self.assertIn("external_alias_target", self.codes(report))
        self.assertEqual(report["queries"][0]["state"], "OPEN")

    def test_external_cname_record_query_still_has_global_gap(self):
        self.query("outside.example.", "CNAME")
        report = self.run_review(BASE + b"outside CNAME external.invalid.\n")
        self.assertEqual(report["status"], "OPEN")
        self.assertEqual(report["queries"][0]["state"], "PASS")

    def test_empty_nonterminal_and_absent_name(self):
        data = BASE + b"a.empty A 192.0.2.9\n"
        self.query("empty.example.", expect="NOT_RESOLVES")
        self.assertEqual(self.run_review(data)["queries"][0]["outcome"], "NODATA")
        self.query("missing.example.", expect="NOT_RESOLVES")
        self.assertEqual(self.run_review(data)["queries"][0]["outcome"], "NXDOMAIN")

    def test_failed_property_and_single_record_mutation(self):
        self.assertEqual(self.run_review()["status"], "PASS")
        report = self.run_review(BASE.replace(b"www A 192.0.2.2\n", b""))
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["queries"][0]["outcome"], "NXDOMAIN")

    def delegation(self, parent_ns=b"ns.child", child_ns=b"ns", glue=True):
        self.doc["zones"].append({"origin": "child.example.", "file": "child.zone"})
        child = BASE.replace(b"@ NS ns", b"@ NS " + child_ns)
        (self.root / "child.zone").write_bytes(child)
        self.query("www.child.example.")
        return BASE + b"child NS " + parent_ns + b"\n" + (
            b"ns.child A 192.0.2.1\n" if glue else b"")

    def test_delegation_glue_and_child_source_identity(self):
        report = self.run_review(self.delegation())
        self.assertEqual(report["status"], "PASS")
        path = report["queries"][0]["path"]
        self.assertEqual([p["action"] for p in path], ["REFERRAL", "ANSWER"])
        self.assertEqual([p["source_id"] for p in path], [1, 2])

    def test_parent_child_ns_conflict(self):
        report = self.run_review(self.delegation(child_ns=b"other"))
        self.assertEqual(report["status"], "FAIL")
        self.assertIn("parent_child_ns_set_conflict", self.codes(report))

    def test_missing_required_glue_and_child_mutation(self):
        report = self.run_review(self.delegation(glue=False))
        self.assertEqual(report["status"], "FAIL")
        self.assertIn("required_in_domain_glue_missing", self.codes(report))
        self.doc["zones"] = self.doc["zones"][:1]
        data = self.delegation()
        (self.root / "child.zone").write_bytes(BASE.replace(b"www A 192.0.2.2\n", b""))
        report = self.run_review(data)
        self.assertEqual(report["queries"][0]["outcome"], "NXDOMAIN")
        self.assertEqual(report["status"], "FAIL")

    def test_out_of_domain_ns_does_not_require_in_domain_glue(self):
        data = self.delegation(parent_ns=b"ns.example.", child_ns=b"ns.example.", glue=False)
        report = self.run_review(data)
        self.assertEqual(report["status"], "PASS")
        self.assertNotIn("required_in_domain_glue_missing", self.codes(report))

    def test_missing_delegated_zone_is_open(self):
        self.query("www.child.example.")
        report = self.run_review(BASE + b"child NS ns.child\nns.child A 192.0.2.1\n")
        self.assertEqual(report["status"], "OPEN")
        self.assertIn("delegated_zone_snapshot_missing", self.codes(report))
        self.assertEqual(report["queries"][0]["state"], "OPEN")

    def test_orphan_child_not_used_to_bypass_parent(self):
        self.delegation()
        report = self.run_review()
        self.assertEqual(report["queries"][0]["outcome"], "NXDOMAIN")
        self.assertEqual(report["status"], "FAIL")

    def test_parent_data_below_cut_cannot_be_answer(self):
        report = self.run_review(self.delegation() + b"www.child A 192.0.2.99\n")
        self.assertEqual(report["status"], "FAIL")
        self.assertIn("non_glue_parent_data_below_cut", self.codes(report))
        self.assertEqual(report["queries"][0]["state"], "OPEN")

    def test_ns_alias_and_nested_parent_delegations(self):
        report = self.run_review(self.delegation() + b"ns.child CNAME ns\n")
        self.assertEqual(report["status"], "FAIL")
        self.assertIn("non_glue_parent_data_below_cut", self.codes(report))
        self.assertNotIn("ns_target_is_cname", self.codes(report))
        self.doc["zones"] = self.doc["zones"][:1]
        report = self.run_review(self.delegation() + b"sub.child NS ns.child\n")
        self.assertIn("nested_parent_delegation_data", self.codes(report))

    def test_apex_ns_alias_and_authoritative_witness(self):
        data = BASE.replace(b"@ NS ns\n", b"@ NS alias\n") + b"alias CNAME ns\n"
        report = self.run_review(data)
        self.assertEqual(report["status"], "FAIL")
        finding = next(f for f in report["findings"] if f["code"] == "ns_target_is_cname")
        self.assertEqual(finding["byte_offset"], data.index(b"@ NS"))
        self.assertEqual(finding["alias_location"]["byte_offset"], data.index(b"alias CNAME"))
        self.assertEqual(finding["alias_location"]["source_id"], 1)
        self.assertEqual(self.run_review()["status"], "PASS")

    def test_child_apex_and_parent_cut_ns_alias_use_child_authority(self):
        parent = self.delegation()
        child = BASE.replace(b"ns A 192.0.2.1\n", b"ns CNAME actual\nactual A 192.0.2.1\n")
        (self.root / "child.zone").write_bytes(child)
        report = self.run_review(parent)
        self.assertEqual(report["status"], "FAIL")
        findings = [f for f in report["findings"] if f["code"] == "ns_target_is_cname"]
        self.assertEqual({f["source_id"] for f in findings}, {1, 2})
        self.assertEqual({f["alias_location"]["source_id"] for f in findings}, {2})
        self.assertEqual({f["alias_location"]["byte_offset"] for f in findings},
                         {child.index(b"ns CNAME")})

    def test_external_ns_target_is_open_without_network(self):
        with patch.object(socket, "getaddrinfo", side_effect=AssertionError("network forbidden")):
            report = self.run_review(BASE.replace(b"@ NS ns\n", b"@ NS ns.external.invalid.\n"))
        self.assertEqual(report["status"], "OPEN")
        self.assertIn("ns_target_outside_entry", self.codes(report))
        self.assertEqual(report["queries"][0]["state"], "PASS")

    def test_parent_cached_alias_without_child_cannot_prove_ns_alias(self):
        data = BASE + b"child NS ns.child\nns.child CNAME ns\n"
        report = self.run_review(data)
        self.assertEqual(report["status"], "FAIL")
        self.assertIn("non_glue_parent_data_below_cut", self.codes(report))
        self.assertIn("ns_target_delegation_unresolved", self.codes(report))
        self.assertNotIn("ns_target_is_cname", self.codes(report))

    def test_orphan_child_alias_never_bypasses_entry_authority(self):
        self.delegation()
        child = BASE.replace(b"ns A 192.0.2.1\n", b"ns CNAME actual\nactual A 192.0.2.1\n")
        (self.root / "child.zone").write_bytes(child)
        self.query("www.example.")
        report = self.run_review()
        self.assertEqual(report["status"], "OPEN")
        self.assertIn("ns_source_zone_unreachable", self.codes(report))
        self.assertEqual(report["queries"][0]["state"], "PASS")
        self.assertNotIn("ns_target_is_cname", self.codes(report))

    def test_ns_target_dname_descendant_is_open_owner_is_not_alias(self):
        suffix = b"old DNAME new\nnew A 192.0.2.9\n"
        report = self.run_review(BASE.replace(b"@ NS ns\n", b"@ NS ns.old\n") + suffix)
        self.assertEqual(report["status"], "OPEN")
        self.assertIn("ns_target_dname_projection_unsupported", self.codes(report))
        report = self.run_review(BASE.replace(b"@ NS ns\n", b"@ NS old\n") +
                                 suffix + b"old A 192.0.2.8\n")
        self.assertEqual(report["status"], "PASS")

    def test_ns_target_incomplete_authority_is_open(self):
        report = self.run_review(BASE + b"alias CNAME ns\nx HTTPS 1 .\n")
        self.assertEqual(report["status"], "OPEN")
        self.assertIn("ns_source_zone_unreachable", self.codes(report))
        self.assertNotIn("ns_target_is_cname", self.codes(report))

    def test_wildcard_is_open_not_fake_nxdomain(self):
        self.query("absent.example.", expect="NOT_RESOLVES")
        report = self.run_review(BASE + b"* A 192.0.2.9\n")
        self.assertEqual(report["status"], "OPEN")
        self.assertEqual(report["queries"][0]["outcome"], "UNKNOWN")

    def test_duplicates_and_ttl_conflict(self):
        report = self.run_review(BASE + b"www A 192.0.2.2\n")
        self.assertEqual(report["status"], "PASS")
        self.assertIn("duplicate_record", self.codes(report))
        report = self.run_review(BASE + b"www 60 A 192.0.2.3\n")
        self.assertEqual(report["status"], "FAIL")
        self.assertIn("rrset_ttl_conflict", self.codes(report))

    def test_duplicate_soa_is_one_normalized_rr(self):
        report = self.run_review(BASE + b"@ SOA ns hostmaster 1 1h 30m 1w 1h\n")
        self.assertEqual(report["status"], "PASS")
        self.assertIn("duplicate_record", self.codes(report))

    def test_apex_and_out_of_zone_checks(self):
        for data, code in ((BASE.replace(b"@ NS ns\n", b""), "apex_ns_required"),
                           (BASE.replace(b"@ IN SOA", b"other IN SOA"), "soa_not_at_apex"),
                           (BASE + b"outside.invalid. A 192.0.2.9\n", "owner_outside_asserted_zone")):
            with self.subTest(code=code):
                report = self.run_review(data)
                self.assertEqual(report["status"], "FAIL")
                self.assertIn(code, self.codes(report))

    def test_unknown_rr_and_directives_are_open(self):
        for suffix in (b"x HTTPS 1 .\n", b"$INCLUDE private.zone\n", b"$GENERATE 1-9 x$ A 192.0.2.1\n",
                       b"x CH TXT hello\n", b"$UNKNOWN secret\n"):
            with self.subTest(suffix=suffix):
                report = self.run_review(BASE + suffix)
                self.assertEqual(report["status"], "OPEN")
                self.assertEqual(report["queries"][0]["state"], "OPEN")

    def test_malformed_and_truncated_lexer(self):
        cases = (b'x TXT "unfinished', b'x TXT ( "ok"\n', b"x A 192.0.2.8 )\n",
                 b'x TXT foo"bar\n', b'x TXT "one"two\n', b"x A 192.0.2.8\r", b"x A \\\n")
        for suffix in cases:
            with self.subTest(suffix=suffix):
                report = self.run_review(BASE + suffix)
                self.assertEqual(report["status"], "OPEN")
                self.assertFalse(report["complete_for_selected_model"])

    def test_rdata_validation(self):
        cases = (b"x A 999.0.0.1\n", b"x AAAA 192.0.2.1\n", b"x AAAA fe80::1%eth0\n",
                 b"x MX 65536 mail\n", b"x CNAME two names\n", b"x SOA ns hm 4294967296 1 1 1 1\n",
                 b'x MX "1" ns\n', b"x TXT " + b"a" * 256 + b"\n")
        for suffix in cases:
            with self.subTest(suffix=suffix):
                self.assertEqual(self.run_review(BASE + suffix)["status"], "OPEN")

    def test_missing_rdata_location_is_the_rr_source(self):
        report = self.run_review(BASE + b"broken CNAME\n")
        finding = next(item for item in report["findings"] if item["code"] == "rdata_arity_error")
        self.assertEqual(finding["source_id"], 1)
        self.assertEqual(finding["line"], 6)
        self.assertEqual(finding["byte_offset"], len(BASE) + 7)

    def test_time_and_grouped_header_dialect_gaps(self):
        for suffix in (b"x 1h30 A 192.0.2.9\n", b"($TTL 60)\n", b"(x) A 192.0.2.9\n",
                       b"x (A) 192.0.2.9\n", b"$TTL " + b"0s" * 32 + b"\n"):
            self.assertEqual(self.run_review(BASE + suffix)["status"], "OPEN")

    def test_supported_mx_ptr_txt_and_ipv6(self):
        data = BASE + b'mx MX 10 mail\nptr PTR www\ntxt TXT ""\nv6 AAAA 2001:0db8::1\n'
        for name, kind in (("mx", "MX"), ("ptr", "PTR"), ("txt", "TXT"), ("v6", "AAAA")):
            self.query(name + ".example.", kind)
            self.assertEqual(self.run_review(data)["status"], "PASS")

    def test_name_length_and_escape_boundaries(self):
        for name in (b"a" * 64 + b".example.", b"a..example.", b"a\\25.example.",
                     b"a\\256.example.", b"a\\", b""):
            with self.subTest(name=name), self.assertRaises(Gap):
                parse_name(name, (), Location())
        name = parse_name(b"a\\000b.Example.", (), Location())
        self.assertEqual(name, (b"a\0b", b"example"))
        self.assertEqual(len(wire(name)), 13)

    def test_manifest_schema_unknown_and_wrong_types(self):
        for key, value in (("schema_version", True), ("schema_version", 2), ("zones", []),
                           ("zones", "private"), ("queries", {}), ("entry_zone", "relative")):
            doc = copy.deepcopy(self.doc)
            doc[key] = value
            with self.subTest(key=key, value=value):
                self.assertEqual(self.run_review(doc=doc)["status"], "OPEN")
        for key, value in (("type", []), ("expect", {}), ("type", "ANY"), ("name", "é.example.")):
            doc = copy.deepcopy(self.doc)
            doc["queries"][0][key] = value
            self.assertEqual(self.run_review(doc=doc)["status"], "OPEN")

    def test_manifest_missing_metadata_and_multiple_snapshots(self):
        for change in (lambda d: d["zones"][0].pop("origin"),
                       lambda d: d["zones"].append(d["zones"][0].copy()),
                       lambda d: d.update(entry_zone="missing."),
                       lambda d: d["queries"][0].pop("expect"),
                       lambda d: d.update(unknown=1)):
            doc = copy.deepcopy(self.doc)
            change(doc)
            self.assertEqual(self.run_review(doc=doc)["status"], "OPEN")

    def test_manifest_raw_delimiters_require_name_escapes(self):
        for name in ("space name.example.", "line\nname.example.", "semi;colon.example.", "del\x7fname.example."):
            self.query(name)
            self.assertEqual(self.run_review()["status"], "OPEN")
        self.query(r"space\032name.example.")
        self.assertEqual(self.run_review(BASE + b"space\\032name A 192.0.2.8\n")["status"], "PASS")

    def test_invalid_json_duplicates_and_deep_nesting(self):
        for raw in (b"", b'{"schema_version":1,"schema_version":1}', b"{", b"NaN", b"[" * 17):
            (self.root / "manifest.json").write_bytes(raw)
            report = review_manifest("manifest.json", root=str(self.root))
            self.assertEqual(report["status"], "OPEN")

    def test_json_syntax_and_encoding_numeric_positions(self):
        for raw, line, offset in ((b'{\n"secret": "\xc3\xa9",\n!}', 3, 18), (b'{\n"secret": "\xff"}', 2, 13)):
            (self.root / "manifest.json").write_bytes(raw)
            report = review_manifest("manifest.json", root=str(self.root))
            finding = report["findings"][0]
            self.assertEqual(report["status"], "OPEN")
            self.assertEqual(finding["line"], line)
            self.assertEqual(finding["byte_offset"], offset)
            self.assertNotIn(b"secret", encode_report(report))

    def test_missing_file_is_open_without_invented_structural_failure(self):
        (self.root / "manifest.json").write_text(json.dumps(self.doc))
        report = review_manifest("manifest.json", root=str(self.root))
        self.assertEqual(report["status"], "OPEN")
        self.assertEqual(report["failure_count"], 0)

    def test_paths_absolute_parent_url_stdin_and_symlinks(self):
        self.run_review()
        for path in ("../manifest.json", "/manifest.json", "https://invalid/x", "-", "a/../manifest.json", ""):
            self.assertEqual(review_manifest(path, root=str(self.root))["status"], "OPEN")
        (self.root / "link.json").symlink_to(self.root / "manifest.json")
        (self.root / "linkdir").symlink_to(self.root, target_is_directory=True)
        for path in ("link.json", "linkdir/manifest.json"):
            self.assertEqual(review_manifest(path, root=str(self.root))["status"], "OPEN")
        self.assertEqual(review_manifest("manifest.json", root=str(self.root / "linkdir"))["status"], "OPEN")

    def test_zone_path_escape_and_fifo_are_not_read(self):
        for path in ("../other.zone", "/tmp/other.zone", "https://invalid/zone"):
            doc = copy.deepcopy(self.doc)
            doc["zones"][0]["file"] = path
            self.assertEqual(self.run_review(doc=doc)["status"], "OPEN")
        os.mkfifo(self.root / "fifo")
        self.assertEqual(review_manifest("fifo", root=str(self.root))["status"], "OPEN")
        self.assertEqual(review_manifest("manifest.json", root="relative")["status"], "OPEN")

    def test_controlled_short_read(self):
        self.run_review()
        real_fdopen = os.fdopen

        class ShortRead:
            def __init__(self, *args):
                self.handle = real_fdopen(*args)
            def __enter__(self):
                self.handle.__enter__()
                return self
            def __exit__(self, *args):
                return self.handle.__exit__(*args)
            def read(self, size):
                return self.handle.read(size)[:-1]
            def fileno(self):
                return self.handle.fileno()

        with patch("zone_graph_guard.files.os.fdopen", ShortRead):
            report = review_manifest("manifest.json", root=str(self.root))
        self.assertEqual(report["status"], "OPEN")
        self.assertIn("input_changed_or_short_read", self.codes(report))

    def test_controlled_descriptor_identity_change(self):
        self.run_review()
        original, calls = os.fstat, 0

        def altered(fd):
            nonlocal calls
            calls += 1
            value = original(fd)
            if calls != 2:
                return value
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode")
            result = {field: getattr(value, field) for field in fields}
            result["st_ino"] += 1
            return SimpleNamespace(**result)

        with patch("zone_graph_guard.files.os.fstat", altered):
            report = review_manifest("manifest.json", root=str(self.root))
        self.assertEqual(report["status"], "OPEN")
        self.assertIn("input_changed_or_short_read", self.codes(report))

    def test_total_record_limit_across_two_zone_files(self):
        report = self.run_review(self.delegation(), limits=Limits(records=7))
        self.assertEqual(report["status"], "OPEN")
        self.assertIn("total_record_budget_exceeded", self.codes(report))

    def test_file_total_token_record_node_and_work_budgets(self):
        for limits, code in ((Limits(file_bytes=20), "file_byte_budget_exceeded"),
                             (Limits(total_bytes=200), "total_byte_budget_exceeded"),
                             (Limits(records=2), "record_budget_exceeded"),
                             (Limits(tokens=2), "token_budget_exceeded"),
                             (Limits(token_bytes=20), "token_byte_budget_exceeded"),
                             (Limits(nodes=1), "node_budget_exceeded"),
                             (Limits(steps=1), "work_budget_exceeded")):
            with self.subTest(code=code):
                report = self.run_review(BASE + b"x TXT " + b"a" * 21 + b"\n", limits=limits)
                self.assertEqual(report["status"], "OPEN")
                self.assertIn(code, self.codes(report))

    def test_nesting_query_and_hop_budgets(self):
        report = self.run_review(BASE + b"x TXT (( hello ))\n", limits=Limits(nesting=1))
        self.assertEqual(report["status"], "OPEN")
        self.doc["queries"] *= 2
        self.assertEqual(self.run_review(limits=Limits(queries=1))["status"], "OPEN")
        self.query("a.example.")
        report = self.run_review(BASE + b"a CNAME b\nb CNAME www\n", limits=Limits(hops=2))
        self.assertEqual(report["status"], "OPEN")
        self.assertIn("query_hop_budget_exceeded", self.codes(report))

    def test_invalid_library_limits_are_not_silently_defaulted(self):
        for value in (0, False, {}, "limits"):
            with self.assertRaises(TypeError):
                review_manifest("manifest.json", root=str(self.root), limits=value)
        for kwargs in ({"steps": False}, {"tokens": 0}, {"report_bytes": 100}):
            with self.assertRaises(ValueError):
                Limits(**kwargs)

    def test_ledger_and_output_budgets_preserve_known_failure(self):
        self.doc["queries"] *= 100
        self.doc["queries"][0]["name"] = "missing.example."
        report = self.run_review(limits=Limits(findings=1, report_bytes=2048))
        self.assertEqual(report["status"], "FAIL")
        self.assertGreater(report["failure_count"], 0)
        self.assertFalse(report["complete_for_selected_model"])
        self.assertLessEqual(len(encode_report(report)), 2048)

    def test_known_failure_is_retained_with_later_parse_gap(self):
        report = self.run_review(BASE + b"www CNAME ns\n$INCLUDE PRIVATE_SENTINEL\n")
        self.assertEqual(report["status"], "FAIL")
        self.assertIn("cname_conflicting_rrset", self.codes(report))
        self.assertGreater(report["open_count"], 0)

    def test_sensitive_source_values_are_not_echoed(self):
        self.query("PRIVATE_SENTINEL.example.", "TXT")
        self.doc["zones"][0]["file"] = "PRIVATE_SENTINEL.zone"
        (self.root / "PRIVATE_SENTINEL.zone").write_bytes(BASE + b'PRIVATE_SENTINEL TXT "PRIVATE_ACCOUNT_TOKEN"\n')
        report = self.run_review()
        output = encode_report(report)
        self.assertNotIn(b"PRIVATE", output)
        self.assertNotIn(str(self.root).encode(), output)
        self.assertEqual(report["status"], "PASS")

    def test_determinism_and_source_hashes(self):
        first, second = self.run_review(), self.run_review()
        self.assertEqual(encode_report(first), encode_report(second))
        self.assertEqual(first["sources"][1]["sha256"], hashlib.sha256(BASE).hexdigest())
        self.assertEqual(first["queries"][0]["name_sha256"], name_id((b"www", b"example")))

    def test_unescaped_nonascii_and_quoted_names_are_open(self):
        for suffix in (b"x\xff A 192.0.2.8\n", b'"quoted" A 192.0.2.8\n', b"x TXT \x00\n"):
            self.assertEqual(self.run_review(BASE + suffix)["status"], "OPEN")

    def test_no_input_code_execution_or_stderr(self):
        sentinel = self.root / "executed"
        payload = "__import__('pathlib').Path(" + repr(str(sentinel)) + ").write_text('executed')"
        data = BASE + b'x TXT "' + payload.encode() + b'"\n'
        stderr = io.StringIO()
        with patch("sys.stderr", stderr):
            self.assertEqual(self.run_review(data)["status"], "PASS")
        self.assertFalse(sentinel.exists())
        self.assertEqual(stderr.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
