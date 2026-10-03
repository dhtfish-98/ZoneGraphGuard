# ZoneGraphGuard

ZoneGraphGuard reviews an explicitly supplied set of local DNS zone snapshots for defensive configuration mistakes. It has a new byte lexer, DNS octet-label normalizer, record model, delegation checks and finite alias/query paths. It reads files, emits a bounded JSON report to stdout, and never contacts a nameserver or modifies a zone.

Install the built wheel with Python 3.11 or newer. There are no runtime dependencies.

```sh
python -m pip install --no-deps dist/zone_graph_guard-0.1.2-py3-none-any.whl
zone-graph-guard manifest.json --root /absolute/authorized/directory
```

The manifest is a regular JSON file relative to the authorized root. Every listed zone file is also relative to that root. Metadata is an assertion by the caller, not proof of publication or authority. One snapshot is allowed per absolute origin; an entry zone determines where every original query and alias traversal starts. A supplied child zone becomes reachable only through a parent delegation.

```json
{
  "schema_version": 1,
  "entry_zone": "example.",
  "zones": [{"origin": "example.", "file": "example.zone"}],
  "queries": [
    {"name": "www.example.", "type": "A", "expect": "RESOLVES"},
    {"name": "missing.example.", "type": "AAAA", "expect": "NOT_RESOLVES"}
  ]
}
```

A corresponding local `example.zone` could be:

```text
$TTL 1h
@ IN SOA ns hostmaster ( 1 1h 30m 1w 1h )
@ NS ns
ns A 192.0.2.1
www A 192.0.2.2
```

`RESOLVES` means the finite asserted-snapshot path has a record of the requested type, including a synthesized CNAME for a supported DNAME descendant query. `NOT_RESOLVES` means its known terminal outcome is NODATA, NXDOMAIN, LOOP or YXDOMAIN. A loop or overflowing DNAME also fails a separate configuration check. Missing or unsupported information produces OPEN instead of a negative answer. A path contains numerical source/record IDs, positions and hashes for its witness records; it is not a serialized DNS response or a returned address set.

The selected profile supports IN A, AAAA, NS, CNAME, DNAME, SOA, MX, TXT and PTR; case-insensitive octet-label names, relative origins, owner omission, comments, quoted TXT, escapes, RDATA parentheses, `$ORIGIN` and `$TTL`. An RR requires an explicit TTL or a preceding `$TTL`; legacy SOA/last-RR TTL inheritance is OPEN. Plain or fully unit-suffixed time expressions are supported, with a 63-character and 31-bit profile bound. Quoted domain names, grouped headers, raw non-ASCII, newline string/escape continuations, DNSSEC and all other RR types remain OPEN. See [DEFENSIVE_SCOPE.md](DEFENSIVE_SCOPE.md) for the full contract.

Checks cover conflicting CNAME/DNAME sets, apex SOA/NS, duplicate records, RRset TTL conflicts, out-of-zone owners, DNAME-occluded records, parent/child NS-set disagreement, required in-domain glue, direct CNAME aliases used as NS targets and parent data hidden below a delegation. The NS check covers apex, parent-delegation and child-apex records, using only complete authoritative snapshots reachable through entry-zone cuts. Missing authority, external targets, orphan source zones and DNAME-hidden targets remain OPEN; parent glue/cache never proves alias presence or absence. CNAME graph cycles are checked inside each asserted zone; DNAME and cross-zone cycles are checked for the supplied query paths. Wildcards are deliberately OPEN; no equivalence classes or all-query verification are claimed.

`PASS` means the selected checks and submitted properties completed without a failure or gap. `FAIL` preserves a demonstrated selected-model violation even when other checks are OPEN. `OPEN` means the selected model could not decide. Exit codes are 0, 1 and 2 respectively; invalid CLI options use argparse's exit 2. `external` always keeps live DNS, all possible queries, multiple authoritative servers, DNSSEC and CVP eligibility OPEN.

Default limits include 2 MiB total input, 256 KiB per file, 32 files including the manifest, 8192 records, 65536 tokens per zone, 4096 bytes per token/name, nesting 16, 32768 nodes, 256 submitted queries, 64 path iterations, 200000 graph steps, 256 findings and 256 KiB output. Reads may probe one extra byte to detect a growing file; failed reads still consume the total byte budget. CLI overrides total/file bytes and path iterations. Library `Limits` exposes all budgets and rejects non-positive or incorrectly typed values. Output truncation preserves aggregate failure counts and changes completeness to OPEN.

Reads use anchored directory descriptors and refuse symlinks at every root/file path component, `..`, absolute file paths, URLs and special files. Before/after descriptor identity, timestamps, regular-file type and exact read length are checked. `$INCLUDE`/`$GENERATE` are rejected without opening additional files. No stdin, archives, subprocesses, dynamic properties, script execution, DNS, AXFR, import of input, or write-back exist.

Reports omit literal input paths, domain names, addresses, TXT contents and raw exception messages. Numerical positions and stable SHA-256 fingerprints support local correlation. Fingerprints do not promise secrecy against dictionary guessing. No source content is written to stderr by the reviewer.

Authorship, fixed upstream review scope and complete licenses are in [ORIGIN.md](ORIGIN.md), [NOTICE](NOTICE) and [LICENSE](LICENSE). New implementation author and maintainer: dhtfish98. This is a defensive portfolio candidate; program eligibility remains OPEN. [VALIDATION.md](VALIDATION.md) distinguishes local tests/packages from remote CI and live deployment evidence.

Local file I/O requires the positive integer OS protection flags documented by
the reader/writer. Missing, zero, None, Boolean or non-integer flags return a
controlled OPEN/error before requested filesystem input/output instead of
weakening the boundary. Native
Windows file I/O is not verified; the current verification is macOS POSIX.

Directory descriptor capability contract: `os.supports_dir_fd` must be a set or frozenset containing `os.open` before requested local file access. Missing, malformed or incomplete capability declarations return the existing controlled OPEN/error result. This finite POSIX contract is checked locally; native Windows file operations are not implemented or claimed.
