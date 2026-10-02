"""One local JSON manifest, an explicit root, one bounded stdout report."""

import argparse
import sys
from .contracts import Limits, encode_report
from .review import review_manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description="Review local asserted DNS zone snapshots offline.")
    parser.add_argument("manifest", help="relative manifest file below --root")
    parser.add_argument("--root", required=True, help="absolute authorized directory (no symlinks)")
    parser.add_argument("--version", action="version", version="ZoneGraphGuard 0.1.0")
    parser.add_argument("--max-bytes", type=int, default=2097152)
    parser.add_argument("--max-file-bytes", type=int, default=262144)
    parser.add_argument("--max-hops", type=int, default=64)
    options = parser.parse_args(argv)
    try:
        limits = Limits(total_bytes=options.max_bytes, file_bytes=options.max_file_bytes,
                        hops=options.max_hops)
    except ValueError:
        parser.error("positive supported budgets required")
    report = review_manifest(options.manifest, root=options.root, limits=limits)
    sys.stdout.buffer.write(encode_report(report))
    return {"PASS": 0, "FAIL": 1, "OPEN": 2}[report["status"]]
