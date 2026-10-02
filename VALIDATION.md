# Validation boundary

The local validation record is finalized in `evidence/reviewed-source.json` and the separate engineering handoff. It covers full reads of the new runtime, tests, packaging, CI, documentation and complete bundled licenses, alongside the fixed selected upstream scope. Build tooling is pinned separately and is not a runtime dependency.

The regression corpus uses synthesized defensive configurations and negative cases: normalized escapes/case, quotes/comments, owner/origin/TTL handling, type-specific RDATA, CNAME/DNAME paths and cycles, DNAME overflow, empty nonterminals, missing names, parent/child delegation and NS/glue conflicts, apex/child/parent NS target CNAME witnesses, parent cache versus child authority, external/orphan/incomplete/DNAME NS authority gaps, root/child single-record mutations, missing files/metadata, wildcard and unsupported dialect gaps, malformed/truncated data, resource limits, privacy, symlink/root escapes, FIFO avoidance, controlled short reads, determinism and unchanged inputs.

Final checks run all tests against source and a fresh wheel installation from an unrelated working directory, exercise CLI reports/exits through actual processes, verify unchanged files, and compare source/wheel/sdist/installed module identity. Wheel RECORD member hashes/sizes and complete installed license files are checked. Artifact SHA-256 values and actual counts are recorded in the engineering handoff instead of claimed from source inspection alone.

Only Python 3.14.6 is locally available. CI declares Python 3.11 and 3.14; remote exact-commit CI remains OPEN until separately observed. No network DNS, AXFR, deployment, server reachability, multiserver consistency or CVP approval is tested or inferred.
