# Normalization conformance data

`normalization_tests.rs` is the generated Rust test corpus from
[`unicode-rs/unicode-normalization`](https://github.com/unicode-rs/unicode-normalization),
version **0.1.25**, `tests/data/normalization_tests.rs`.
Its generator, `scripts/unicode.py`, selects **Unicode 17.0.0** and reads
<https://www.unicode.org/Public/17.0.0/ucd/NormalizationTest.txt>.

The generated source retains its upstream copyright and dual-license notice.
This copy is distributed under the MIT option; the upstream MIT license is
included as `LICENSE-MIT`. The corpus has 20,034 rows.

`tests/normalization.rs` checks the five NFC identities for every row:

- NFC(source) = NFC(nfc) = NFC(nfd) = nfc
- NFC(nfkc) = NFC(nfkd) = nfkc

That is 100,170 checks of the bounded encoder against supplied expected
strings, not expectations computed by the normalization implementation.
Each input also checks symbolic encoding against the bounded bytes. Every
row whose NFD differs from NFC checks that the unnormalized wire is rejected
as `NonCanonicalString`; the suite requires this rejection domain to be
nonempty. Long-run and Hangul fixtures supplement the conformance corpus.
When upgrading Unicode data, update the dependency pin, corpus, provenance,
and review the bounded normalization algorithm against the new dependency.

## Recorded bounded-work evidence

Admission traces and tightness ratios begin with a tab-separated
`#\tconfiguration\t<identity>` header. The development shells export
`DCBOR_CONFIGURATION` with the toolchain, target, standard-library source,
hashbrown fork revision, rust-overlay revision, and nixpkgs revision.
Recording without that identity fails.

Admission-trace rows contain case name, feature gate, declared outcome, and
calls. Tightness rows contain bound, measured use, ceiling, checked outcome,
and case/dimension name. Outcomes distinguish publication, invalid input,
and cancellation; analytical tightness calculations use `exact`. A defect
cannot be recorded or accepted by the ratchet, even when its numeric result
matches an existing record. Diagnostics name cases rather than their indices.

Both recorders write a uniquely named temporary file beside the destination,
then rename the completed file over it. An outcome failure occurs before any
publication. Planted-defect tests exercise that boundary and require the
previous evidence to remain intact.

Stock and custom-standard-library records are separate, as are builds with
and without `num-bigint`: the suffixes are empty, `.num-bigint`, `.custom-std`,
and `.custom-std.num-bigint`. Records in the older format are not upgraded by
inference. They require an explicitly authorized recording after the oracle
and the corresponding mechanism have passed verification.

Verification and recording proceed at each mechanism boundary. Each new
record's delta is attributed to that mechanism. Unsafe changes additionally
require strict-provenance Miri under both aliasing models at that boundary;
a later combined run does not replace that evidence.

### Complete variant inventory

In the active fork-enabled development shell, run
`bash tests/record-evidence.sh check` to check all four variants of every
trace and tightness family. The check reports every missing, empty, legacy,
or stale-configuration file. Its explicit family inventory prevents a
missing family from disappearing from coverage through file discovery.

`bash tests/record-evidence.sh record` runs the library's correctness and
attribution tests and the admission-trace recorder for all four feature
projections, then checks completeness. It stops on a failed test. Each Rust
recorder retains its outcome checks and atomic publication. Recording does
not fabricate missing variants by copying another configuration's results.
Use the development shell whose identity should appear in the records;
the script uses that shell directly and does not install or switch tools.

Review deltas against their mechanisms: FF-17 moves release charges to
acquisition; staged arenas add metadata acquisition and release; merge
scratch grows geometrically across retained runs. Observation-only changes
and one-pass refusal must leave successful admission traces unchanged.

### Matrix cost evidence

The same recording command also records matrix costs for both rigor layers
and all four feature projections. Set `DCBOR_COST_REASON` to the mechanism
explaining the change. `TMPDIR` is required: the recorder's staging
directory.

```sh
DCBOR_COST_REASON='Describe the verified mechanism here' bash tests/record-evidence.sh record
bash tests/record-evidence.sh check-costs
```

`record-costs` records costs alone after trace and tightness records are
qualified. `check-costs` runs the same matrix targets with the same features
in both layers. Every matrix's stage selection and available schedule count
are compared exactly. Pipeline records additionally measure attempts,
physical requests, boundaries, certified classes and unclassified boundaries.
Changes in either direction fail: a decrease may mean missing coverage.
Wall-clock time is reported but is never a ratcheted quantity.

Cost records and inventories live in `costs/` in the working tree and are
not tracked: `.gitignore` excludes the directory. Each record is bound to one
exact development-shell configuration and a configuration change replaces the
whole set, so the ratchet is local evidence for the shell that recorded it.
`check-costs` therefore requires a prior `record-costs` in the same
configuration; in a fresh clone, or under another configuration, there is no
inventory to compare against and the check fails.

Records carry the full configuration, feature projection, rigor, test
executable, semantic matrix name and mechanism reason. Filenames use a
bounded digest; equality and collision checks use the full identity, never
the digest. Matrices write atomic staged records only when they finish without
an oracle panic. The recorder keeps those records in its staging directory
under `TMPDIR` until the eight feature/rigor test commands and cross-leg
identity checks pass, then publishes records and finally the complete
per-variant inventories. A failed validation leg leaves existing cost records
and inventories intact. Individual files are replaced atomically; publication
of the entire set is not one atomic transaction.

An interrupted recording resumes from its staging directory:

```sh
DCBOR_COST_REASON='Describe the verified mechanism here' bash tests/record-evidence.sh record-costs "$TMPDIR/dcbor-costs.XXXXXX"
```

A leg is reused only when it completed: its retained log, raw inventory and
completed inventory must agree, and its staged records must exist with the
active configuration header and no identity collision. Any other leg runs
again from its beginning. Resumption is per feature/rigor leg, not per test,
and does not compare source contents: reuse is valid only when the change
since the reused legs cannot alter their schedules or measurements.

Checking compares the inventories too, so removing a matrix cannot silently
remove its cost check. It also rejects digest-named records belonging to the
active configuration that no current inventory references. A complete recording
removes those orphan records after publication. Records with another
configuration header or an unrecognized header are preserved; this run cannot
qualify or prune them. Captured logs remain in the staging directory.

`tests/record_evidence_test.py` exercises publication, failed-leg preservation,
identity collisions, orphan detection/removal, preservation of foreign and
unrecognized records, read-only checking of missing records, isolation from
inherited trace and tightness recording flags, and resumption (reuse of a
completed leg, and rejection of a changed configuration, a missing staged
record, or a log/inventory mismatch) using fake Cargo in a temporary tree.
These controls validate recorder behavior, not the measured matrix costs;
real eight-leg recording and checking remain separate qualification.
