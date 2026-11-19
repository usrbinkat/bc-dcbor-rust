# Normalization conformance data

`NormalizationTest.txt` is the Unicode Character Database's own conformance file for **Unicode
17.0.0**, the version the pinned `unicode-normalization` (**0.1.25**, `src/tables.rs`,
`UNICODE_VERSION`) normalizes by, copied unchanged from unicodetools
`unicodetools/data/ucd/17.0.0/NormalizationTest.txt` (revision `2621ff34`). Its license, the Unicode
License V3 of that repository, is `LICENSE-UNICODE`. `tests/normalization.rs` compiles it in and
parses it itself (part headers, comments, rows of five columns, anything else refused naming its
line), so the suite runs under Miri's isolation and holds the data once; no row count is written
anywhere. The file's header names its version, which must equal `dcbor::UNICODE_VERSION`: data of
another version is refused before any row is read, and planted controls rewrite the header to each
neighbouring version, derived from the pin, and remove it.

The package's other Unicode data, `data/unicode/17.0.0/DerivedAge.txt` (license
`data/unicode/LICENSE-UNICODE`), is what `build.rs` generates the stabilized-text table from
(`src/stabilized_text.rs`); its version is checked against the same constant at compile time.

dCBOR requires NFC alone, so the file's NFC invariants are the ones checked, in both directions, for
every column of every row:

- NFC(c1) = NFC(c2) = NFC(c3) = c2
- NFC(c4) = NFC(c5) = c4

Normalizing: the bounded encoder reaches the expected string the file supplies, never one computed
by the normalization implementation, and the symbolic encoding equals the bounded bytes. Validating:
each column's own, unnormalized wire is accepted by the decoder exactly when the file states it is
its own NFC, and refused as `NonCanonicalString` otherwise; both outcomes must occur. The file's
second invariant is checked too: every code point assigned in the pinned version
(`dcbor::is_assigned`, the table `build.rs` generates from `DerivedAge.txt`) that Part 1 does not
list is its own NFC, encoded and decoded unchanged, which ties the two data files together. Long-run
and Hangul fixtures supplement the conformance data. When upgrading Unicode data, move the
dependency pin, both data files (`data/unicode/<version>/DerivedAge.txt` and
`NormalizationTest.txt`) and their provenance together, and review the bounded normalization
algorithm against the new dependency: the build and this suite refuse data whose version differs
from the pin's.

## dCBOR conformance vectors

`dcbor-appendix-a.md` is Appendix A, "dCBOR Numeric Test Vectors", of
**draft-mcnally-deterministic-cbor-18**, the revision this crate implements
(`dcbor::DCBOR_DRAFT_REVISION`): lines 324-390 of `draft-mcnally-deterministic-cbor.md` in the
draft's own repository, `BlockchainCommons/WIPs-IETF-draft-deterministic-cbor`, revision `ec77ab6`
(2026-08-10, the draft's date), copied unchanged, with one first line added naming the revision, the
repository, the commit and the lines. The repository's `LICENSE.md` refers to its contribution
guidelines, which place the material in the public domain and make it a Contribution to the IETF
Standards Process under BCP 78, BCP 79 and the IETF Trust Legal Provisions; both are copied
unchanged beside the data, as `LICENSE-DCBOR-DRAFT.md` and `CONTRIBUTING-DCBOR-DRAFT.md`.

`tests/appendix_a.rs` compiles the file in and parses its two tables itself (each table's rows from
its separator line to the next blank line, the value's first token and the encoding's hex, anything
else refused naming its line), so it runs in every gate domain and under Miri's isolation; no row
count is written anywhere. The first line must name `DCBOR_DRAFT_REVISION`: data of another revision
is refused before any row is read, naming both, and planted controls rewrite it to the neighbouring
revisions and remove it. Every valid row is encoded by the symbolic and the bounded encoder and
decoded by both decoders, in both directions; every invalid row is refused by both decoders with the
error its reason names. The revision is part of every evidence gate's identity (`gate dcbor-draft`,
`tests/gate-common.sh` `source_identity`): moving to another revision means replacing this file, its
first line and the constant together, a deliberate change.

`gate evidence` checks each normative test target (`tests/gate/src/rows.rs`, `NORMATIVE`,
`normative_faults`) by parsing its source: a top-level `const` or `static`, under no `cfg` or
`cfg_attr`, in a file under none, compiles in exactly its data file through `include_str!`, and is
read by a path outside any code a `cfg` or `cfg_attr` carries. The guarantee is syntactic: not name
resolution, and not proof that the test executes the vectors, which remains the test's own
obligation, reviewed by reading its source.

## Recorded bounded-work evidence

Admission traces and tightness ratios begin with a tab-separated `#\tconfiguration\t<identity>`
header. The development shells export `DCBOR_CONFIGURATION` with the toolchain, target,
standard-library source, hashbrown fork revision, rust-overlay revision, and nixpkgs revision.
Recording without that identity fails.

Admission-trace rows contain seven tab-separated columns: case name, feature gate, declared outcome,
evidence class, and the run's three columns (`tests/refinement`, `text.rs`, the rows' one format).
The first is the recording session's whole stream (`Session::finish`), every observation in the
session's one order as its publishing family, its performer and its event, each identity as
`FAMILY.SEQUENCE`; the second the driver's marks at session boundaries (`Session::boundary`):
`@B checkpoint`, every declared owner's held obligations (kind, remaining work, identity,
acquisition) and permits by identity, `@B cleaning` and its cause, `@B published` and the output's
permits; the third the run's end. Identities are numbered canonically over the whole run, so a row
renders one way. Every run is checked by the refinement machine before it is recorded and when it is
read, by the recorder and by `gate refine` and `gate evidence`: admission correspondence per
performer; each held obligation, acquisition, owner and permit by identity, its family the
publishing one; each settlement of the named obligation in its own kind, acquisition and origin
family; each permit granted, given its observed physical outcome, split, merged and released exactly
once; each checkpoint's custody equal to the state the observations before its boundary reach; the
cleanup cause and publication derived from the stream; and quiescence at the end. A boundary is a
position in the whole session's stream, never a policy's call count. The machine is a refusal check
only: a run it refuses is never recorded and a record holding one is a fault, but acceptance
upgrades nothing. The class is `observed` for every row (`dcbor_refinement::evidence`), and a row
claiming another is refused, until every correspondence obligation of the refinement register and
each rule's planted divergence are verified. Every recorded test's whole stream, trace or not, is
checked by the same transitions (`dcbor_refinement::settled`, through `tests/support/lifecycle.rs`
`recorded_run`). Tightness rows contain bound, measured use, ceiling, evidence class, checked
outcome, requirement, and case/dimension name. The class is the ceiling's (`exact` derived, every
other ceiling observed; `dcbor_record::Evidence`), and a row claiming another is refused. The
requirement is the case's eligibility, separate from the representation projection the file suffix
names: `-` for a case every build executes, or the one capability the case needs
(`dcbor_record::capabilities`, the one definition of `derive` and `hashbrown`, shared with the
admission-trace feature column). A build checks every row whose requirement it satisfies and ignores
the rest; a missing eligible row, a changed requirement, an unknown one, and a measurement taken
without its capability are refused; recording requires every capability. Outcomes distinguish
publication, invalid input, and cancellation; analytical tightness calculations use `exact`. A
defect cannot be recorded or accepted by the ratchet, even when its numeric result matches an
existing record. Diagnostics name cases rather than their indices.

Both recorders write a uniquely named temporary file beside the destination, then rename the
completed file over it. An outcome failure occurs before any publication. Planted-defect tests
exercise that boundary and require the previous evidence to remain intact.

Stock and custom-standard-library records are separate, as are builds with and without `num-bigint`:
the suffixes are empty, `.num-bigint`, `.custom-std`, and `.custom-std.num-bigint`. Records in the
older format are not upgraded by inference. They require an explicitly authorized recording after
the oracle and the corresponding mechanism have passed verification.

Verification and recording proceed at each mechanism boundary. Each new record's delta is attributed
to that mechanism. Unsafe changes additionally require strict-provenance Miri under both aliasing
models at that boundary; a later combined run does not replace that evidence.

### Complete variant inventory

In the active fork-enabled development shell, run `bash tests/record-evidence.sh check` to check all
four variants of every trace and tightness family. The check reports every missing, empty, legacy,
or stale-configuration file. Its explicit family inventory prevents a missing family from
disappearing from coverage through file discovery.

`bash tests/record-evidence.sh record` runs the library's correctness and attribution tests and the
admission-trace recorder for all four feature projections, then checks completeness. It stops on a
failed test. Each Rust recorder retains its outcome checks and atomic publication. Recording does
not fabricate missing variants by copying another configuration's results. Use the development shell
whose identity should appear in the records; the script uses that shell directly and does not
install or switch tools.

Review deltas against their mechanisms: FF-17 moves release charges to acquisition; staged arenas
add metadata acquisition and release; merge scratch grows geometrically across retained runs.
Observation-only changes and one-pass refusal must leave successful admission traces unchanged.

### Recording budgets

A recording budget is the observation storage a fixture whose recording outgrows the default
capacity (`support::CAPACITY`) was measured to need: the session preallocated before the fixture
runs, never an expected accounting total. No test states one; each is a row of its family's record.

`bash tests/record-evidence.sh record-budgets` records every budget record, then checks each with
recording disabled. `gate budgets` names every record to hold, one line each: its file name, its
projection's features, its test target and exact test, and its rigor layer and witness size. That
list is `dcbor_record::budgets::inventory`: every family of `budgets/families.rs` in every variant
it is compiled in (`dcbor_record::VARIANTS`; a family of the forked collections in the custom-std
variants alone), at both layers and both witness sizes. The support crate's build compiles the same
list in (`tests/support/build.rs`) and `gate evidence` requires each record current.

Each `budgets/{family}{variant}.{rigor}.{witness}.txt` holds the configuration line, then one
tab-separated row per fixture: its identity, the events and the permit records its finished
recording held. Every selection has its own record, the fixtures that selection runs, so a fast or
minimal run is never sized by another selection's fixtures. A reader refuses a record with no
configuration line, a malformed or impossible count (no event, more permit records than events), a
fixture twice, and a family missing a fixture or holding one it does not declare.

`support::budgets::Budgets` is a family's one source of capacity. Each fixture runs through it
(`Budgets::run`, `Budgets::construction`, or `Budgets::encode_checked`), measured from the evidence
its recording finished with; a fixture undeclared, measured twice, or begun before the last finished
is refused; `Budgets::finish` requires every declared fixture measured, and a family dropped
unfinished is refused. `DCBOR_RECORD_BUDGETS` names the one record a run records: under it every
fixture runs at the fixed bootstrap capacity, never grown or retried, and the finished family is
published whole, a family incomplete or failed leaving the previous record intact; any other family
it reaches refuses to run. Every finished family reports `budget finalized: <record>`, and the
recorder requires exactly one per run. Publication across families is not a transaction.

The capacity of a recorded fixture is its counts each padded by a quarter and rounded up to a power
of two, never below the default (`support::measured`, private to the support crate, so no
integration test can size a recording by hand); an overflowing count is refused. Apart from a
budget, a recording is never enlarged: a pipeline schedule states no capacity, and the one public
sizing, `support::recorded_run_short`, only shrinks the default, to witness a recording's
exhaustion. The library's own unit tests, which cannot reach the support crate, make their sessions
directly, each sized for its own test: the session module's capacity tests and the exhaustion
witnesses at the exact sizes they test, the rest at sizes well below the default, kept small
because the Miri gate runs most of them (`tests/miri-suites.txt`) and a session initializes every
slot it holds. A record absent from the build is compiled in as absent, which only its own
recording run accepts: the first recording needs no placeholder file. Cost qualification clears the
recording flag, and the launcher sets it for one record at a time.

Driver selection and observation extraction are private to the budget authority. Fixtures supply
inputs and semantic inspections; they cannot supply a replacement observation stream to the
recorder.

### Matrix cost evidence

The same recording command also records matrix costs for both rigor layers and all four feature
projections. Set `DCBOR_COST_REASON` to the mechanism explaining the change. `TMPDIR` is required:
the recorder's staging directory.

```sh
DCBOR_COST_REASON='Describe the verified mechanism here' bash tests/record-evidence.sh record
bash tests/record-evidence.sh check-costs
```

`record-costs` records costs alone after trace and tightness records are qualified. `check-costs`
runs the same matrix targets with the same features in both layers. Every matrix's stage selection
and available schedule count are compared exactly. Pipeline records additionally measure attempts,
physical requests, boundaries, certified classes and unclassified boundaries. Changes in either
direction fail: a decrease may mean missing coverage. Wall-clock time is reported but is never a
ratcheted quantity.

Cost records and inventories live in `costs/` in the working tree and are not tracked: `.gitignore`
excludes the directory. Each record is bound to one exact development-shell configuration and a
configuration change replaces the whole set, so the ratchet is local evidence for the shell that
recorded it. `check-costs` therefore requires a prior `record-costs` in the same configuration; in a
fresh clone, or under another configuration, there is no inventory to compare against and the check
fails.

Records carry the full configuration, feature projection, rigor, test executable, semantic matrix
name and mechanism reason. Filenames use a bounded digest; equality and collision checks use the
full identity, never the digest. Matrices write atomic staged records only when they finish without
an oracle panic. The recorder keeps those records in its staging directory under `TMPDIR` until the
eight feature/rigor test commands and cross-leg identity checks pass, then publishes records and
finally the complete per-variant inventories. A failed validation leg leaves existing cost records
and inventories intact. Individual files are replaced atomically; publication of the entire set is
not one atomic transaction.

An interrupted recording resumes from its staging directory:

```sh
DCBOR_COST_REASON='Describe the verified mechanism here' bash tests/record-evidence.sh record-costs "$TMPDIR/dcbor-costs.XXXXXX"
```

A leg is reused only when it completed: its retained log, raw inventory and completed inventory must
agree, and its staged records must exist with the active configuration header and no identity
collision. Any other leg runs again from its beginning. Resumption is per feature/rigor leg, not per
test, and does not compare source contents: reuse is valid only when the change since the reused
legs cannot alter their schedules or measurements.

Checking compares the inventories too, so removing a matrix cannot silently remove its cost check.
It also rejects digest-named records belonging to the active configuration that no current inventory
references. A complete recording removes those orphan records after publication. Records with
another configuration header or an unrecognized header are preserved; this run cannot qualify or
prune them. Captured logs remain in the staging directory.

The recorder is the gate tool's (`tests/gate`, `costs`; the script launches `gate costs`). Its tests
(`cargo test -p dcbor-gate costs::`) exercise publication, failed-leg preservation, identity
collisions, orphan detection/removal, preservation of foreign and unrecognized records, read-only
checking of missing records, isolation from inherited trace and tightness recording flags and
minimal witnesses, and resumption (reuse of a completed leg, and rejection of a changed
configuration, a missing staged record, or a log/inventory mismatch) with a fake leg runner in a
temporary tree. These controls validate recorder behavior, not the measured matrix costs; real
eight-leg recording and checking remain separate qualification.

## Model bounds

`model-bounds.txt` is a record of every model a checker build runs (`src/sync/models.rs`, and the
baselines' entry point in `tests/resumable/native_traces.rs`): its least bound (loom's branch
capacity, shuttle's step bound), its least stack in bytes where it runs on a sized one, and the
schedules shuttle's exhaustive search explores. After its configuration line it tags the build
profile and the page size its stacks are multiples of. Its rows are defined once
(`tests/model-bounds`), read by the model runner (`tests/support/model.rs`) and derived, written and
verified by the gate (`tests/gate`). `bash tests/concurrency-models.sh derive` searches each value
upward across processes and rewrites the record: a change states its cause, the protocol or the
toolchain that moved a count. `bash tests/concurrency-models.sh gate` runs each model at its
recorded values, one under each, and the planted controls, on copies of a clean commit.

## Planted controls

`controls/` holds diffs a gate applies to show that one of its checks fails on the defect the diff
plants (`tests/gate-common.sh`, `apply_diff DIFF DIR`), and their one table, `controls/controls.tsv`
(`tests/gate`, `controls`). Every diff in the directory has a row and every row names a diff that
exists, or the table is refused and no control runs. A row names the runner that shows the refusal
(a model checker, `native`, or a Miri aliasing model the gate lists, `gate miri models`), the
outcome the refusal must be, and the text it must name in its own report: the whole report of a run
of exactly the one selected test, or the named trybuild fixture's own block. Under Miri, whose
undefined behavior ends the interpreter before libtest's summary, the report is the one test's when
libtest selected exactly that test and started it. A failure of another test, an ignored test,
another outcome than planned, or the text printed anywhere else is not the defect refused by its own
rule.

Each is an exact `-p0` diff against the source it plants into, applied to a copy of a clean commit,
never to the checkout: a change to those lines makes it fail to apply, and the gate fails. The model
checkers' controls run in the concurrency gate (`tests/concurrency-models.sh`,
`gate models control`). The native and Miri controls run in `tests/controls.sh`, in the shell of the
toolchain channel their row names (a Miri control's is nightly, whose toolchain carries Miri): red
with the diff applied, then green with it reversed in the same copy, the copy's digest required to
change with the diff and to read back equal once it is reversed (`gate control evidence`). A Miri
control's test runs under the Miri gate's own command and its model's flags (`tests/gate-common.sh`,
`miri_command`, `miri_flags`), the flags part of the run's identity, and is judged by the gate tool
as a native run is (`gate control judge`): a defect only undefined behavior shows, such as a drop
reading a field its prefix never initialized, is refused there.

`relaxed-publication.patch` makes the decode scope queue's link store, the publication of every
record queued behind another, `Relaxed` (`tests/concurrency-models.sh`). loom must refuse it with a
causality violation on the record's custody in one of its models: a record reached through that link
alone is read without its retiring thread's writes ordered before the read.

`substituted-write.patch` and `substituted-block.patch` each read one of a block's two contract
quantities from the build's own atomics family instead of its production representation
(`stable.rs`, `Contract::of`, the one definition every block's charge and cost read): the leak I3
forbids, the charge varying with the build. Both run under loom and under shuttle. A substituted
write makes the scope's and the record's headers exceed the quantum, so the checker build must fail
to compile with the quantum assertion (`write_extent`). A substituted block leaves the write within
the quantum, so the build compiles and the I3 witness (`admits_its_production_representation`) must
fail on the scope's allocation request.

`text-allocation-retried.patch` makes the text encoder's driver (`TextEncoder::step`,
`text_cursor.rs`) send a failed output reservation back to `ReleaseOutput` instead of into cleanup:
the retry the `Resumable` contract forbids after a terminal error. The cleanup driver's next step
(`tests/support/lifecycle.rs`, `Holding::finish`, reached through the test's `encoded`) re-admits
the output's release, requests the output again (the next physical request, which is not failed) and
publishes; the holding retains and retires the unexpected output before returning its stop, so
`tests/resumable/native_heap.rs`
`every_real_normalization_and_output_allocation_can_fail_without_leaking` must fail naming
`the operation published where its schedule admits none`, before the oracle's release count is read.
Seen red at failure 0: the cleanup's stop beside the oracle's `another path to the failed request`,
the recording finished and refined; green with the patch reversed.

`session-index-unchecked.patch` removes the root session's node check (`in_place.rs`, `enter`): a
bound session then steps its binding from whatever node its context names. The crate's adversarial
schedules (`in_place.rs`, `tests::adversarial`) must fail: a stabilized text checked on one node
continued from another, and a minimal big integer's magnitude taken from a node other than its
sign's. Not yet seen red.

`sequence-built-in-cleanup.patch` lets a sequence's build continue from its cleanup phase `Reclaim`
as from `Next` (`in_place/vector.rs`, `build_sequence`): a parent's build reaching a part whose
cleanup began. `a_sequence_in_cleanup_refuses_a_build_and_admits_nothing` must fail: the build
admits a unit and moves the sequence to `Complete`. Not yet seen red.

`context-recombination.patch` restores a public document handle apart from its slot
(`Context::origin`, `Origin::context`), the recombination route the context closes. The compile-fail
fixture `dcbor-derive/tests/ui/fail/context_recombination.rs` must then compile, so trybuild reports
an expected compile failure that did not happen. Not yet seen red.

The three cleanup-capability controls each re-open one route the cleanup step's capability
(`reclamation.rs`, `Cleanup`) closes: `cleanup-grants-allocation.patch` implements `Allocator` for
it, `cleanup-derefs-to-policy.patch` lets it dereference to the policy it wraps, and
`cleanup-policy-public.patch` makes that policy a public field. Each makes its own compile-fail
fixture (`dcbor-derive/tests/ui/fail/cleanup_allocate.rs`, `cleanup_deref.rs`, `cleanup_field.rs`)
compile, which trybuild reports in that fixture's block, the one block its row judges. The
allocation and field patches change only their own fixture. The dereference patch cannot be
isolated: a capability that dereferences to its policy reaches the policy's methods and fields by
autoderef, so `cleanup_allocate.rs` compiles too and `cleanup_field.rs` gains a field-privacy error
of the policy's; that is the route the dereference opens, observed on stable. What the fixtures show
is that no new allocation can be requested through the capability a cleanup step is given, and no
route reaches the policy behind it; an implementer's own allocations outside it are the
physical-allocation observer's and the trusted domain's to refuse. Not yet seen red.

A binding's `Done` carries a record of its value's initialization (`in_place.rs`, `Initialized`),
branded with its context's lifetime. A binding's step is generic over that brand, so a record cannot
outlive the step that minted it: kept in a static, in state, across steps, constructions or cleanup,
it does not type-check, with no counter and no shared state. Within the step, its parent verifies
and consumes it on arrival against the place it projected and a context a session stepped; a
mismatch is `PlanMismatch`. Coverage is the parent's state, never a stored record. Each run-time
check is planted out by its own patch and named by its own test (`in_place.rs`,
`tests::adversarial::records`, a step forging its record from its own context's assembly):

- `record-place-unchecked.patch` drops the place comparison; a record of the next byte's place
  advances its parent through the part entry and builds its session through the root entry.
- `record-part-unverified.patch` stops the part entry verifying; the part's forged record advances
  its parent.
- `record-root-unverified.patch` stops the root entry verifying; the root's forged record builds its
  session.
- `record-unbound-context-accepted.patch` drops the stepped mark's comparison; a record verifies
  against a context no session stepped.

Each test also accepts the same forgery at its own place, so a refusal is the check's and not the
forger's.

The two check removals are also refused by the record check's Kani harness (`in_place/proofs.rs`,
`a_record_is_accepted_exactly_at_its_projected_place_of_a_stepped_context`), exhaustive over every
place address and both session flags of the record and of the projected assembly: under either patch
a record the check must refuse is accepted, "a record is accepted only at its projected place".

Three compile-fail fixtures hold the record's closed routes, each re-opened by its own patch so only
its fixture compiles, which trybuild reports in that fixture's block: `record-fields-public.patch`
(`record_forged.rs`, a record built from its fields), `record-clone-derived.patch`
(`record_cloned.rs`, a record cloned) and `record-assembly-safe.patch` (`record_unproven.rs`, a
record minted without the unsafe obligation). Three more hold the brand's invariance, each variance
re-opened by its own patch: `record-brand-contravariant.patch` lets a step's record be stored as
`'static` (`record_kept_across_steps.rs`, kept in a thread-local across steps;
`record_after_cleanup.rs`, held in the binding's state into cleanup), and
`record-brand-covariant.patch` lets a `'static` record another construction left be presented as
this step's (`record_of_another_construction.rs`). Each fixture compiles under exactly the variance
that admits its misuse. Their `.stderr` files are blessed on stable. None is yet seen red.

A witness inside a recorded run detects its planted defect without ending the run there: it records
the finding (`RecordedRun::defect`), a malformed custody observation is recorded the same way
(`capture`), and a policy whose history disagrees with its counters is found after the body returns
(`correspondence`). Every capability is then dropped and the recording finished and refined
(`concluded`, `finalize`), and the run fails naming each finding beside what the recording finished
as. So a control's expected text is its own finding, and a leak its defect causes is reported with
it, never in its place.

The credit controls each plant one defect of the four-ledger accounting (`A = C + F + H`,
`Credits::conserved_with`, the custody's `held_credit`), each named for what it defeats; their
oracles are in `tests/resumable/native_heap.rs`. None is yet seen red.

`credit-spend-dropped.patch` forgets the text output release's held obligation at its grant instead
of spending it (`text_cursor.rs`, `Phase::Allocate`): neither the spend nor the obligation's drop
forfeit (`Retained`'s backstop) records anything, so the custody advances past the grant holding
nothing while the ledgers leave the release open, and
`text_encoding_credit_is_conserved_at_every_suspension_and_settled_at_its_end` must fail
conservation (lost credit) on the turn of the grant.

`credit-spend-twice.patch` spends that obligation twice. A held obligation is settled by value
(`Retained::spend` takes `self`), so the second spend is a use of a moved value: the planted copy
must fail to build, the defect refused by the type rather than by a run.

`credit-left-held.patch` makes `BucketCursor::end(by, rule)` neither forfeit nor take its window's
obligation: the ledgers conserve with what the custody reports, but it still reports credit once the
enumeration completes, so `bucket_credit_is_conserved_at_every_call_and_settled_at_its_end` must
fail its terminal zero-held check (an obligation left held).

`credit-lost-across-suspension.patch` takes a bucket cursor's window obligation as it yields an
entry and forgets it, neither spent nor forfeited: the same test must fail conservation after that
call (lost credit).

`credit-terminal-fresh-counters.patch` builds the terminal policy (`Limits::terminal`, `policy.rs`)
over counters of its own instead of its permit's. A held obligation settles into the origin it
stored at its admission (`Retained`), so the drain's forfeits still reach the admitting family and
conservation still holds; what the defect loses is the drain's own admitted cleanup units, which no
longer reach the originating family.
`an_abandoned_scope_conserves_credit_through_its_terminal_drain` must fail on that: no terminal
drain's admitted work reached the originating family. The witness's `stop_matrix` stops at every
boundary through the measured publication turn, including the completed decode, in both rigor
layers. The unit test `a_family_shares_one_ledger_and_a_fresh_policy_does_not` must fail too, on a
terminal forfeit recorded through the terminal policy's own origin.

`credit-attribution-misscoped.patch` begins the text encoding's delta in
`two_operations_on_one_policy_are_checked_by_their_deltas` once the encoding first holds credit: the
delta records that credit's settlement without its admission, so the encoding's delta must fail
conservation (credit attributed to the wrong scope). The plant captures that first nonzero held
credit in the holding driver's observer; a missing or zero custody observation cannot select the
snapshot.

`standalone-unwind-cleanup-skipped.patch` bypasses the held standalone cleanup after its consumer
unwinds (`tests/support/reclamation.rs`). `standalone_consumer_unwind_reclaims_before_finalization`
requires both the original consumer panic and a finished, refined recording: the initialized
destination must be reclaimed before its driver, document and slot retire. Automated
red/restored-green qualification is pending.

`standalone-loss-cleanup-skipped.patch` makes the drained cleanup schedule
(`tests/support/reclamation.rs`, `reclaim_by`) return at the first turn whose recording is no
evidence, instead of retaining that failure and draining on.
`standalone_recording_loss_reclaims_without_accepting_evidence` invalidates the session after a
completed construction, then requires the payload's storage released and its credit conserved before
finalization, beside the loss the finalizer still refuses: it must fail naming
`standalone cleanup did not finish before finalization`. Automated red/restored-green qualification
is pending.

`lost-turn-observer-invoked.patch` presents an already-invalid recording to a turn observer.
`lost_turn_skips_history_observation_and_retains_its_publication` requires the observer skipped, the
publication retained, and the original loss snapshot returned without changing its turn.
`observer-invalidation-unchecked.patch` removes the shared outcome guard's post-observer integrity
read. `observer_invalidation_and_unwind_retain_the_acquired_outcome` invalidates the recording
inside observation, both returning and unwinding, and requires the outcome and loss together.
Automated red/restored-green qualification of both controls is pending.

`free-scheduler-restored.patch` restores a free scheduling entry point; the `lifecycle_authority`
source census rejects it. `cleanup-observer-unwind-propagated.patch` lets an observer unwind
interrupt a defined drain; the cleanup witness requires all remaining units executed and the
original observer failure returned. `worker-join-failures-discarded.patch` discards the shared
worker batch's join failures; its witness requires every worker panic collected after every join.
Automated red/restored-green qualification of these controls is pending.

`cleanup-loss-snapshot-replaced.patch` makes the drained cleanup schedule (`reclaim_by`) overwrite
its first recording-loss snapshot with each later turn's;
`drained_cleanup_keeps_the_loss_turn_when_its_bound_is_exceeded` requires the snapshot of the turn
the loss occurred at. `cleanup-later-loss-discarded.patch` drops a recording loss found after an
earlier observer failure; `drained_cleanup_retains_loss_after_an_earlier_observer_unwind` requires
both returned together. `ratchet-eligibility-unfiltered.patch` holds every recorded tightness row to
every build, its requirement ignored; `the_ratchet_holds_each_row_to_its_cases_eligibility` requires
a build without `hashbrown` to pass its own record. Automated red/restored-green qualification of
these controls is pending.

The recording-budget controls cover its authority and publication boundaries.
`budget-raw-evidence-public.patch` makes `Budgets::measure`, which pairs a capacity with the
evidence measured under it, public; `execution_cleanup_and_worker_startup_have_one_authority` names
the raw budget evidence it exposes. `budget-construction-capacity-public.patch` makes the
construction driver's capacity-taking entry public; the same census refuses every public capacity
parameter, return type, callback type and field, `support::recorded_run_short` its one exception,
and `short-recording-enlarged.patch` lets that entry size a recording at or past the default;
`a_short_recording_never_enlarges_the_default` requires each refused.
`budget-membership-unchecked.patch` lets an undeclared fixture reach capacity selection;
`an_undeclared_or_unmeasured_fixture_is_refused` requires it refused as undeclared.
`budget-duplicate-accepted.patch` lets a fixture begin again after it was measured;
`a_fixture_measured_twice_is_refused_and_keeps_its_measurement` requires the second run refused.
`budget-observer-measured-prematurely.patch` measures a fixture before its driver and its evidence
observers return; `a_failed_evidence_observer_measures_nothing` requires a failed observer to leave
no measurement. `budget-unfinished-drop-accepted.patch` accepts a family dropped unfinished;
`a_family_dropped_unfinished_is_refused` requires the drop refused.
`budget-incomplete-family-published.patch` publishes a family missing a fixture;
`incomplete_publication_preserves_previous_evidence` requires the publication refused and the
previous record intact. `budget-authorization-unchecked.patch` accepts any recording flag;
`recording_requires_the_exact_selection_name` requires other families, representations, rigor
layers, witness sizes and non-filename values refused.
`budget-control-authorization-inherited.patch` lets gate subprocesses inherit recording flags;
`controls_cannot_inherit_recording_authorization` requires them absent in the child.
`budget-family-unlisted.patch` removes a family from the launch inventory;
`every_budget_family_has_one_fixture_entry_and_one_launch_identity` requires every family a test
declares listed exactly once and every record and launch identity unique. Automated
red/restored-green qualification of these controls is pending.

`acquisition-drop-unsettled.patch` makes a record acquisition token dropped holding credit settle
nothing (`reclamation/owned.rs`, `Acquisition`'s `Drop`): its `Pending`, the owning custody of both
its retained slots (the grant's write and the release), is forgotten whole in place of
`Pending::settle_all`, so neither the explicit forfeit nor `Retained`'s own drop fallback records
anything, while the granted block's release (`release_granted`) and the scope reference's release
still run. The token's owner capability is leaked with it. Witnesses, in `reclamation/owned.rs`'s
tests: `a_dropped_acquisition_forfeits_into_the_admitting_family` must fail on the admitting
family's forfeit delta (zero, not the held write, or write and release), read from that family's
ledgers after the token is gone and independent of any recording; and
`a_dropped_acquisitions_forfeit_is_recorded_before_its_session_finishes` must fail with the missing
forfeit beside the session's refusal to finish (`Incomplete::Live`, the leaked owner and
obligations), both read before either is asserted. The refusal alone is not the accounting defect's
evidence. Not yet seen red.

`owner-drop-unsettled.patch` makes a decode scope authority dropped uninitialized holding credit
settle nothing (`DecodeOwner`'s `Drop`): its `Pending` is forgotten whole in place of
`Pending::settle_all`, so the scope block's admitted write and release reach no ledger, while a
partially initialized block is still freed and an initialized scope still abandoned to its terminal
drain. Witnesses: `an_uninitialized_owner_dropped_holding_credit_settles_it` and
`an_owners_obligations_each_settle_into_their_own_family` must fail on the admitting families'
forfeits, and `a_dropped_owners_forfeit_is_recorded_before_its_session_finishes` with the missing
forfeit beside the session's `Incomplete::Live`. Not yet seen red.

`held-credit-unreported.patch` makes the one custody traversal of a held acquisition (`stable.rs`,
`Pending::observe_custody`) report its grant's obligation alone, leaving out its release slot. A
byte buffer's payload release, admitted at `ReleasePayload` and held in the construction's pending
until its request is granted, is then in the ledgers and in no reported custody, so the held credit
the custody projects (`Standalone::held_credit`, `total_held` over `observe_custody`) falls short of
the ledgers' `A - C - F`, and `tests/held_credit.rs` `a_buffers_held_credit_is_its_ledgers_held`
must fail conservation (`against held`) at the step whose payload request is refused. Bindings
report no obligations of their own; the pending is the one reporter. The same patch is also detected
through the refinement machine by
`a_refused_requests_held_obligations_are_each_checkpointed_under_their_owner`: a text's metadata
block request refused with its write and release held in the root pending, the checkpoint after that
step missing the release, and finalization refusing it (`MissingHeld`,
`which its custody did not report`). Not yet seen red.

The arena controls plant defects of a parsed document's arena transfer and cleanup
(`cursor/publication.rs`), each detected by `tests/arena_transfer.rs`, whose runs checkpoint every
transfer and cleanup prefix:

- `arena-permit-omitted-before-owner.patch`: the arena's moved permit is not reported between its
  storage's last part and its owner's write, so
  `every_transfer_part_is_refused_checkpointed_and_resumed_under_another_policy` fails at
  finalization (`MissingPermit`, `which its custody did not report`).
- `arena-permit-under-record-owner.patch`: the permit is reported in the enclosing record's group
  instead of a group of its own owner, so the same test fails at finalization, the record's owner
  reporting a permit it does not hold (`ExtraPermit`, `which it does not hold`). Which of the two
  divergences the machine names is fixed by source: identities order by family then sequence, the
  record's owner is minted at the operation's first step and the arena storage's deferred owner at
  its first acquisition later in the same family, and the machine walks reported owners in that
  order, so the record's owner is examined first. The test asserts that order from the production
  traversal.
- `arena-permit-reported-twice.patch`: the permit is reported twice, so the same test's first
  checkpoint after the permit moves is refused by the collector (`DuplicatePermit`). The refusal is
  kept as the run's defect, no checkpoint stored (`tests/support/lifecycle.rs`, `capture`): the run
  goes on through retirement and cleanup to its finalization, which names it beside what the
  recording finished as.
- `arena-release-skipped-after-owner.patch`: cleanup drops the permit only when the owner's stage
  was never made, so `a_parse_cancelled_at_every_transfer_prefix_reports_its_arena_once` fails once
  a cancellation follows the whole transfer (`the arena's permit outlived its cleanup`): the live
  bytes left once every capability is dropped, recorded as the run's defect beside the recording's
  own refusal of the leaked permit.

None is yet seen red.

`acquisition-drop-reference-first.patch` makes a record acquisition token dropped after its scope's
owner release its scope reference before settling its pending (`reclamation/owned.rs`,
`Acquisition`'s `Drop`): the last reference then frees the abandoned scope before the token's
forfeit is recorded. `an_acquisition_outliving_its_owner_forfeits_before_the_scope_is_freed` reads
the order from its finished session, the token's `Cancelled` forfeit before the scope block permit's
`Released`, and must fail naming it. Not yet seen red.

`plan-preparation-undropped.patch` leaves an owned preparation's drained preparation in its record
instead of dropping it in place (`encoding.rs`, `Planned`'s `reclaim_step`, `ReclaimPreparation`).
The record's block runs no destructor, so each of the preparation's arenas keeps a pending whose
owner holds its session's store.
`a_plan_records_cleanup_releases_every_capability_and_admits_nothing_after_done` (`encoding.rs`,
`plan_record`) finishes each run's session after its scope shuts down, and the published run's
finish is refused live: it must fail naming `the run's recording is no evidence: Live(`. Seen red:
`a plan record, cut None: the run's recording is no evidence: Live(6)`; green with the patch
reversed.

`storage-tenant-short-of-peak.patch` restores the storage-resumption fixture's tenant to 4 KiB
(`tests/resumable/native_schedules.rs`). Released, it leaves the blocked decode short of its peak,
so no release lets the same decode finish; the fixture's capacity check against the unobstructed
decode's measured peak must refuse it first, naming `cannot hold the decode's peak`. Seen red:
`the pool of 69877 bytes cannot hold the decode's peak of 133733`; green with the patch reversed.

`invalidation-last-cause-kept.patch` makes a session's invalidation keep its last cause instead of
its first (`src/bounded/policy/record.rs`, `exhaust`). Four workers over one pool of eight permit
records then report the foreign pairings that follow the exhaustion, and
`concurrent_workers_each_name_the_first_invalidation` (`tests/support/lifecycle.rs`) must fail
naming `a worker named another first cause`. Seen red: workers and the finalization named
`ForeignOwner`; green with the patch reversed.

`recording-loss-skips-finalization.patch` makes the recorded run's finalizer
(`tests/support/lifecycle.rs`, `recorded_run_with`) panic with the body's finding before it reaches
`concluded`: the driver's stop reaches the caller alone, and the session is never finished nor its
refusal named. `a_driver_stops_at_the_turn_its_recording_runs_out_of_event_slots` must fail naming
`the run's finalization was skipped`. Seen red: the report was the loss alone,
`the run's recording became no evidence (Exhausted, first by Some(Events)) at turn 15`, with no
finalization suffix; green with the patch reversed.

`driver-evidence-unchecked.patch` makes every driver's one integrity read
(`tests/support/lifecycle.rs`, `lost`) report nothing. A grant refused `Unrecorded` once the permit
records ran out then reaches the caller as the operation's own refusal, its cause lost:
`a_driver_stops_at_the_turn_its_recording_runs_out_of_permit_records` must fail naming
`the stop returned is not the recording's loss by Permits`. Seen red: the body returned
`Driver("the operation failed: Refused(Unrecorded)")`. The event-slot witness is refused by the same
plant, every driver's turn reading through `lost`: the copy outgrowing its slots completes with no
stop, and `a_driver_stops_at_the_turn_its_recording_runs_out_of_event_slots` must fail naming
`the body returned the driver's stop`. Seen red; both green with the patch reversed.

`btree-arena-owners-undropped.patch` makes a whole B-tree's cleanup
(`src/bounded/decode/construction/in_place/btree/cleanup.rs`, `ReleaseArenas`) free its metadata
block without first dropping its four released arenas in place. The block runs no destructor, so
each arena's pending owner, made by its first acquisition, outlives the run:
`tests/owned_physical_failure.rs` `terminal_tree_cleanup_allocates_nothing_in_either_drop_order`
must fail naming `the run's recording is no evidence: Live(4)`. Seen red as the production defect
itself, before the arenas were dropped (the trace case `owned decode BTreeMap<u64, u64>` refused
alike); green with the patch reversed.

`fixture-loss-drops-findings.patch` makes the fixture runner (`tests/resumable/native_harness.rs`,
`every_fixture`) return a lost recording alone, dropping the failures found before it. Two joined
workers each fail fixture 0 and lose a session of 64 event slots in fixture 1:
`an_earlier_fixture_failure_and_a_recording_loss_both_reach_finalization` must fail naming
`each worker returns its earlier failure beside the loss`. Seen red: `(0, 2, 2)` returned against
`(2, 2, 4)`, the finalization naming 2 defects; green with the patch reversed: both earlier failures
and both losses returned, no fixture run after a loss, the finalization naming all 4 and refusing
the recording by `Events`.

`text-continuation-reused-live.patch` marks a preparation's published text continuation for its next
text's initialization without destroying it (`encoding.rs`, `Preparation`'s advance): the next
text's raw initialization writes over the continuation's arenas' and its output's live owners, whose
session references then outlive the run. `every_text_continuation_is_destroyed_before_its_next_text`
(`encoding.rs`, `bound_tests`) finishes the session of a three-text preparation and must fail naming
`the preparation's recording is no evidence: Live(`. Seen red:
`refusing false, cut None: ... Live(9)`, three owners left live by each of the reused continuations;
green with the patch reversed.

`plan-prefix-release-unrecorded.patch` records an owned preparation's incomplete-prefix release as
`Prefix::EMPTY`, the unstarted prefix, instead of releasing it (`encoding.rs`, `Planned`'s
`reclaim_step`). A step after `Done` then takes the incomplete-prefix branch again and admits
`PLAN_TRANSITION` a second time. The shared released-prefix witness (`construction/operation.rs`,
`cuts::every_cut`), run by
`a_plan_records_cleanup_releases_every_capability_and_admits_nothing_after_done`, steps every cut's
record once more after `Done` and must fail naming `a step after Done admitted`, at the first cut
inside the prefix. Seen red: `a plan record, cut Some(0): a step after Done admitted`; green with
the patch reversed.

`window-cleanup-understated.patch` counts the preparation's window arena as one cleanup unit while
it is unreleased (`encoding.rs`, `Preparation::reclaim_remaining`), as a plain-data clear would be.
The window arena holds two typed parts per open cursor, each drained by its own admitted unit
(`Storage::reclaim_step`), so its count is `len + 3`, never one.
`preparation_cleanup_is_bounded_at_every_cut` (`encoding.rs`, `bound_tests`) cancels a nested-map
preparation after every step, cleans it up with each call refused once and then admitted, and must
fail naming `calls remained after call` at a cut that holds open cursors. Not yet run: red and green
unobserved.

`window-malformation-gated-on-finished.patch` gates the preparation's terminal malformation check on
an unfinished preparation again (`encoding.rs`, `Preparation::reclaim_step`). Custody left malformed
when a terminal error finished the preparation is then closed at cleanup entry without invalidating
its session. `malformed_custody_after_a_terminal_error_still_invalidates` (`encoding.rs`,
`bound_tests`) holds a live acquisition with no credit part, marks the preparation finished and
steps its cleanup, and must fail naming
`malformed custody after a terminal error was not invalidated`. Not yet run: red and green
unobserved.

The window custody's mechanism controls, one plant per mechanism, each refused by the witness that
exercises it. None has been run yet: red and green are unobserved for every one.

- `window-second-part-skipped.patch` drops the second part a pair append takes (`storage.rs`,
  `Spare::push_pair`). A cursor is then published beside half its pair.
  `cursor_publication_is_whole_and_a_refused_reservation_fetches_nothing` (`encoding.rs`,
  `bound_tests`) counts parts against cursors after every step and must fail naming
  `a cursor without its whole window pair`.
- `window-append-allocates.patch` grows the allocation inside the pair append.
  `pair_append_is_atomic_at_the_reserved_capacity_boundary` (`storage.rs`, `tests`) must fail naming
  `pair append allocated`.
- `window-premature-publication.patch` fetches the root instruction and advances the instruction
  index before the step's admission (`encoding.rs`, `Preparation::advance`). The refused-reservation
  witness above counts the root's fetches across a refused step and must fail naming
  `a refused step fetched an instruction`.
- `window-traversal-skips-part.patch` skips the first old-allocation element of a relocating
  traversal (`storage.rs`, `for_each_mut`).
  `window_custody_is_whole_and_closed_in_order_at_every_relocation_boundary` (`encoding.rs`,
  `bound_tests`, under `hashbrown`) closes the window arena at every growth cut and must fail naming
  `a capability survived the terminal close`.
- `window-end-before-settlement.patch` swaps the terminal close's passes (`encoding.rs`,
  `forfeit_windows`). The same witness must fail naming
  `an acquisition ended before every credit was settled`.
- `window-end-omitted.patch` drops an acquisition instead of ending it (`encoding.rs`,
  `end_window_acquisition`). The same witness must fail naming `each acquisition ended once`.
- `window-remint-on-retry.patch` mints a fresh window acquisition on every retry (`buckets.rs`,
  `BucketCursor::step`). `preparation_repeated_refusal_admits_the_window_exactly_once`
  (`tests/held_credit.rs`) refuses the window's admission four times and must fail naming
  `refusal replaced the credit-free acquisition`.
- `window-wrong-origin.patch` gives a window's credit the performing budget's origin at every spend
  (`buckets.rs`, `BucketCursor::step`). `preparation_continues_a_window_across_families` settles
  under a third family. Its spends then carry an identity of that family, which the refinement
  machine refuses at finalization: the run must fail naming
  `the run's recording does not refine the protocol`.

`retirement-record-left-unqueued.patch` links a retired record into the scope queue without moving
its custody from `Handle` to `Queued` or publishing the `Queued` custody event (`reclamation.rs`,
`Reclaimer::enqueue`). The queue then reports the record's permit at stage `Handle`.
`a_stopped_decoder_queues_every_record_it_held` (the support crate's `lifecycle.rs` tests) steps a
typed decode until it holds records of its own beside its input's, retires it as
`Retirement::Stopped` through the one orchestration, and must fail naming
`the value's Handle record`: the comparison, scoped to the permits the stopped decoder itself
reported, requires every `Handle` record it held to be `Queued` afterwards. Not yet run: red and
green unobserved.

The five `pending-settle-wrong-origin-*` rows run the same patch as `pending-settle-wrong-origin`
through the decode scope's four-family provenance cases (`reclamation/owned.rs`): the grant's write
admitted under a, its release under b, its storage under c, its cleanup under d. Every settlement
lands in a detached family, so a's ledgers record no consumption or forfeit, which each case's
per-family check names first. A defect settling into the performing policy's family cannot be
planted: held credit owns its origin and no settlement path receives a budget's origin. Not yet seen
red.

The proof controls plant defects of the numeric reduction, the head writer and parser, the scalar
profile and the key comparison (register item 4). Each is refused by a Kani harness that states its
obligation from the specification, or, for binary16 and binary32, by an exhaustive native test: a
NaN payload kept (`float-nan-payload-kept`), the binary32 width skipped (`float-f32-width-skipped`),
the binary64 and binary16 validators accepting a reducible value
(`float-f64-validator-accepts-reducible`, `float-f16-validator-accepts-reducible`), a head one byte
longer than its shortest (`head-shortest-one-late`), a parser accepting a non-shortest head
(`head-parser-accepts-nonshortest`), the negative range widened past `i64::MAX` in the one
integer-wire rule every decoder calls, `decode::negative` (`decode-negative-range-widened`), the
canonical NaN's payload changed against the specified `7e00`, which the reference states
independently of the implementation (`float-canonical-nan-payload-changed`), the key order reversed
(`key-prefix-order-reversed`), a turn's window undercharged with ordering unchanged
(`key-window-undercharged`), a first turn short of the quantum (`key-turn-short-of-quantum`), a
resumed turn's first pair left uncompared, refused by the long-key harness
(`key-resumed-pair-skipped`), and `undefined` (simple 23) decoded as `null`, refused by the scalar
profile harness (`decode-simple-undefined-accepted`). A Kani control is judged by the one harness
its row names, checked alone (`tests/gate/src/controls.rs`, `checked_alone`). None is yet seen red.

The binary32 test runs the run's layer's domain (`DCBOR_RIGOR`): every pattern under `exhaustive`,
which `run_tests.sh` runs once optimized, and the reduction rules' edges under `fast` (`float.rs`,
`f32_edges`), every developer run's. `float-f32-width-skipped` fails in both, at `0x00000001`, the
least subnormal, the first pattern binary32 holds and binary16 does not.
`f32-edges-high-mantissas-dropped.patch` drops the edge set's high mantissas cleared below each bit,
and the edge set's own reach check (`the_f32_edges_reach_every_reduction_class`) must name 65504,
the greatest binary16, `0x477fe000 is not a fast edge`.

The binary16 conversion controls close each link of the numeric reduction's composed evidence: the
binary64 reduction proved under a conversion contract, the reference classifier proved consistent
with its widening, and the contract checked exhaustively on each production branch of half's
dispatch, the accelerated one natively on an f16c host and the software one under each Miri model.
The gate requires both branch runs, each marker agreeing with the build and `Cargo.lock`, as rows of
its results (`tests/gate/src/conversion.rs`):

- `float-conversion-contract-broken.patch` breaks the conversion contract stub so a held binary16
  value converts one unit off; the binary64 reduction proof must fail, showing that the theorem
  depends on exact conversion of held values.
- `float-classifier-over-permissive.patch` makes the reference classifier name a value binary16 does
  not hold (a NaN); reference consistency must fail.
- `float-classifier-misses-held.patch` makes it miss values binary16 holds (the zeros); reference
  consistency must fail.
- `float-reference-widening-wrong.patch` breaks the reference's subnormal widening; the exhaustive
  contract test must fail, natively and under Miri, showing that it compares the reference widening
  against the real implementation.
- `float-contract-oracle-broken.patch` breaks the contract test's own round-trip oracle; the test
  must fail on the real conversion both natively and under Miri, showing that the oracle runs on
  each branch.
- `float-adapter-round-trip-broken.patch` breaks production's narrowing adapter for one held value
  (1.0); the exhaustive contract test must fail natively and under Miri. It validates the witness at
  the adapter boundary, not half's dispatch.
- `float-classifier-misses-infinities.patch` makes the reference classifier name neither infinity,
  both of which binary16 holds; reference consistency (`every_held_value_is_named`) must fail, and
  the exhaustive test at `0x7c00` ("the reference does not name a held value").
- `reference-infinity-sign-dropped.patch` reduces both infinities to `0x7c00` in the reference
  (`reference::reduce`); its fixtures must fail at `-inf` and the exhaustive test at `0xfc00`
  ("reduction differs from the reference").
- `half-version-stale.patch` names a `half` version `Cargo.lock` does not resolve as the branch
  marker's; `the_branch_marker_names_the_resolved_half` must fail, so the marker the gate reads
  always names the resolved dependency.

The claims are scoped: the reduction is proved under the contract, the conversion's correspondence
is exhaustively checked on each branch, and the production guarantee follows by their composition.
half itself is never proved. None is yet seen red.

The ledger controls plant defects of the credit ledgers' one update rule (`policy.rs`,
`Ledgers::record`), refused by the Kani harness that holds it to the documented component-wise
checked updates (`bounded::policy::proofs`):

- `ledger-held-part-consumed.patch` counts an admission's held part in C as well; ledger arithmetic
  must fail, and legal-transition conservation with it.
- `ledger-forfeit-consumed.patch` records a forfeit into C instead of F; ledger arithmetic must
  fail.
- `ledger-violation-cleared.patch` lets a later fitting event clear the violation flag; ledger
  arithmetic's stickiness check must fail.
- `retained-forfeit-unrecorded.patch` makes a held obligation's forfeit (`bounded.rs`,
  `Retained::forfeit`) take its remaining work and record nothing into its origin; legal-transition
  conservation (`legal_transitions_conserve_every_family`, "legal transitions conserve: A = C + F +
  H") must fail on any forfeited obligation.
- `ledger-delta-hides-violation.patch` clears a delta's violation when the earlier snapshot was
  already violated (`Credits::checked_sub`); the delta harness's "a delta taken at or after a
  violation shows it" must fail.
- `ledger-violated-reported-conserved.patch` ignores the violation flag in
  `Credits::conserved_with`; "a violated ledger is never reported conserved" must fail.

Conservation is proved over legal transitions only. The invalid ones are refused elsewhere:
`Retained` settles exactly what it holds, by value, and the refinement machine refuses an
over-settled or twice-settled obligation as overdrawn (`tests/refinement`,
`an_over_settled_or_twice_settled_obligation_is_refused`). None is yet seen red.

The recurrence controls plant defects of the counts the arena and B-tree bounds rest on, each
refused by a Kani harness against an independent reference (`bounded::growth_proofs`,
`bounded::encoding::proofs`):

- `grown-capacity-from-empty.patch` grows an empty arena to two, not four (`bounded.rs`,
  `grown_capacity`). The growth rule's exactness, the recurrence's step from the empty arena and the
  closed form of `owned_growth` must each fail: the step proof is seen red against the production
  rule, not only against its own model.
- `growth-one-too-many.patch` counts a full arena as needing one more growth (`owned_growth`); the
  closed forms of `owned_growth` and of `storage_growth`, which composes it, must fail.
- `storage-growth-releases-miscounted.patch` counts one release too few per retained arena
  (`storage_growth`); its closed form must fail.
- `growth-base-case-nonempty.patch` gives the harness's closed form a capacity of four before any
  growth (`growth_proofs.rs`, `closed`); the base case, "no growth, no counts", must fail, so the
  reference is not trusted unchecked.
- `tree-height-base-off-by-one.patch` starts the height recurrence at 10, not `m(2) = 11`
  (`encoding.rs`, `tree_height`); a ten-entry tree is given two levels, and the reference's least
  count must fail.
- `levels-off-by-one.patch` adds one level to `floor(log2 n) + 1` (`encoding.rs`, `levels`); the
  bracket must fail.
- `tree-height-reference-off-by-one.patch` makes the harness's reference least count one too many
  (`encoding/proofs.rs`, `fewest`); its base, "the recurrence starts at m(2) = 11", must fail, so
  the reference is not trusted unchecked.

The closed form of `storage_growth` is a formula over the retained arena's per-growth constants
(`storage.rs`: four writes of at most a quantum, a staging block of at most a quantum, two releases
per growth). Its correspondence with a real arena's admissions is held by
`bounded::decode::storage::tests::every_growth_admits_exactly_its_bound` over its stated count
domain: checked evidence there, not proved. Beyond that domain the correspondence rests on the
transition argument in that test's documentation, each growth's steps read from `storage.rs` and
related to one step of the recurrence plus a fixed overhead: an argument reviewed against the
source, not checked by any harness.

The whole-operation controls plant defects of six operations' bounds, each refused by a Kani harness
over its stated domain:

- `emit-bound-gaps-uncounted.patch` leaves the segments that header gaps end early unpriced
  (`writer.rs`, the emission terms' `of`); the emission no longer completes within its bound's steps
  (two gaps, two encoded bytes: five units against four, derived from the source, not observed).
- `header-bound-validation-unpriced.patch` prices the header validation's bytes at zero
  (`header.rs`); the cursor's admissions exceed its bound.
- `preparation-bound-plan-unretained.patch` charges the published plan nothing retained
  (`encoding.rs`, `encode_bound`); every successful encoding keeps its plan arena's permit, so the
  retained check must fail.
- `decode-bound-arena-halved.patch` grows the document arena for half the input (`decode.rs`); a
  one-byte scalar's document holds a four-entry arena the bound no longer retains.
- `text-bound-buffers-unpriced.patch` charges the normalization buffers nothing (`text.rs`,
  `validation_bound`); a text the quick check cannot prove normal (`e` and U+0301, three bytes) is
  normalized into buffers the policy grants (`text.rs`, `normalize`), so the request check must
  fail.
- `string-retained-unpriced.patch` counts the string decode's published string as retaining nothing
  (`string_cursor.rs`, its bound); the string harness's "the string decode's string retains no more
  than its bound" must fail.

`owned-output-request-unpriced.patch` prices the owned write's output request at nothing
(`writer.rs`, `EmitTerms::owned`); every other emission term is work alone, so the owned-emission
harness's "the owned write requests no more than its bound" must fail on any non-empty plan.

Two controls plant a step that changes its cursor before its admission, so a refused step keeps the
change the `Resumable` contract forbids:

- `header-finished-before-admission.patch` marks the header cursor finished before its validation is
  admitted (`header.rs`); refused there, its position (`next_work` gone) differs, and the header
  harness's "a refused step changes nothing the cursor holds" must fail.
- `string-inspect-advanced-before-admission.patch` moves the string decode's phase past its
  inspection before admitting it (`string_cursor.rs`); refused there, the decode's position (its
  phase) has moved, and the string harness's "a refused step changes nothing the decode reports"
  must fail.
- `gap-passed-before-admission.patch` passes a header gap before its unit is admitted (`writer.rs`,
  `PlanView::segment`); refused there, the emission position has moved, and the emission harness's
  "a refused unit moves nothing" must fail.

The refusal controls plant a policy refusal swallowed where it must propagate, one site per harness
that schedules a refusal at any one attempt and any one request (`proof_budget.rs`,
`Counting::scheduled`):

- `reserve-refusal-swallowed.patch` returns `Ok` from `Owned::reserve` when its allocation request
  is refused (`bounded.rs`), forfeiting the growth's credit and growing nothing; the decode's arena
  push then completes, and the decode harness's "a refused decode returns its refusal" must fail.
- `validation-pass-refusal-swallowed.patch` ignores a refused comparison pass in strict validation
  (`text.rs`, `is_normalized`); a text the quick check leaves unproven is validated anyway, and the
  validation harness's refusal check must fail.
- `segment-refusal-swallowed.patch` emits a segment whose admission was refused (`writer.rs`,
  `PlanView::segment`); publication returns its encoding, and the preparation harness's refusal
  check must fail.

Emission is bounded over plans of at most 130 bytes and two gaps, the header over inputs of at most
nine bytes, preparation over roots of at most two leaves (integers of any value, byte strings and
texts of at most two bytes), decoding over inputs of at most four bytes at nesting limits up to two
under both text policies, and strict validation over texts of at most six bytes. Each failing
assertion above is derived from the source, not observed. None is yet seen red.

The retained text encoder's premise of the preparation bound is a native exhaustive test, not a
harness:
`bounded::text_cursor::tests::every_alphabet_text_is_encoded_within_its_bound_at_every_refusal_and_cancellation`
runs every text of up to five bytes over the alphabet that holds each shape entry once, unrefused,
refused once at each attempt and at each request, and cancelled before each step. Checked there, not
proved. `text-cleanup-output-kept.patch` keeps the encoder's output permit past its cleanup
(`text_cursor.rs`, `reclaim_step`); a text cancelled after its output is allocated still holds it
when cleanup reports done, and the test's release check must name it. Not yet seen red.

The dispatch-depth controls plant defects of the two depth checks (`reclamation.rs`,
`admitted_depth` and `Depth`):

- `standalone-depth-unchecked.patch` removes the static check from `Standalone::new`; the
  compile-fail fixture `standalone_depth_beyond_limit.rs`, a root declaring one past
  `MAX_DISPATCH_DEPTH`, must then compile, which trybuild reports. The check at
  `Reclaimer::allocate` is the same definition and is not removed.
- `depth-unchecked.patch` makes the run-time comparison against the root's declared depth always
  pass (`Depth::descend`). A binding declaring one level and dispatching its scalar as a part then
  builds and is cleaned past its declaration, and each of the two tests must fail by name
  (`a_binding_understating_its_depth_is_refused_on_build`, `..._on_cleanup`): the build case at its
  refusal check, the cleanup case at its own.

`scope-end-in-place.patch` drops an input task's scope reference in place inside its cleanup
(`input.rs`, `release_scope`) where it must defer it. The release-site census
(`every_scope_reference_end_is_classified`, a syntax walk over `owned.rs`, `input.rs` and
`operation.rs` against one table of every site, its function and whether it runs inside a cleanup
step) must name the new site as unlisted. Implicit drops have no site; the nesting oracle in
`drain_terminally` aborts any test that starts a drain inside another.

The census identifies a site by its module, its function and the full tokens of its impl's self type
and trait, so a same-named function of another impl, or of a same-named type in another module, is a
distinct site. Three controls plant a scope reference release the table does not list, each named by
the census's own fault text:

- `scope-release-extra-site.patch` adds a second `release_reference` to `process`:
  `owned process release_reference: x3, the table lists x2`.
- `scope-release-other-impl.patch` adds one to `OwnedRecord`'s `drop`:
  `unlisted: owned <OwnedRecord < '_ , T , A > as Drop>::drop release_reference x1`.
- `scope-release-same-name-impl.patch` moves the owner's release out of `DecodeOwner`'s `drop` into
  the `Drop` of a same-named type in a nested module `twin`: the moved site is
  `unlisted: owned <twin :: DecodeOwner < A > as Drop>::drop release_reference x1`, a site a census
  keyed by the last identifier alone would read as the listed one.

`deferral-inline-drop.patch` releases a scope reference in place where cleanup must defer it
(`reclamation/owned.rs`, `reclaim_under` at `Done`).
`retirement_into_abandoned_scopes_never_nests_a_drain` abandons every scope with its records still
held, checks the pending chain through each scope's outstanding count, then retires the holders
forward and in reverse while measuring the most terminal drains active at once; under the patch a
drain releases the next scope's leaf in place and drains that scope inside itself, and the invariant
"at most one terminal drain active" must fail.

`depth-not-restored.patch` leaves the cleanup level raised after a dispatch returns
(`reclamation.rs`, `Cleanup::descend`).
`successive_siblings_each_enter_the_level_after_their_parents` dispatches two resource-free siblings
under one capability declaring two levels; the second is refused at its parent's level and the test
must name it. No scope, record or permit is held, so the control leaves nothing unreclaimed.

The deferral controls plant defects of the scope worklist's processing (`reclamation/owned.rs`,
`process`), each against `several_handles_of_one_scope_released_in_one_step_are_all_performed`,
three references of one abandoned scope deferred in one step:

- `deferral-one-release.patch` performs one release where `n - 1` are owed; the count still clears,
  one reference leaks and the scope block is never freed, which the test's release check must name.
- `deferral-all-releases-first.patch` performs all `n` releases before the count is cleared; the
  last frees the block and the clear that follows touches freed memory, which Miri must report under
  both aliasing models.

The abandoned-scope controls plant defects of an abandoned scope's shared custody
(`reclamation/owned.rs`, `ScopeRef::observe_abandoned` and the scope's dispatch unit), each against
`an_abandoned_scope_is_reported_once_by_its_handles_under_its_owner`, two record handles observed
after their scope's authority is dropped. Each must fail naming "the abandoned scope block, reported
once under its owner":

- `abandoned-scope-unreported.patch` stops a record handle's observation at its record, so no handle
  reports the scope block it keeps alive; in a recorded run the refinement machine names the block's
  permit missing at that checkpoint.
- `abandoned-scope-reported-twice.patch` removes the sink's `shared` gate, so every handle reports
  the block; in a recorded run the collector refuses the capture as `DuplicatePermit`.
- `abandoned-scope-owner-misattributed.patch` writes the dispatch unit with no owner, so the block
  is reported in a group no stored owner names; in a recorded run the collector refuses the capture
  as `Unowned`.

`record-payload-custody-unobserved.patch` stops a record's observation at its block's permit
(`reclamation.rs`, `Record::observe_custody`, which every holder of a record calls, its handle and
the queue alike), so a payload holding other records reports none of them. The same witness's
grouped observation of the holder's custody, taken before the drain, must fail naming "the holder's
custody does not report its three held records".

The unsafe-impl census (`tests/unsafe_census.rs`,
`every_unsafe_impl_of_a_governed_trait_is_listed_and_names_its_obligations`) governs every public
unsafe trait an implementer upholds for the engine: each trait's `# Safety` section labels its
obligations (`UNSAFE_TRAITS`), every shipped impl, the derive's generated ones included, is listed
(`UNSAFE_IMPLS`), and its `// SAFETY:` comment names each label. Two controls plant a gap the census
must name:

- `reclaim-safety-count-unnamed.patch` drops the `count` justification from the scalar bindings'
  `Reclaim` SAFETY comment (`in_place/scalars.rs`):
  `unsafe impl Reclaim for macro_rules! scalar: its SAFETY comment names no ["count"]`.
- `derived-variants-unlisted.patch` removes the derive's generated `Variants` impl from the listing:
  `unsafe impl Variants for expand: not listed`.

`deferral-clear-unchecked.patch` replaces the compare-exchange from 1 to 0 in `process` by a store.
A deferral another thread makes between the load and the store is then cleared without its release,
so the scope block outlives the drain. The concurrent model `deferral_races_processing`
(`src/sync/models.rs`), whose workers reclaim records of an abandoned scope in place, must fail in
some interleaving under loom and under shuttle: "deferral racing processing: a record or the scope
outlived the drain".

Overstated declarations are sound and kept: the derive declares five levels more than it dispatches
per derived level, for the stack frames the dispatch count does not see; `Parsed` one, for its input
handle chain's frames; `Option` and `StableOption` one each, which no frame accounts for, kept for
the declarations composed from them. Each margin is stated beside its declaration and pinned exactly
by one of two censuses, whose tests are source-reviewed here: the bindings' (`in_place.rs`,
`tests::adversarial`, `every_bindings_declaration_exceeds_its_dispatch_by_its_recorded_margin`,
through the standalone driver: 0 for the leaves, sequences and tree, 1 for the options, 5, 10 and 15
for derived records one, two and three levels deep, 5 for a derived enum) and the records'
(`construct.rs`, `depth`, `every_records_declaration_exceeds_its_dispatch_by_its_recorded_margin`,
through their public steps: `Parsed` 1, `Constructed` 0 by its value and 1 by its document,
`Planned` 0). A change in either direction fails:

- `derive-depth-understated.patch` makes the derive's declaration its deepest field's and 5, not 6
  (`dcbor-derive/src/construction/in_place.rs`); the bindings' census must fail at its first derived
  fixture, `Scalars: declared 6, measured 2`.
- `parsed-depth-margin-changed.patch` makes `Parsed` declare one level more over its input chain
  (`parse.rs`); the records' census must fail at its first case, `Parsed: declared`.
- `constructed-depth-overstated.patch` makes `Constructed` declare one level over its value's
  (`construct.rs`); the records' census must fail at `Constructed, its value: declared`, and
  `a_construction_suspended_at_its_declared_depth_drains_terminally`, whose terminal drain reaches
  the true depth only, must keep its finding "the terminal drain's deepest level".

None is yet seen red.

The CDDL controls plant defects of the CDDL the derives emit, each detected by
`tests/cddl/tests/correspondence.rs` `every_fixtures_cddl_admits_exactly_what_its_decoders_accept`,
which runs every fixture's generated domain through the symbolic decoder, the bounded decoder where
the type has one, and the independent validator (`cddl`, pinned `=0.10.7`), and names each
disagreement by its kind and item:

- `cddl-optional-rendered-required.patch` renders every derived map member required
  (`dcbor-derive/src/cddl.rs`, `member`). A record whose optional field is absent is accepted by
  both decoders and refused by its CDDL: an optionality divergence on `key 2 removed`.
- `cddl-key-off-by-one.patch` renders every member's key one past its own. Every valid sample is
  refused by its CDDL: a domain divergence on `valid`.
- `cddl-tag-omitted.patch` renders a tagged type's rule without its tag. The item with the tag
  stripped is admitted by the CDDL and refused by both decoders: a tag divergence on
  `tag 40000 stripped`.
- `cddl-unknown-keys-forbidden.patch` closes every derived map to the keys no field names
  (`src/cddl.rs`, `map`). A record with an unknown key is accepted by both decoders and refused by
  its CDDL: an unknown-key divergence on `unknown key 99 added`.
- `cddl-range-one-too-wide.patch` renders every integer range one past its maximum (`src/cddl.rs`,
  `integer!`). `Record`'s `u8` field replaced by `u8::MAX + 1` is admitted by its CDDL and refused
  by both decoders: a domain divergence on `key 1 > replaced by u8::MAX + 1`.
- `cddl-domain-tag-kind-dropped.patch` removes the foreign-tag value from the mutation domain's
  kinds (`tests/cddl/src/lib.rs`); the domain's own check,
  `the_domain_holds_every_kind_of_mutation_a_control_targets`, must fail naming the missing
  `replaced by tag 2 around a byte string` item, so a control's item cannot silently leave the
  domain.

The correspondence holds over the generated domain only: its evidence class is checked, never
proved. None is yet seen red.
