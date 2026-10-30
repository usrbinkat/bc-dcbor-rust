# Resumable acceptance coverage

`../resumable_contract.rs` registers the runtime groups below. Paths are relative
to this directory unless otherwise specified. Run with `--features derive,hashbrown`
to exercise generated construction, bucket-indexed map preparation, and their
allocation-failure matrices; `--all-features` on the flake toolchain adds the
standard-library hash map and ordered-collection schemas.

| Requirement | Registered test source |
| --- | --- |
| Header interruption, retained bytes, nonminimal and truncated heads | `native_header_cursor.rs`, `native_schedules.rs` |
| Same-operation decoding, typed construction, externally released capacity | `native_continuation.rs` |
| Payload, key comparison, child completion at every child, trailing-data boundaries | `native_matrix.rs` |
| Long-prefix keys out of order or equal, rejected after bounded comparison | `native_matrix.rs` |
| Exact comparison offsets and literal ordering cases | `native_comparison_cursor.rs` |
| Storage relocation, overlapping permits, retained values, cancellation | `native_storage_cursor.rs` |
| Derived records, newtypes, tags, enum shapes, nested generics, unknown-field policy | `native_derive.rs` |
| Completed field values, output lifetimes, cancellation, failed growth | `native_ownership.rs` |
| Reservation split and merge: zero-sized, refused and foreign transfers, exact capacity | `native_ownership.rs` |
| Ownership at every phase transition (input, parser scratch, partial field, typed output, scratch released) and cancellation | `native_ownership.rs` |
| Physical allocation failure in retained decoding, derived construction, text encoding | `native_heap.rs` |
| Physical allocation failure in preparation, plan ownership, allocation-free emission | `native_preparation_heap.rs` |
| Preparation and emission refusal/cancellation, exact prefixes, shared pool | `native_pipeline.rs` |
| Retained schema encoding, nested generics, enum representations, optional omission, tags, fixed arrays, map-header finalization, physical allocation failures | `native_schema_encoding.rs` |
| `BTreeMap`, `dcbor::Map` and symbolic `CBOR` schemas: canonical key order, canonical collisions, nested and multi-level trees, every major type, out-of-profile negatives, nesting limit, physical allocation failures; walked by the tree's iterator on stable and by the stepped cursor on the forked std | `native_schema_encoding.rs::ordered` |
| Sparse bucket scans ending at the last entry, dynamic-key ordering, canonical duplicate rejection, refusal traces, cancellation, physical allocation failures | `native_dynamic_maps.rs` |
| Deleted-bucket hash maps, entry-advance validation | `native_hash_map_schema.rs` (hashbrown and standard-library maps) |
| Nested dynamic tables as keys and values, derived-field composition, header-gap compaction, repeated refusal, canonical collisions, physical allocation failures | `native_nested_maps.rs` |
| Batched sparse scanning, constant-work plain-data truncation, root map permuted in place under refusal at every preparation and emission step and published only once canonical, shorter-run merge scratch, early duplicate rejection, bytes-times-depth total work | `native_map_review.rs` |
| Literal composition, reordering, leading marks, decomposition, Hangul, radix ordering over both digits of the combining class | `native_text_matrix.rs` |
| Long combining runs with linear turn limits | `native_text_matrix.rs::long_combining_run_requires_retained_progress_not_whole_run_admission` |
| A 100,000-mark canonical sequence accepted, and rejected by one late disordered mark | `native_text_matrix.rs::long_valid_combining_sequence_is_accepted_and_one_late_disordered_mark_rejects_it` |
| Retained text positions and cancellation at progress boundaries | `native_text_progress.rs` |
| QuickOnly refusal and acceptance under suspension | `native_quick_suspension.rs` |
| QuickOnly parity with upstream wherever a scalar or a base-and-mark boundary meets a validation quantum | `native_quick_suspension.rs` |
| Exhaustive Unicode scalar quick-check parity | `native_schedules.rs::quick_only_matches_upstream_for_all_scalars_and_cross_character_cases` |
| Successive refusals on a single operation | `native_repeated.rs` |
| Malformed literals (heads, payloads, UTF-8, surrogates, NFC, key order, duplicates, trailing items, indefinite containers, impossible lengths), truncations, cancellation, positive refusal observation | `native_malformed.rs` |
| Generated inputs, mutations, scalar differential checks, bound overflow | `native_differential.rs` |
| Randomized fresh allowances, zero included, never change results or replay admitted work | `native_differential.rs` |
| Deadline expiration before and between admissions | `native_deadlines.rs` |
| Source-contract defects classified apart from caller refusal; a caller refusal within a write keeps its class and paid prefix | `native_bound_defects.rs` |
| Wrong-sized destinations refused before any admission, refused segments preserving prefix and position, checked work composition | `native_output_bounds.rs` |
| Schema-contract defects (arena cap, counted heads, entry windows, endless nesting), publication in place within the retained bound | `../bounded_adversarial.rs`, `../bounded_extended.rs` |
| Measured step latency for payload decoding and normalization | `native_latency.rs` |
| Large-operation quanta, typed copies, canonical semantics, shared recovery | `native_tests.rs` |
| Concurrent retained decoding and exact capacity reacquisition | `native_schedules.rs::capacity_pool_survives_concurrent_success_and_every_refused_constructor` |
| A storage refusal held until another thread releases capacity, then resumed without replay | `native_schedules.rs::storage_refusal_holds_a_retained_decode_until_another_thread_releases_capacity` |
| Recorded admission baselines of every public operation, each case gated on the feature it is compiled under; recording requires every gating feature | `native_traces.rs`, data in `../data/admission-traces.txt`; `.num-bigint` where bignums are encoded and `.custom-std` over the forked standard library's collections, each and both (`admission-traces.custom-std.num-bigint.txt`) |

## Owned lifecycle targets

Each is its own test binary under `tests/`, driven by `dcbor-test-support`.

| Requirement | Test source |
| --- | --- |
| Input acquisition: every admission, physical failure, and retire, unwind or cancel stop | `owned_input.rs` |
| Inspection: every admission, physical failure, and stop; cancellation independent of a live document | `owned_inspection.rs` |
| Typed decoding: every admission, every cancellation turn, malformed inputs, QuickOnly | `owned_lifecycle_matrix.rs` |
| Each physical acquisition after admission fails and drains | `owned_physical_failure.rs` |
| Owned pipeline (acquisition, decoding, owned preparation, chunked emission) for text, vectors and stable options: every admission, physical failure, and stop; rejected inputs | `owned_pipeline_matrix.rs` |
| Cross-thread retirement and pipeline interleavings | `owned_pipeline_interleavings.rs` |
| Fixed arrays constructed in place and reclaimed element by element; exact length | `reclamation_owner.rs`, `reclamation/schema.rs` |

## Harness and observations

- `tests/support/lifecycle.rs` (the `dcbor-test-support` crate) drives
  production operations through `Resumable` with fresh three-value/64-byte
  turns, checks every step against the contract (`checked`, `contracted`,
  `exhausted`), and derives every turn limit from a production bound
  (`turns`): `decode_turns`, `typed_turns`, `string_turns`, `normalize_turns`,
  `prepare_turns` with `shape`, `emit_turns` and `text_emit_turns`. The owned
  pipeline driver takes its phases' limits from `copy_bound`, `parse_bound`,
  `typed_decode_bound` and `owned_prepare_bound`.
- One matrix seam drives every fault schedule, in the layer `DCBOR_RIGOR`
  selects (`CONTRACT.md`, Test independence): `refusal_matrix` for a single
  resumable operation, `synchronous_matrix` for one that ends at its first
  refusal, `physical_matrix` and `stop_matrix`, and `support::pipeline`'s
  `matrix` for the owned pipeline (acquisition, inspection, typed decoding,
  owned preparation and chunked emission), with refusal, physical failure,
  and retire, unwind or cancel stops at every observed boundary. No test
  holds a fault loop of its own; `repeated_refusal` and `reason_matrix` are
  the seam's stages for repeated refusal of one unit and for refusal
  reasons.
- Stop classes (`tests/support/classes.rs`) reduce the fast layer's stops: a
  boundary's class is its state's cleanup obligation, every count cleanup
  never reads dropped, each arena by its growth stage, its permits and
  whether it holds anything (its elements only while staging or
  relocating, where cleanup drains per element). The exhaustive layer
  requires every member of a class to clean up with exactly its first
  member's calls (`support::agree`); a planted class merging different
  custody is rejected (`owned_inspection.rs`). Unclassified, so every stop
  runs in both layers: the scope boundary, before anything is held; the
  published plan, which only retires; every emission boundary, no cleanup
  argument covering a writer's states; and a container's construction
  boundaries (`classes::parsed`), since containers declare no reduction.
- Binding observations and reductions are checked by the observed
  construction driver (`support::construction`, `tests/reclamation_owner.rs`,
  `tests/reclamation/schema.rs`, `tests/owned_btree.rs`): observing twice
  equal, admitting and allocating nothing (`observe_custody`); observation
  complete for custody on every reached state (`support::observation`);
  every declared reduction a simulation of cleanup (`support::certified`,
  for `String`, `ByteString`, native and stable options and derived tagged
  values); every transition in the binding's successor relations, with the
  exact remaining cleanup and the live permits and physical allocations
  witnessed (`support::legal`, `tests/support/legality.rs`, and the tree's
  in `tests/owned_btree.rs`); planted reductions and planted observers each
  rejected; and properties across counts and lengths
  (`properties_hold_across_counts_and_lengths`).
- `tests/support/heap.rs` observes physical requested allocations and injects
  allocation failures.
- `native_harness.rs` holds the suite policy and the preparation matrices,
  which take the expected encoding or the expected rejection.
- `native_bindings.rs` binds the production operations the suite drives and
  holds one deliberately non-compliant operation per contract check, proving
  each check rejects what it guards.
- `native_schedules.rs::bound_assertion_rejects_oversized_instrumentation` checks
  that oversized work is detected.

## Compile-time ownership

Doctests on the production continuation types cover:

- `src/bounded/decode/construction.rs`: references cannot outlive `TypedValue`;
  input cannot mutate while retained by `TypedDecoder`.
- `src/bounded/text_cursor/pipeline.rs`: a writer cannot outlive `PreparedText`;
  the destination cannot be mutated while a writer retains its exclusive borrow.
- `src/bounded/decode/header.rs` and `comparison.rs`: cursor input borrowing.
- `src/bounded/encoding.rs`: preparation input immutability, writer-plan lifetime,
  and exclusive destination borrowing.

The derive UI target is `dcbor-derive/tests/ui.rs`.

## Fuzz execution

`fuzz/fuzz_targets/decode_schedule.rs` drives retained decoding with an observed
admission refusal, same-operation resumption, cancellation, truncation, mutation,
cumulative work comparison, and ownership release. `schema_schedule.rs` exercises
derived preparation, nested arrays and dynamic tables, optional fields,
normalization, same-cursor refusal recovery, cancellation, and allocation-free
emission, within the input-derived `prepare_turns` bound. `owned_lifecycle.rs`
drives the owned typed decode over arbitrary input, then the owned pipeline: a
selected refusal resumed without replay, a selected physical failure, and a
retire or cancel stop, with emission equal to the input exactly when the input
is canonical text. libFuzzer aborts before any unwind, so unwinding stops are
qualified by `owned_pipeline_matrix.rs`. `fuzz/smoke.sh` and `fuzz/qualify.sh`
run every target. Toolchain and execution commands are in `fuzz/README.md`.

## Miri

`../miri-owned.sh` runs the selection in `../miri-suites.txt` under Miri,
each test in a Miri process of its own, under strict provenance, symbolic
alignment checks, host isolation (no file, clock, entropy or environment of
the host; the variables the gate sets forwarded one by one) and both
Stacked and Tree Borrows: the owned suites, `reclamation_owner`, the
ordered-collection schemas and storage cursor of `resumable_contract`, the
abort witnesses in both domains, and the tests chosen to reach what those
do not. Every selection line is listed before any test runs and must name
a test, by its full path or its module; no test is named twice. The tests
that race threads (`race` lines) run once per seed, each seed one schedule.
The union of the classes each model's runs reach must equal the native
run's: a class the native run reaches and Miri does not is a missed unsafe
transition. The gate publishes, per test, model, domain and seed, its
outcome class (`pass`, `undefined_behavior`, `unsupported`, `failed`,
`not_run`), seconds and peak memory in `results.tsv`, under its identity.

`../reach-map.sh` holds the selection to its target: every function of a
module holding `unsafe`, outside test code, reached by some test Miri runs,
and the minimal witness sizes Miri runs executing every region the full
sizes do. The gate refuses to run without a passing map of the same source
and toolchain (`DCBOR_REACH_DIR`): set cover chose the fewest tests, so a
map of other source says nothing of this one.

Miri runs the fast layer: one stop of each kind per certified cleanup class,
and every stop at an unclassified boundary. That one member stands for its
class rests on these premises, each checked natively and not under Miri:

- a class keeps everything a state's cleanup reads (`tests/support/classes.rs`;
  each binding's declared reduction certified a simulation of cleanup over
  every reached state, `support::certified`);
- in the exhaustive layer, every member of each class cleans up with exactly
  its first member's admitted calls (`support::agree`), on the fixtures and
  sizes the suites enumerate.

So two members of a class take the same cleanup units over the same
custody, and differ only in what cleanup never reads. A defect on a path
that reads such a quantity is a path cleanup takes, which the certification
would have separated into classes of their own. What the premises leave
open: a member whose difference matters only beyond the enumerated
fixtures and sizes; and undefined behavior in construction, which the
fast layer reaches at every admission by its one-pass refusal but stops
at only one member per class. The exhaustive evidence counts only when it
ran on the same source and toolchain as the Miri gate (`gate-common.sh`,
`same_source`).

## Resource bounds

Each bound is checked in the module that defines it, against the production
operation it bounds, under the attribution policy (`src/bounded.rs::places`),
which records what each place reported, requested, held at its peak and left
retained. A per-place check passes when every place is within its own term on
every run, and fails, by the same rule, when any witnessed place's term is
removed: both ship in each check below.

Tightness is held by a ratchet, not a fixed factor: each witnessed place's
term, each named joint witness's total and, where a suite records them, every
run's total are recorded in `tests/data/tightness/<suite>.txt`, or
`<suite>.num-bigint.txt` where bignums are encoded, as the exact bound and
use, integers, with the ceiling each is held to (`within-N`, `measured`,
`joint`, `total`, `exact`). Any change fails until it is recorded with
`DCBOR_RECORD_FACTORS=1`; a derived `within-N` ceiling is checked without
rounding. Joint witnesses are named runs, never positions in a suite.

| Bound | Per-place check | Whole-bound checks |
| --- | --- | --- |
| `decode_bound`, `decode_bound_with` | `src/bounded/decode.rs::terms_tests` | each term by two inputs of one length that differ only there |
| `header::heads_work` | `src/bounded/decode/header.rs::attribution` | |
| `retained_decode_bound` | `src/bounded/decode/cursor.rs::attribution` | turn limits of every retained suite |
| `string_bound` | `src/bounded/decode/string_cursor.rs::attribution` | turn limits |
| `text::validation_bound` | `src/bounded/text.rs` | coverage of every text kind; joint witnesses of two- and three-part letters; every run's total recorded; the parts-per-byte maxima exhaustively |
| `text_cursor::encode_bound`, `normalization_bound`, `pipeline::preparation_bound` | `src/bounded/text_cursor.rs` | coverage of every text kind at its own shape and at the worst shape of its length; every encoding's and preparation's total recorded, the worst text's at the worst shape included; the ordering term equal to the ordering's work on runs of one, of two, long, mixed and crossing a scalar (`ordering_charges_its_derived_per_phase_count`); the run trade the joint worst bound makes (`every_part_sorted_in_pairs_is_the_most_any_runs_charge`); ordering work linear in a run (`ordering_and_encoding_work_grow_linearly_in_a_run`); the joint worst bound against the exact most of every text of up to eight bytes (`text_joint`); `no_composition_is_longer_than_its_decomposition` exhaustively |
| `text_cursor::pipeline::writer_bound` | `src/bounded/text_cursor/pipeline.rs::attribution`: empty, one-byte and four-byte scalars, each output equal to the symbolic encoding | turn limits (`text_emit_turns`) |
| `encoding::prepare_bound` | `src/bounded/encoding.rs::bound_tests::attribution` | coverage of every engine path, every engine path's total recorded, the shape walk's counts and admission, overflow |
| `encoding::emit_bound` | `src/bounded/encoding/writer.rs`: a borrowed write, a caller-owned write (`encode_owned`) and publication in place | coverage of every plan shape, tightness on its worst plans |
| `encode_bound` | composed from the walk (`walk_work`), `prepare_bound` and `emit_bound`; retains the plan's byte arena alone | monotone in every shape count (`src/bounded.rs::places`); every published encoding of `bounded_adversarial.rs` and `bounded_extended.rs` held within its retained bytes; erased controls before a map's last entry charged, the scan ending at its declared count, a refused run within the complete bound (`../hashbrown_scan.rs`) |
| `encoding::buckets::bucket_bound` | `src/bounded/encoding/buckets.rs::attribution`: empty, sparse and dense tables, one bucket at a time and batched, the dense table's last entry in its last bucket | completion at the last entry (`enumeration_completes_at_the_last_entry`); the group scan (`next_full_bucket`) against the per-index scan in the hashbrown fork and in the forked standard library |
| `scope_bound`, `copy_bound`, `borrow_bound`, `parse_bound`, `construction_bound` | `src/bounded/decode/construction.rs::attribution`: every operation at its operation's places, summed over the operations a run touches, and each task at its own places within its operation's task | turn limits |
| `InPlace::COST` | at the construction's `Build` place in the owned lifecycle check | `reclamation_owner.rs::every_built_in_construction_is_within_its_cost`, `reclamation/schema.rs::every_derived_construction_is_within_its_cost` |
| `typed_decode_bound`, `owned_prepare_bound` | composed from the bounds above | turn limits of every retained suite and fuzz target |

## Admission route

One route, three mechanisms, each checking what the others cannot
(`CONTRACT.md`, Admission route and trusted domain).

| Mechanism | Catches | Misses | Pass and fail |
| --- | --- | --- | --- |
| `clippy.toml` `disallowed-methods` on `dcbor::bounded::Budget::traverse` | every direct call, generic or concrete, in the crate, its tests, the support crate, fuzz and examples, including derive output expanded there; stale exemptions and an unresolvable path, as unfulfilled expectations | calls clippy never sees: code outside these crates | clippy clean with item-level `expect`s at each sanctioned site; a new direct call fails at its span |
| The attribution policy's routed mark (`src/bounded.rs::places`) | any admission reaching the policy outside the route on an exercised path, wherever its code lives | paths no run exercises | every attribution suite passes through the route; `an_admission_outside_the_route_is_refused` fails with the bypass message; `a_panic_inside_the_route_leaves_no_mark` |
| Attribution coverage | allocations, which are not routed, made at no place | nothing an attributed run makes | every per-place check; `an_allocation_at_no_place_is_unattributed` |

## Coverage boundaries

Callback bounds, measured latency, and physical allocation observation are
distinct measurements. None substitutes for the others. Every retained
operation has a whole-operation bound and every turn admits at most one fixed
quantum (`CONTRACT.md`, Execution and resource bounds), so the next unit of any
operation is bounded by the quantum. Generic custom-constructor execution and
destruction require explicit qualification.
