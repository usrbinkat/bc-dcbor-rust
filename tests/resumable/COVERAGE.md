# Resumable acceptance coverage

`../resumable_contract.rs` registers the runtime groups below. Paths are relative
to this directory unless otherwise specified. Run with `--features derive` to
exercise generated construction and its allocation-failure matrix.

| Requirement | Registered test source |
| --- | --- |
| Header interruption, retained bytes, nonminimal and truncated heads | `native_header_cursor.rs`, `native_schedules.rs` |
| Same-operation decoding, typed construction, externally released capacity | `native_continuation.rs` |
| Payload, key comparison, child completion, trailing-data boundaries | `native_matrix.rs` |
| Exact comparison offsets and literal ordering cases | `native_comparison_cursor.rs` |
| Storage relocation, overlapping permits, retained values, cancellation | `native_storage_cursor.rs` |
| Derived records, newtypes, tags, enum shapes, nested generics | `native_derive.rs` |
| Completed field values, output lifetimes, cancellation, failed growth | `native_ownership.rs` |
| Physical allocation failure in retained decoding, derived construction, text encoding | `native_heap.rs` |
| Physical allocation failure in preparation, plan ownership, allocation-free emission | `native_preparation_heap.rs` |
| Preparation and emission refusal/cancellation, exact prefixes, shared pool | `native_pipeline.rs` |
| Retained schema encoding, nested generics, enum representations, optional omission, tags, map-header finalization, physical allocation failures | `native_schema_encoding.rs` |
| Literal composition, reordering, leading marks, decomposition, Hangul | `native_text_matrix.rs` |
| Long combining runs with O(n log n) turn limits | `native_text_matrix.rs::long_combining_run_requires_retained_progress_not_whole_run_admission` |
| Retained text positions and cancellation at progress boundaries | `native_text_progress.rs` |
| QuickOnly refusal and acceptance under suspension | `native_quick_suspension.rs` |
| Exhaustive Unicode scalar quick-check parity | `native_schedules.rs::quick_only_matches_upstream_for_all_scalars_and_cross_character_cases` |
| Successive refusals on a single operation | `native_repeated.rs` |
| Malformed literals, truncations, cancellation, positive refusal observation | `native_malformed.rs` |
| Generated inputs, mutations, scalar differential checks, bound overflow | `native_differential.rs` |
| Deadline expiration before and between admissions | `native_deadlines.rs` |
| Work-bound defects and caller-refusal classification | `native_bound_defects.rs` |
| Output capacity, written prefixes, checked work composition | `native_output_bounds.rs` |
| Measured step latency for payload decoding and normalization | `native_latency.rs` |
| Large-operation quanta, typed copies, canonical semantics, shared recovery | `native_tests.rs` |
| Concurrent retained decoding and exact capacity reacquisition | `native_schedules.rs::capacity_pool_survives_concurrent_success_and_every_refused_constructor` |

## Harness and observations

- `native_driver.rs` drives production continuations with finite step limits and
  fresh three-value/64-byte completion turns.
- `native_bindings.rs` translates production outcomes into test outcomes.
- `native_harness.rs` records admission traces and synchronized live capacity.
- `native_heap.rs` observes physical requested allocations and injects allocation
  failures. Its negative control detects an unreported allocation.
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
derived preparation, nested arrays, optional fields, normalization, same-cursor
refusal recovery, cancellation, and allocation-free emission. `fuzz/smoke.sh`
includes both alongside the six other targets. Toolchain and execution commands
are in `fuzz/README.md`.

## Coverage boundaries

Callback bounds, measured latency, and physical allocation observation are
distinct measurements. None substitutes for the others. Synchronous work-bound
tests do not establish next-unit bounds for every retained transition. Generic
custom-constructor execution and destruction require explicit qualification.
Dynamic-map schema encoding and downstream Kappa integration require their own
continuation and public-boundary tests under `CONTRACT.md`.
