# Owned contribution contracts

Every contract runs against the production owned interfaces
(`docs/owned-decoding.md`). A compile failure in a positive contract is a
failing requirement, not a passing compile-fail test. No contract is ignored.

| Requirement | Executable contract |
| --- | --- |
| Safe immutable input acquisition | `owned_public_contract`: `copy_input`, retained acquisition, input publication; `forbid(unsafe_code)` |
| Input custody | `owned_lifecycle_matrix` / shared driver: input reservation retained, release observed exactly once |
| Worker transfer | `contribution_capabilities`: positive Send bounds; `owned_public_contract`: each decode turn transfers through a spawned worker |
| Parse and inspect | `owned_public_contract`: owned document publication and original encoded bytes |
| Construct and encode | `owned_public_contract`: typed publication into owned preparation, plan publication, chunk emission and literal bytes |
| Bounded turns | Both meters reset to three values/64 bytes; oversized work fails or refuses |
| Bounded operations | Every owned operation completes within the turns of its whole-operation bound: `scope_bound`, `copy_bound`, `borrow_bound`, `parse_bound`, `construction_bound`, `typed_decode_bound`, `owned_prepare_bound`, `emit_bound` |
| Per-place bounds | `src/bounded/decode/construction.rs::attribution`: the scope, copies and borrows published and cancelled, parses published and failed, constructions published, failed and cancelled after detachment, each place within its term, and each witnessed place's run failing without its term |
| One admission route | `resumable/CONTRACT.md`, Admission route and trusted domain: every direct `Budget::traverse` call linted, routed admissions marked and unrouted ones refused under attribution, unplaced allocations unattributed |
| Stable small publication | `owned_decode`: address recorded during chunked construction equals published address; handle size independent of payload size |
| Independent cancellation | `owned_decode`: cancelled operation must finish while unrelated output remains live |
| No payload Drop | `owned_decode`: instrumented payload destructor remains uncalled before and after drain |
| Input retirement | Shared driver: retiring output does not release input; explicit drain releases it exactly once |
| Exact accounting | Drivers require zero live requested bytes after bounded shutdown |
| Terminal shutdown | `owned_decode`: closing cannot reopen initialization |
| Admission retention | `optional_admission`: repeated allocation refusal cannot change successful work trace |
| Lifecycle refusal | `owned_lifecycle_matrix`: inject at each observed callback, positively observe refusal, compare successful trace |
| Cancellation matrix | Discover successful turn count first, cancel at every preceding turn |
| Physical failure | `owned_physical_failure`: return null at each real decoder allocation following admission |
| Lifetimes | `owned_lifetimes`: positive import/borrow control plus escaping-reference, use-after-retirement, and mutation compile failures |
| Fuzz | `owned_lifecycle`: symbolic String oracle, observed refusal, trace conservation, cancellation, drain |
| Memory model | `miri-owned.sh`: explicit cargo-miri suites with separate logs and failure status |
| Safe pipeline failure matrix | `owned_pipeline_matrix`: every observed work/allocation callback refuses; every observed physical acquisition returns null, from scope setup through safe acquisition, decode, preparation and emission |
| Plan and controller retirement | `owned_pipeline_matrix`: drop/unwind at every discovered phase boundary, including published plan; no synchronous reservation release, no retirement allocation, allocation-free drain |
| Interleaved operations | `owned_pipeline_interleavings`: retire A at each preparation boundary under 16 advancement schedules while B completes with literal output |
| Concurrent retirement | `owned_pipeline_interleavings`: two workers retire plans while the owner closes and drains; both retirement orders, joins and exact final recovery |

`owned_public_contract.rs` is the safe consumer path, `forbid(unsafe_code)`:
`copy_input`, `DocumentDecoder::parse`, `into_input`, `TypedDecoder` stepped on
a new thread each turn, `OwnedPreparation::prepare`, `into_writer` and
`OwnedEmitStep` emission, then drain. Renaming these interfaces must preserve
its assertions and its safe consumer boundary.

The unsafe `Instrumented` input in `tests/support/lifecycle.rs` is only
instrumentation of input custody: it counts its own cleanup to prove drain
releases the input exactly once. It does not satisfy the safe-acquisition
contract, which `copy_input` does. Its decoder observer starts after fixture
setup. `owned_pipeline_matrix` starts observing at scope initialization and
drives safe acquisition, decoding, owned preparation and emission directly.
Interleaving tests enumerate bounded schedules and race retirement with
cleanup; they are not an exhaustive model check of every possible concurrent
execution.

Run the independent runtime/compile suites and lifetime fixtures with:

```sh
nix develop -c bash tests/run-contribution-contracts.sh
```

Run memory-model checks in a matching Miri-equipped environment with:

```sh
bash tests/miri-owned.sh
```

The recorded fuzz campaign includes `owned_lifecycle` and hashes its shared
test driver along with the fuzz and production sources.
