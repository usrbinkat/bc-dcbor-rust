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
| Cancellation matrix | The shared pipeline matrix (`dcbor-test-support`): retire, unwind and cancel at the first boundary of each certified cleanup class and at every unclassified boundary (fast layer), at every boundary with each class's members cleaning up alike (exhaustive layer) |
| Physical failure | `owned_physical_failure`: return null at each real decoder allocation following admission |
| Lifetimes | `owned_lifetimes`: positive import/borrow control plus escaping-reference, use-after-retirement, and mutation compile failures |
| Fuzz | `owned_lifecycle`: symbolic String oracle, observed refusal, trace conservation, cancellation, drain |
| Memory model | `miri-owned.sh`: each selected test (`miri-suites.txt`) in a Miri process of its own, strict provenance, Stacked and Tree Borrows, its log, verdict and inventory per run (stop classes and boundary predicate valuations reached), every model's inventory equal to the native run's |
| Safe pipeline failure matrix | `owned_pipeline_matrix`: every observed work/allocation callback refuses; every observed physical acquisition returns null, from scope setup through safe acquisition, decode, preparation and emission |
| Plan and controller retirement | `owned_pipeline_matrix`: drop/unwind at every discovered phase boundary, including published plan; no synchronous reservation release, no retirement allocation, allocation-free drain |
| Interleaved operations | `owned_pipeline_interleavings`: retire A at each preparation boundary under four named interleavings (A's retirement before B begins, after B publishes, and while B is in flight with either leading) while B completes with literal output |
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

A custom binding, an implementation of `InPlace` and `Reclaim`, is held to
the contract the built-in ones are:

- `Custody` is required: its state's observation, a projection of the one
  state construction and cleanup use, distinguishing every state whose
  cleanup differs, with no default.
- `Reclaim::remaining` is required: the most cleanup calls the state can
  still take, completion included. The scope enforces it; a call beyond it
  is a defect, and overstating is sound.
- `Reduction` is optional, with no default: a class map that is a
  simulation of cleanup, its argument stated at its definition. A binding
  without one is never reduced, and every stop over its states runs.

All three are checked as the built-in bindings' are, by the observed
construction driver (`support::construction`, `support::certified`,
`support::legal`; `resumable/COVERAGE.md`, Harness and observations).

Run the independent runtime/compile suites, the recorded-evidence checks and
the lifetime fixtures in the fork shell, where the evidence was recorded:

```sh
nix develop .#custom-std -c bash tests/run-contribution-contracts.sh
```

Run the memory-model checks in the same shell, whose toolchain carries Miri,
after a reach map of the same source (`tests/reach-map.sh`), which the gate
requires:

```sh
nix develop .#custom-std -c env DCBOR_REACH_DIR=<reach directory> bash tests/reach-map.sh
nix develop .#custom-std -c env DCBOR_REACH_DIR=<reach directory> MIRI_LOG_DIR=<log directory> bash tests/miri-owned.sh
```

Run the planted controls at a clean commit, each on a copy of it, never the
checkout (`tests/data/controls/controls.tsv`, `tests/data/README.md`, Planted
controls): each toolchain channel named on the command line, the native and
Miri controls in the shell of the channel their row names (Miri's is the
nightly fork shell), the Kani controls in any shell carrying `cargo kani`,
red with the diff applied and green again with it reversed in the same copy;
the model checkers' controls in the concurrency gate:

```sh
nix develop .#custom-std -c env CONTROL_LOG_DIR=<log directory> bash tests/controls.sh nightly
nix develop .#stable -c env CONTROL_LOG_DIR=<log directory> bash tests/controls.sh stable
nix develop .#custom-std -c env CONTROL_LOG_DIR=<log directory> bash tests/controls.sh kani
nix develop .#custom-std -c env CONCURRENCY_LOG_DIR=<log directory> bash tests/concurrency-models.sh gate
```

Each refuses to run when a diff under `tests/data/controls` has no row in the
table, and a control counts only when its own test, run alone, fails with its
planned outcome naming its pattern (`tests/gate`, `controls`).

Calibrate the proof harnesses after the native control runs of the nightly and
the stable channel have finished and passed on the same clean commit, with no
other gate workload running. Adopt each sample into the checkout, then commit
the adopted runs and the predictions fitted from them
(`tests/data/proofs/expectations.json`). Qualify the census at that commit: the
proof gate runs on a copy of the commit, so only committed calibration evidence
reaches it (`tests/data/README.md`, Proof runtime evidence):

```sh
nix develop .#custom-std -c env CONTROL_LOG_DIR=<nightly log directory> bash tests/controls.sh nightly native
nix develop .#stable -c env CONTROL_LOG_DIR=<stable log directory> bash tests/controls.sh stable native
nix develop .#custom-std -c env PROOF_LOG_DIR=<log directory> bash tests/proofs.sh calibrate <plan> <nightly log directory> <stable log directory>
nix develop .#custom-std -c cargo run --quiet --manifest-path tests/gate/Cargo.toml --bin gate -- proofs-adopt <log directory>/calibration/<harness>.<n>.evidence "$PWD"
nix develop .#custom-std -c env PROOF_LOG_DIR=<log directory> bash tests/proofs.sh
```

The recorded fuzz campaign includes `owned_lifecycle` and hashes its shared
test driver along with the fuzz and production sources.
