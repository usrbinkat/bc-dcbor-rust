# Policy accounting conformance

`src/bounded/policy/conformance.rs` checks the admission contract once per policy.
`conformance!(limits: Limits; governed: OperationBudget)` instantiates every obligation for both
implementations. Adding a policy requires its `Conforming` setup and observation adapter and one
macro argument.

The suite checks lifetime authorization across turns, refusal atomicity for work and requests,
quantum versus turn allowance, refusal precedence, cleanup accounting and scheduling, cleanup
capability routing, saturating cleanup totals, terminal admissions and allocation refusal, permit
release, and rollback after a later reservation refusal. Quantities are checked independently at
overflow; saturated cleanup cannot erase foreground usage or prevent still-authorized foreground
work.

`Authority` stores foreground and cleanup independently. Foreground additions are checked against
the lifetime ceiling and `u64`; cleanup additions saturate independently in values and bytes. The
reported total is their saturating sum. Authorization reads the foreground account, never a
subtraction from the reported total. Cleanup can still be refused by its turn or quantum, with no
account committed.

Rollback setup exercises each policy's actual late-refusal path: an exhausted permit-record session
for `Limits`, and occupied group capacity for `OperationBudget`. The shared `Storage` and `Reserved`
controls run against both instantiations. A policy-specific plant runs only on its policy: for
example, `authority-refusal-commits` plants in `Limits`'s `Authority::work` wrapper, which
governance does not call.

Policy-specific witnesses retain simulated expiry, recording finalization, share clamping, group
aggregation and cross-level atomicity, cancellation, monotonic deadlines, terminal group counting,
and the typed decode chain. These assertions cannot be replaced by an unlimited-group conformance
fixture: such a fixture cannot trigger a group-level refusal.

`tests/data/controls/controls.tsv` binds each planted defect to an exact test and diagnostic.
`authority-cleanup-total-refuses` restores checked cleanup addition and must fail both policies with
`a cleanup unit was refused for its total`.
