//! Kani harness of the record check (R-C, check-on-consume; register item
//! 4, correspondence): written and unverified until the gate runs it.
//!
//! A binding's `Done` carries its record ([`Initialized`]) of the place it
//! initialized, minted from its context's assembly ([`Assembly::assemble`]),
//! and the dispatching entry checks it against the assembly of the place it
//! projected for that exact advance ([`verified`], the one check of
//! `enter`, `dispatch_part` and `fields::build_payload`).
//! The brand confines a record to its step at compile time (the trybuild
//! fixtures `record_*`); this harness checks the run-time part, the
//! destination binding itself: over every place address and both session
//! flags of the record and of the expected assembly, and both reports,
//! `verified` accepts `Done` exactly when both contexts were stepped by a
//! session and the record's place is the projected place, refuses every
//! other `Done` with `PlanMismatch`, and passes `Progress` unchecked.
//!
//! Domain, stated: every `usize` place for the record and for the expected
//! assembly, each `bound` flag, and `Progress` and `Done`; `verify` and
//! `verified` have no loop: no unwind bound. The general argument is the
//! domain itself: the check reads only those two words and two flags, so
//! the harness is exhaustive over its inputs. Compiled only under
//! `cfg(kani)`.

use super::{Assembly, Building, Built, verified};
use crate::bounded::BoundedError;

/// Every record against every projected place: accepted exactly when both
/// contexts were stepped by a session and the places agree.
#[kani::proof]
fn a_record_is_accepted_exactly_at_its_projected_place_of_a_stepped_context() {
    let (minted_at, minted_bound): (usize, bool) = (kani::any(), kani::any());
    let (expected_at, expected_bound): (usize, bool) = (kani::any(), kani::any());
    let expected = Assembly::<u64>::at(expected_at, expected_bound);
    // SAFETY: the record is data the check reads; no value is behind it and
    // nothing dereferences its place.
    let record = unsafe { Assembly::<u64>::at(minted_at, minted_bound).assemble() };
    let accepted = minted_bound && expected_bound && minted_at == expected_at;
    match verified::<u64, ()>(Building::Done(record), expected) {
        Ok(built) => {
            assert!(accepted, "a record is accepted only at its projected place");
            assert!(built == Built::Done, "an accepted record reports Done");
        }
        Err(error) => {
            assert!(!accepted, "a record at its projected place is accepted");
            assert!(
                matches!(error, BoundedError::PlanMismatch),
                "a refused record is a plan mismatch"
            );
        }
    }
    assert!(
        matches!(
            verified::<u64, ()>(Building::Progress, expected),
            Ok(Built::Progress)
        ),
        "progress carries no record and is not checked"
    );
}
