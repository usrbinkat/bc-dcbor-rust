//! Production-backed safe acquisition, cancellation and allocation matrices.
#[global_allocator]
static HEAP: heap::Heap = heap::Heap;
use dcbor::bounded::{Limits, Step};
use dcbor_test_support::classes::Classes;
use dcbor_test_support::pipeline::{Expected, acquire, matrix};
use dcbor_test_support::rigor::rigor;
use dcbor_test_support::{self as support, heap};

#[test]
fn all_safe_input_admissions_physical_failures_and_stops() {
    for len in [0, 1, 63, 64, 65, 1024] {
        let source = vec![0xa5; len];
        matrix(
            &format!("acquire {len} bytes"),
            rigor(),
            Expected::Complete,
            |schedule| acquire(&source, schedule, &Classes::certified()),
        );
    }
}

#[test]
fn safe_input_cancel_finishes_with_unrelated_live_input() {
    let mut m = Limits::unlimited().logged().strict();
    let mut owner = support::scope(&mut m);
    let output = support::copy(&owner, &mut m, b"retained evidence bytes");
    let mut second = owner.copy_input(b"cancelled");
    // One admitted step, so cancellation interrupts an operation in progress,
    // within the copy's own bound.
    let bound = support::turns(
        dcbor::bounded::decode::construction::copy_bound::<Limits, ()>(b"cancelled".len() as u64)
            .expect("the copy bound of an input held in memory fits in u64"),
    );
    let mut progressed = false;
    for _ in 0..bound {
        match support::checked(&mut m, |m| support::contracted(m, &mut second)) {
            Ok(Step::Progress) => {
                progressed = true;
                break;
            }
            Err(error) if support::ordinary_exhaustion(&m, &error) => {}
            _ => panic!("input acquisition did not remain in progress"),
        }
    }
    assert!(progressed);
    second.cancel();
    support::finish_within(&mut m, &mut second, bound);
    assert_eq!(output.value().data(), b"retained evidence bytes");
    drop(second);
    drop(output);
    support::drain(&mut owner, &mut m);
    assert_eq!(m.live_bytes(), 0);
}
