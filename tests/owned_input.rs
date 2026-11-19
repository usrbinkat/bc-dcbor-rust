//! Production-backed safe acquisition, cancellation and allocation matrices.
#[global_allocator]
static HEAP: heap::Heap = heap::Heap;
use dcbor::bounded::decode::construction::DecodeOwner;
use dcbor_test_support::classes::Classes;
use dcbor_test_support::pipeline::{Expected, acquire, matrix};
use dcbor_test_support::rigor::rigor;
use dcbor_test_support::{self as support, Retirement, heap, pipeline::Unwitnessed};

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

/// One recorded run: a copy published and kept live while a second copy is
/// cancelled mid-acquisition and cleaned up; the scope then drains, and the
/// run's finalizer refines the whole stream.
#[test]
fn safe_input_cancel_finishes_with_unrelated_live_input() {
    use support::Source;
    support::recorded_run(|run| {
        let policy = run.policy(u64::MAX);
        run.holding(
            DecodeOwner::new(),
            Retirement::Scope,
            &Unwitnessed,
            |owner| {
                owner.initialize(policy)?;
                let source = support::Copying(b"cancelled");
                let bound = source.turns();
                let second = source.acquire(owner.value());
                let first = support::Copying(b"retained evidence bytes");
                let first_bound = first.turns();
                let first = first.acquire(owner.value());
                owner.holding(first, Retirement::Stopped, |first| {
                    first.drive(policy, first_bound, Retirement::Published, |output| {
                        output.holding(second, Retirement::Stopped, |second| {
                            let reached = second.controlled(
                                policy,
                                bound,
                                Retirement::Published,
                                true,
                                |_, _, at| at == 1,
                                |_| (),
                            )?;
                            assert!(reached.is_none(), "the copy published at its first step");
                            second.value().cancel();
                            second.finish(policy, bound, Retirement::Published)?;
                            Ok::<_, support::Finding>(())
                        })?;
                        assert_eq!(output.value().value().data(), b"retained evidence bytes");
                        Ok::<_, support::Finding>(())
                    })?
                })?;
                owner.drain(policy)
            },
        )?;
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok(())
    });
}
