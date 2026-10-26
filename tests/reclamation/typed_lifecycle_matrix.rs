use super::*;
use dcbor::bounded::decode::construction::in_place::StableOption;
use dcbor::bounded::decode::construction::reclamation::{MAX_DISPATCH_DEPTH, Written};

/// Literal [["q\u{301}", "b"], ["c"]] through the decode matrix
/// ([`support::pipeline::matrix`]): the first text requires the retained NFC
/// proof path but is already canonical, and no encoder supplies the oracle.
/// Every admission refused and resumed; every physical request failed; and
/// at the decode's boundaries a retire, which neither allocates nor releases
/// storage outside admission, an unwind and a cancellation, the scope's
/// drain recovering everything after each. The probe's own lifecycle matrix
/// is `every_probe_lifecycle_fault_keeps_custody_without_destructors`.
#[test]
fn normalized_nested_text_cancellation_retains_custody_at_every_boundary() {
    use support::classes::parsed;
    use support::pipeline::{Expected, decode, matrix};
    use support::rigor::rigor;
    let wire = [
        0x82, 0x82, 0x63, b'q', 0xcc, 0x81, 0x61, b'b', 0x81, 0x61, b'c',
    ];
    let expected = vec![
        vec!["q\u{301}".to_owned(), "b".to_owned()],
        vec!["c".to_owned()],
    ];
    matrix(
        "nested normalized text decode",
        rigor(),
        Expected::Complete,
        |schedule| {
            decode::<Vec<Vec<String>>>(
                &wire,
                Options::normalizing(8),
                schedule,
                &parsed::<Vec<Vec<String>>>(),
                |value| assert_eq!(value, &expected),
            )
        },
    );
}

#[test]
fn large_optional_payload_is_initialized_at_its_published_address() {
    assert_eq!(
        std::mem::size_of::<StableOption<Probe, Limits>>(),
        std::mem::size_of::<usize>()
    );
    for (wire, present) in [([0x00], true), ([0xf6], false)] {
        let mut m = turns(None);
        let (mut owner, input) = open(&mut m, &wire);
        let output = support::decode::<_, StableOption<Probe, Limits>>(
            &mut m,
            input,
            Options::normalizing(8),
        )
        .expect("stable optional literal failed");
        assert_eq!(output.value().is_some(), present);
        if let Some(value) = output.value().as_ref() {
            assert_eq!(value.inline, [0x5a; 256]);
            assert_eq!(
                value.construction_address,
                std::ptr::from_ref(value) as usize
            );
        }
        drop(output);
        drain(&mut owner, &mut m);
        assert_eq!(m.live_bytes(), 0);
    }
}

/// A leaf payload declaring dispatch depth `D`. The `Reclaim` contract
/// forbids understating a depth, not overstating it, so a declared depth
/// places a typed decode on either side of [`MAX_DISPATCH_DEPTH`] without the
/// deep type nesting whose auto-trait proof exceeds the compiler's limit.
struct Declared<const D: usize>;

// SAFETY: the value is zero-sized and owns nothing; one admitted unit retires
// it. `D` is at least its true depth of 1, asserted at build time.
unsafe impl<A: Allocator, const D: usize> Reclaim<A> for Declared<D> {
    const DISPATCH_DEPTH: usize = D;
    type State = Written;
    const INITIAL: Written = Written::Empty;

    #[expect(
        clippy::disallowed_methods,
        reason = "a third-party binding admits its own cleanup, as `Reclaim` documents"
    )]
    unsafe fn reclaim_step(
        _: NonNull<MaybeUninit<Self>>,
        state: &mut Written,
        a: &mut A,
    ) -> dcbor::bounded::BoundedResult<Reclaimed, A> {
        a.traverse(1, 0).map_err(BoundedError::Refused)?;
        *state = Written::Empty;
        Ok(Reclaimed::Done)
    }

    /// One call, which is `Done`.
    unsafe fn remaining(_: NonNull<MaybeUninit<Self>>, _: &mut Written) -> u64 {
        1
    }
}

// SAFETY: one admitted unit initializes the zero-sized value.
unsafe impl<A: Allocator, const D: usize> InPlace<A> for Declared<D> {
    // One build unit and one cleanup unit.
    const COST: ConstructionCost = ConstructionCost::fixed(plus(unit(0), unit(0)));

    #[expect(
        clippy::disallowed_methods,
        reason = "a third-party binding admits its own construction, as `InPlace` documents"
    )]
    unsafe fn build_step(
        _: &Document<'_, A::Permit>,
        _: usize,
        _: NonNull<MaybeUninit<Self>>,
        state: &mut Written,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
        const { assert!(D >= 1, "a declared depth below the true depth of 1") };
        a.traverse(1, 0).map_err(BoundedError::Refused)?;
        *state = Written::Initialized;
        Ok(Built::Done)
    }
}

/// A payload one dispatch level below the limit puts its construction record
/// exactly at the limit, which decodes; one level more fails to compile
/// (`dcbor-derive/tests/ui/fail/dispatch_depth_beyond_limit.rs`).
#[test]
fn dispatch_depth_limit_admits_its_maximum() {
    // The construction record adds one dispatch level to its payload's.
    type Deepest = Declared<{ MAX_DISPATCH_DEPTH - 1 }>;
    // Real nesting declares one level per vector over its leaf: 64 vector
    // levels imply a payload of the limit, whose record is one beyond.
    type Four<T> = Vec<Vec<Vec<Vec<T>>>>;
    type Sixteen<T> = Four<Four<Four<Four<T>>>>;
    type SixtyFour<T> = Sixteen<Sixteen<Sixteen<Sixteen<T>>>>;
    let nested = <SixtyFour<u8> as Reclaim<Limits>>::DISPATCH_DEPTH;
    assert_eq!(nested, 64 + <u8 as Reclaim<Limits>>::DISPATCH_DEPTH);
    assert!(nested >= MAX_DISPATCH_DEPTH);

    let mut m = turns(None);
    let (mut owner, input) = open(&mut m, &[0xf6]);
    let output = support::decode::<_, Deepest>(&mut m, input, Options::normalizing(8))
        .expect("the maximum dispatch depth was rejected");
    drop(output);
    drain(&mut owner, &mut m);
    assert_eq!(m.live_bytes(), 0);
}

#[test]
fn nested_construction_and_cleanup_run_on_a_fixed_size_native_stack() {
    std::thread::Builder::new()
        .stack_size(512 * 1024)
        .spawn(|| {
            type Four<T> = Vec<Vec<Vec<Vec<T>>>>;
            type Sixteen<T> = Four<Four<Four<Four<T>>>>;
            macro_rules! four {
                ($value:expr) => {
                    $value
                        .first()
                        .unwrap()
                        .first()
                        .unwrap()
                        .first()
                        .unwrap()
                        .first()
                        .unwrap()
                };
            }
            macro_rules! sixteen {
                ($value:expr) => {
                    four!(four!(four!(four!($value))))
                };
            }
            let mut wire = [0x81; 33];
            wire[32] = 0;
            let mut m = turns(None);
            let (mut owner, input) = open(&mut m, &wire);
            let output = support::decode::<_, Sixteen<Sixteen<Probe>>>(
                &mut m,
                input,
                Options::normalizing(32),
            )
            .expect("nested construction failed");
            let leaf = sixteen!(sixteen!(output.value()));
            assert_eq!(leaf.inline, [0x5a; 256]);
            assert_eq!(leaf.construction_address, std::ptr::from_ref(leaf) as usize);
            drop(output);
            drain(&mut owner, &mut m);
            assert_eq!(m.live_bytes(), 0);
            assert_eq!(DROPS.get(), 0);
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn maximum_real_dispatch_depth_reclaims_during_unwinding() {
    type Four<T> = Vec<Vec<Vec<Vec<T>>>>;
    type Eight<T> = Four<Four<T>>;
    type Sixteen<T> = Eight<Eight<T>>;
    type ThirtyTwo<T> = Sixteen<Sixteen<T>>;
    type Two = Vec<Vec<Probe>>;
    type Six = Four<Two>;
    type Fourteen = Eight<Six>;
    type Thirty = Sixteen<Fourteen>;
    type Deepest = ThirtyTwo<Thirty>;
    // Sixty-two real vector continuations, a leaf, and its owning
    // construction record: every dispatch level is executed, not merely
    // declared by a shallow binding.
    assert_eq!(
        <Deepest as Reclaim<Limits>>::DISPATCH_DEPTH + 1,
        MAX_DISPATCH_DEPTH
    );
    std::thread::Builder::new()
        .stack_size(512 * 1024)
        .spawn(|| {
            STARTS.set(0);
            DROPS.set(0);
            let mut wire = [0x81; 63];
            wire[62] = 0;
            let mut policy = turns(None);
            let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let (owner, input) = open(&mut policy, &wire);
                let value =
                    support::decode::<_, Deepest>(&mut policy, input, Options::normalizing(62))
                        .expect("maximum real dispatch depth did not publish");
                assert_eq!(value.bytes(), wire);
                assert_eq!(STARTS.get(), 1);
                // Both handles are live when unwinding starts. Their drops
                // retire the record and drive the owner's terminal cleanup.
                assert!(owner.outstanding() > 0);
                policy.exhaust();
                panic!("maximum-depth terminal cleanup");
            }));
            let payload = unwound.expect_err("fixture did not unwind");
            assert_eq!(
                payload.downcast_ref::<&str>(),
                Some(&"maximum-depth terminal cleanup")
            );
            assert_eq!(policy.live_bytes(), 0);
            assert_eq!(
                DROPS.get(),
                0,
                "terminal cleanup invoked the leaf destructor"
            );
        })
        .unwrap()
        .join()
        .unwrap();
}
