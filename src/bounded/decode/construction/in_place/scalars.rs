use super::*;
use crate::ExactFrom;
use half::f16;

macro_rules! scalar {
    ($ty:ty, $zero:expr, $node:ident, $value:expr) => {
        // SAFETY: initial: `Written::Empty`, nothing written. state: `Written`
        // records whether the scalar is written; it acquires nothing.
        // admission: the one cleanup unit is admitted before it marks the
        // state, a refusal changing nothing. cleanup: the scalar owns no child
        // resources and needs no destructor; cleanup only marks it empty,
        // allocating nothing and never unwinding. done: nothing initialized
        // owns anything, so releasing the record without `Drop` is sound.
        // order: the unit is the same from either state, `Done` each time.
        // depth: a leaf, the default 1. count: one call.
        unsafe impl<A: Allocator> Reclaim<A> for $ty {
            type State = Written;
            const INITIAL: Written = Written::Empty;

            fn reclaim_step(
                mut slot: Slot<'_, Self, Written>,
                cleanup: &mut Cleanup<'_, A>,
            ) -> BoundedResult<Reclaimed, A> {
                STEP.admit(cleanup)?;
                *slot.custody() = Written::Empty;
                Ok(Reclaimed::Done)
            }

            /// One call, which is `Done`.
            fn remaining(_: PeekSlot<'_, Self, Written>) -> Option<u64> {
                Some(1)
            }

            /// A scalar owns no permit.
            fn observe_permits(
                _: PeekSlot<'_, Self, Written>,
                _: &mut dyn CustodySink<A::Permit>,
            ) -> PermitsObserved {
                PermitsObserved::Complete
            }
        }
        // SAFETY: admission: `sized::<Self>()` is admitted before the only
        // write. state: the state becomes `Initialized` with the write;
        // errors leave the destination uninitialized and the empty state
        // safe to reclaim. done: `Done` follows the whole value's write.
        // escape: nothing derived from the place is returned or kept.
        // provenance: the write goes through the slot's place. order: a build
        // from any state but `Empty` is refused `PlanMismatch`, nothing
        // changed. cost: `scalar_cost::<$ty>()` is the one admitted unit.
        unsafe impl<A: Allocator> InPlace<A> for $ty {
            const COST: ConstructionCost = crate::const_cost!(scalar_cost::<$ty>());

            fn build_step<'b>(
                ctx: BindingContext<'b, '_, '_, '_, Self, A>,
                a: &mut A,
            ) -> ConstructResult<Building<'b, Self>, A> {
                let node = ctx.node();
                let assembly = ctx.assembly();
                let mut slot = ctx.into_slot();
                let (place, state) = slot.parts();
                if *state != Written::Empty {
                    return Err(BoundedError::PlanMismatch.into());
                }
                sized::<Self>().admit(a)?;
                let $node = node.ok_or_else(wrong_type)?.kind();
                let value: Self = $value;
                // SAFETY: the slot pairs the place with this state, which is
                // empty: nothing to drop, the write admitted above.
                unsafe { place.write(state, value) };
                *state = Written::Initialized;
                // SAFETY: the whole value was written above, by an admitted
                // unit, and the state records it.
                Ok(Building::Done(unsafe { assembly.assemble() }))
            }
        }
        // SAFETY: resources: the scalar zero owns nothing and has no
        // destructor. bounded: one constant, written in constant work.
        unsafe impl Placeholder for $ty {
            fn placeholder() -> Self {
                $zero
            }
        }
    };
}

scalar!(
    bool,
    false,
    node,
    match node {
        Kind::Bool(value) => value,
        _ => return Err(wrong_type()),
    }
);

macro_rules! floats {
    ($($ty:ty => $zero:expr),*) => {$(
        scalar!($ty, $zero, node, match node {
            Kind::Float(n) => Self::exact_from_f64(n),
            Kind::Unsigned(n) => Self::exact_from_u64(n),
            Kind::Negative(n) => Self::exact_from_i128(i128::from(n)),
            _ => return Err(wrong_type()),
        }.ok_or(crate::bounded::decode::DecodeError::Invalid(crate::Error::OutOfRange))?);
    )*};
}
floats!(f16 => f16::ZERO, f32 => 0.0, f64 => 0.0);
