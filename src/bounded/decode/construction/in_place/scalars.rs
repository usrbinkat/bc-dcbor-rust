use super::*;
use crate::ExactFrom;
use half::f16;

macro_rules! scalar {
    ($ty:ty, $zero:expr, $node:ident, $value:expr) => {
        // SAFETY: the scalar owns no child resources and needs no destructor.
        unsafe impl<A: Allocator> Reclaim<A> for $ty {
            type State = Written;
            const INITIAL: Written = Written::Empty;

            unsafe fn reclaim_step(
                _: NonNull<MaybeUninit<Self>>,
                state: &mut Written,
                a: &mut A,
            ) -> BoundedResult<Reclaimed, A> {
                STEP.admit(a)?;
                *state = Written::Empty;
                Ok(Reclaimed::Done)
            }

            /// One call, which is `Done`.
            unsafe fn remaining(_: NonNull<MaybeUninit<Self>>, _: &mut Written) -> u64 {
                1
            }
        }
        // SAFETY: admission precedes the only scalar write; errors leave the
        // destination uninitialized and the empty state safe to reclaim.
        unsafe impl<A: Allocator> InPlace<A> for $ty {
            const COST: ConstructionCost = scalar_cost::<$ty>();

            unsafe fn build_step(
                document: &Document<'_, A::Permit>,
                index: usize,
                place: NonNull<MaybeUninit<Self>>,
                state: &mut Written,
                a: &mut A,
            ) -> ConstructResult<Built, A> {
                if *state != Written::Empty {
                    return Err(BoundedError::PlanMismatch.into());
                }
                sized::<Self>().admit(a)?;
                let $node = node_at(document, index).ok_or_else(wrong_type)?.kind();
                let value: Self = $value;
                unsafe {
                    place.as_ptr().write(MaybeUninit::new(value));
                }
                *state = Written::Initialized;
                Ok(Built::Done)
            }
        }
        // SAFETY: the scalar placeholder is resource-free and fits one quantum.
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
