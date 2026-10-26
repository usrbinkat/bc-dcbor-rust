// A payload declaring the dispatch-depth limit puts its construction record
// one level beyond it: decoding it fails to compile, so no step can reach it.
#[path = "../support/policy.rs"]
mod policy;

use core::{mem::MaybeUninit, ptr::NonNull};
use dcbor::bounded::decode::construction::in_place::{
    Built, ConstructionCost, InPlace, plus, step, unit,
};
use dcbor::bounded::decode::construction::reclamation::{
    MAX_DISPATCH_DEPTH, Reclaim, Reclaimed, Written,
};
use dcbor::bounded::decode::construction::{Borrowed, OwnedInitialized, TypedDecoder};
use dcbor::bounded::decode::{ConstructResult, Document, Options};
use dcbor::bounded::{Allocator, BoundedResult};

struct AtLimit;

unsafe impl<A: Allocator> Reclaim<A> for AtLimit {
    const DISPATCH_DEPTH: usize = MAX_DISPATCH_DEPTH;
    type State = Written;
    const INITIAL: Written = Written::Empty;

    unsafe fn reclaim_step(
        _: NonNull<MaybeUninit<Self>>,
        state: &mut Written,
        a: &mut A,
    ) -> BoundedResult<Reclaimed, A> {
        step(a)?;
        *state = Written::Empty;
        Ok(Reclaimed::Done)
    }

    unsafe fn remaining(_: NonNull<MaybeUninit<Self>>, _: &mut Written) -> u64 {
        1
    }
}

unsafe impl<A: Allocator> InPlace<A> for AtLimit {
    const COST: ConstructionCost = ConstructionCost::fixed(plus(unit(0), unit(0)));

    unsafe fn build_step(
        _: &Document<'_, A::Permit>,
        _: usize,
        _: NonNull<MaybeUninit<Self>>,
        state: &mut Written,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
        step(a)?;
        *state = Written::Initialized;
        Ok(Built::Done)
    }
}

fn decode(input: OwnedInitialized<'static, Borrowed<'static>, policy::Policy>) {
    let mut decoder = TypedDecoder::<_, AtLimit, _>::new(input, Options::normalizing(8));
    let _ = decoder.step(&mut policy::Policy);
}

fn main() {
    let _: fn(OwnedInitialized<'static, Borrowed<'static>, policy::Policy>) = decode;
}
