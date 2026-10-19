use super::*;

macro_rules! floats {
    ($($ty:ty),*) => {$(
        impl ResumableDecodable for $ty {
            type State<P> = ();
            fn start<P>() {}
            fn construct_step<A: Allocator>(document: &Document<'_, A::Permit>, index: usize,
                _: &mut (), _: &mut Storage<A::Permit, A::Permit>, allocator: &mut A,
            ) -> ConstructResult<BuildStep<Self>, A> {
                visit(allocator)?;
                let node = node_at(document, index).ok_or_else(wrong_type)?;
                let value = match node.kind() {
                    Kind::Float(n) => <$ty>::exact_from_f64(n),
                    Kind::Unsigned(n) => <$ty>::exact_from_u64(n),
                    Kind::Negative(n) => <$ty>::exact_from_i128(i128::from(n)),
                    _ => return Err(wrong_type()),
                }.ok_or(DecodeError::Invalid(Error::OutOfRange))?;
                Ok(BuildStep::Complete(value))
            }
        }
    )*};
}
floats!(f16, f32, f64);

impl<T: ResumableDecodable> ResumableDecodable for Option<T> {
    type State<P> = (bool, Option<T::State<P>>);
    fn start<P>() -> Self::State<P> {
        (false, None)
    }
    fn construct_step<A: Allocator>(
        document: &Document<'_, A::Permit>,
        index: usize,
        state: &mut Self::State<A::Permit>,
        permits: &mut Storage<A::Permit, A::Permit>,
        allocator: &mut A,
    ) -> ConstructResult<BuildStep<Self>, A> {
        if !state.0 {
            visit(allocator)?;
            let node = node_at(document, index).ok_or_else(wrong_type)?;
            if matches!(node.kind(), Kind::Null) {
                return Ok(BuildStep::Complete(None));
            }
            state.0 = true;
            state.1 = Some(T::start());
            return Ok(BuildStep::Progress);
        }
        let child = state.1.as_mut().ok_or(BoundedError::PlanMismatch)?;
        Ok(
            match T::construct_step(document, index, child, permits, allocator)? {
                BuildStep::Progress => BuildStep::Progress,
                BuildStep::Complete(value) => {
                    state.1 = None;
                    BuildStep::Complete(Some(value))
                }
            },
        )
    }
}
