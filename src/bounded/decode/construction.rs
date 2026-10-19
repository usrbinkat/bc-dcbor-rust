//! Typed construction states addressed by stable document indices.
use super::cursor::{DecodeStep, Decoder};
use super::storage::Storage;
use super::*;
mod scalars;

pub enum BuildStep<T> {
    Progress,
    Complete(T),
}

/// Construction states own completed fields and partial payloads. They never
/// borrow the document, allowing a decoder to retain both without self-borrows.
pub trait ResumableDecodable: Sized {
    type State<P>;
    fn start<P>() -> Self::State<P>;
    fn construct_step<A: Allocator>(
        document: &Document<'_, A::Permit>,
        index: usize,
        state: &mut Self::State<A::Permit>,
        permits: &mut Storage<A::Permit, A::Permit>,
        allocator: &mut A,
    ) -> ConstructResult<BuildStep<Self>, A>;
}

pub fn node_at<'d, 'a, P>(document: &'d Document<'a, P>, index: usize) -> Option<Node<'d, 'a>> {
    (index < document.entries.len()).then(|| Node {
        input: document.input,
        entries: document.entries.as_slice(),
        index,
    })
}

pub fn next_index(node: Node<'_, '_>) -> usize {
    node.entries[node.index].next
}

/// Owns the constructed value together with its storage reservations.
/// A reference to the value cannot escape that owner.
///
/// ```compile_fail,E0515
/// use dcbor::bounded::decode::construction::TypedValue;
/// fn escape<'a>(owner: TypedValue<String, ()>) -> &'a String {
///     owner.value()
/// }
/// ```
pub struct TypedValue<T, P> {
    value: T,
    _permits: Storage<P, P>,
}

impl<T, P> TypedValue<T, P> {
    pub fn value(&self) -> &T {
        &self.value
    }
}

pub enum TypedStep<T, P> {
    Progress,
    Complete(TypedValue<T, P>),
    Finished,
}

/// Retains an immutable input borrow throughout parsing and construction.
///
/// ```compile_fail,E0502
/// use dcbor::bounded::decode::{construction::TypedDecoder, Options};
/// let mut input = vec![0x61, b'a'];
/// let decoder = TypedDecoder::<String, ()>::new(&input, Options::normalizing(8));
/// input[1] = b'b';
/// drop(decoder);
/// ```
pub struct TypedDecoder<'a, T: ResumableDecodable, P> {
    // State may hold values backed by permits: field destruction order matters.
    state: T::State<P>,
    permits: Storage<P, P>,
    parser: Decoder<'a, P>,
    document: Option<Document<'a, P>>,
    finished: bool,
}

impl<'a, T: ResumableDecodable, P> TypedDecoder<'a, T, P> {
    pub fn new(input: &'a [u8], options: Options) -> Self {
        Self {
            state: T::start(),
            permits: Storage::new(),
            parser: Decoder::new(input, options),
            document: None,
            finished: false,
        }
    }

    pub fn parser_position(&self) -> super::cursor::Position {
        self.parser.position()
    }

    pub fn step<A: Allocator<Permit = P>>(
        &mut self,
        allocator: &mut A,
    ) -> ConstructResult<TypedStep<T, P>, A> {
        if self.finished {
            return Ok(TypedStep::Finished);
        }
        let result = self.advance(allocator);
        if matches!(&result, Err(error) if !matches!(error, DecodeError::Resource(BoundedError::Refused(_))))
        {
            self.state = T::start();
            self.permits = Storage::new();
            self.document = None;
            self.finished = true;
        }
        result
    }

    fn advance<A: Allocator<Permit = P>>(
        &mut self,
        allocator: &mut A,
    ) -> ConstructResult<TypedStep<T, P>, A> {
        let Some(document) = &self.document else {
            match self.parser.step(allocator)? {
                DecodeStep::Progress => {}
                DecodeStep::Complete(document) => self.document = Some(document),
                DecodeStep::Finished => return Err(BoundedError::PlanMismatch.into()),
            }
            return Ok(TypedStep::Progress);
        };
        match T::construct_step(document, 0, &mut self.state, &mut self.permits, allocator)? {
            BuildStep::Progress => Ok(TypedStep::Progress),
            BuildStep::Complete(value) => {
                self.document = None;
                self.finished = true;
                Ok(TypedStep::Complete(TypedValue {
                    value,
                    _permits: core::mem::take(&mut self.permits),
                }))
            }
        }
    }
}

/// Reserve the permit-table slot before acquiring a payload allocation. A
/// relocation may yield; its old and new owners remain in the table.
pub fn hold_step<A: Allocator>(
    bytes: u64,
    permits: &mut Storage<A::Permit, A::Permit>,
    allocator: &mut A,
) -> ConstructResult<bool, A> {
    if !permits.reserve_step(allocator)? {
        if permits.relocated() == 0 {
            permits.reserve_step(allocator)?;
        }
        return Ok(false);
    }
    let permit = allocator.allocate(bytes).map_err(BoundedError::Refused)?;
    permits
        .push_reserved(permit)
        .map_err(|_| BoundedError::PlanMismatch)?;
    Ok(true)
}

macro_rules! integers {
    ($($ty:ty),*) => {$(
        impl ResumableDecodable for $ty {
            type State<P> = ();
            fn start<P>() {}
            fn construct_step<A: Allocator>(document: &Document<'_, A::Permit>, index: usize,
                _: &mut (), _: &mut Storage<A::Permit, A::Permit>, allocator: &mut A,
            ) -> ConstructResult<BuildStep<Self>, A> {
                visit(allocator)?;
                let node = node_at(document, index).ok_or_else(wrong_type)?;
                let number = match node.kind() {
                    Kind::Unsigned(n) => i128::from(n), Kind::Negative(n) => i128::from(n),
                    _ => return Err(wrong_type()),
                };
                let value = <$ty>::try_from(number).map_err(|_| DecodeError::Invalid(Error::OutOfRange))?;
                Ok(BuildStep::Complete(value))
            }
        }
    )*};
}
integers!(u8, u16, u32, u64, usize, i8, i16, i32, i64);

impl ResumableDecodable for bool {
    type State<P> = ();
    fn start<P>() {}
    fn construct_step<A: Allocator>(
        document: &Document<'_, A::Permit>,
        index: usize,
        _: &mut (),
        _: &mut Storage<A::Permit, A::Permit>,
        allocator: &mut A,
    ) -> ConstructResult<BuildStep<Self>, A> {
        visit(allocator)?;
        match node_at(document, index).map(Node::kind) {
            Some(Kind::Bool(value)) => Ok(BuildStep::Complete(value)),
            _ => Err(wrong_type()),
        }
    }
}

pub struct StringState {
    phase: u8,
    value: String,
}

impl ResumableDecodable for String {
    type State<P> = StringState;
    fn start<P>() -> StringState {
        StringState {
            phase: 0,
            value: String::new(),
        }
    }
    fn construct_step<A: Allocator>(
        document: &Document<'_, A::Permit>,
        index: usize,
        state: &mut StringState,
        permits: &mut Storage<A::Permit, A::Permit>,
        allocator: &mut A,
    ) -> ConstructResult<BuildStep<Self>, A> {
        if state.phase == 0 {
            visit(allocator)?;
            if !matches!(
                node_at(document, index).map(Node::kind),
                Some(Kind::Text(_))
            ) {
                return Err(wrong_type());
            }
            state.phase = 1;
            return Ok(BuildStep::Progress);
        }
        let Some(Kind::Text(source)) = node_at(document, index).map(Node::kind) else {
            return Err(wrong_type());
        };
        if state.phase == 1 {
            let bytes = widen(source.len())?;
            if !hold_step(bytes, permits, allocator)? {
                return Ok(BuildStep::Progress);
            }
            state
                .value
                .try_reserve_exact(source.len())
                .map_err(|_| BoundedError::Allocation { bytes })?;
            state.phase = 2;
        }
        let start = state.value.len();
        let mut end = start + (source.len() - start).min(64);
        while !source.is_char_boundary(end) {
            end -= 1;
        }
        allocator
            .traverse(1, widen(end - start)?)
            .map_err(BoundedError::Refused)?;
        state.value.push_str(&source[start..end]);
        if end == source.len() {
            Ok(BuildStep::Complete(core::mem::take(&mut state.value)))
        } else {
            Ok(BuildStep::Progress)
        }
    }
}

pub struct BytesState {
    phase: u8,
    value: Vec<u8>,
}

impl ResumableDecodable for ByteString {
    type State<P> = BytesState;
    fn start<P>() -> BytesState {
        BytesState {
            phase: 0,
            value: Vec::new(),
        }
    }
    fn construct_step<A: Allocator>(
        document: &Document<'_, A::Permit>,
        index: usize,
        state: &mut BytesState,
        permits: &mut Storage<A::Permit, A::Permit>,
        allocator: &mut A,
    ) -> ConstructResult<BuildStep<Self>, A> {
        if state.phase == 0 {
            visit(allocator)?;
            if !matches!(
                node_at(document, index).map(Node::kind),
                Some(Kind::Bytes(_))
            ) {
                return Err(wrong_type());
            }
            state.phase = 1;
            return Ok(BuildStep::Progress);
        }
        let Some(Kind::Bytes(source)) = node_at(document, index).map(Node::kind) else {
            return Err(wrong_type());
        };
        if state.phase == 1 {
            let bytes = widen(source.len())?;
            if !hold_step(bytes, permits, allocator)? {
                return Ok(BuildStep::Progress);
            }
            state
                .value
                .try_reserve_exact(source.len())
                .map_err(|_| BoundedError::Allocation { bytes })?;
            state.phase = 2;
        }
        let start = state.value.len();
        let end = start + (source.len() - start).min(64);
        allocator
            .traverse(1, widen(end - start)?)
            .map_err(BoundedError::Refused)?;
        state.value.extend_from_slice(&source[start..end]);
        if end == source.len() {
            Ok(BuildStep::Complete(ByteString::from(core::mem::take(
                &mut state.value,
            ))))
        } else {
            Ok(BuildStep::Progress)
        }
    }
}

pub struct VecState<T: ResumableDecodable, P> {
    values: Vec<T>,
    child: Option<T::State<P>>,
    phase: u8,
    next: usize,
    end: usize,
    count: usize,
}

impl<T: ResumableDecodable> ResumableDecodable for Vec<T> {
    type State<P> = VecState<T, P>;
    fn start<P>() -> Self::State<P> {
        VecState {
            values: Vec::new(),
            child: None,
            phase: 0,
            next: 0,
            end: 0,
            count: 0,
        }
    }
    fn construct_step<A: Allocator>(
        document: &Document<'_, A::Permit>,
        index: usize,
        state: &mut Self::State<A::Permit>,
        permits: &mut Storage<A::Permit, A::Permit>,
        allocator: &mut A,
    ) -> ConstructResult<BuildStep<Self>, A> {
        if state.phase == 0 {
            visit(allocator)?;
            let node = node_at(document, index).ok_or_else(wrong_type)?;
            let Kind::Array(count) = node.kind() else {
                return Err(wrong_type());
            };
            state.count = usize::try_from(count).map_err(|_| BoundedError::Overflow)?;
            state.next = index + 1;
            state.end = next_index(node);
            state.phase = 1;
            return Ok(BuildStep::Progress);
        }
        if state.phase == 1 {
            let bytes = mul(widen(state.count)?, widen(core::mem::size_of::<T>())?)?;
            if !hold_step(bytes, permits, allocator)? {
                return Ok(BuildStep::Progress);
            }
            state
                .values
                .try_reserve_exact(state.count)
                .map_err(|_| BoundedError::Allocation { bytes })?;
            state.phase = 2;
        }
        if state.next == state.end {
            visit(allocator)?;
            return Ok(BuildStep::Complete(core::mem::take(&mut state.values)));
        }
        let child = state.child.get_or_insert_with(T::start);
        match T::construct_step(document, state.next, child, permits, allocator)? {
            BuildStep::Progress => {}
            BuildStep::Complete(value) => {
                state.values.push(value);
                state.child = None;
                state.next = next_index(node_at(document, state.next).ok_or_else(wrong_type)?);
            }
        }
        Ok(BuildStep::Progress)
    }
}
