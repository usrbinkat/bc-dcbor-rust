//! Cleanup classes of the owned pipeline's stop boundaries.
//!
//! A stop at a boundary (retiring, unwinding or cancelling there) verifies
//! one thing: the cleanup that follows from the state the boundary reached.
//! A class groups boundaries whose cleanup is claimed alike: the same
//! admitted units in the same order, everything released, nothing
//! allocated. Each boundary's class is its operation's declared cleanup
//! reduction ([`Reduction`]), stated beside that operation's cleanup in the
//! crate; this module only selects, for each boundary, the operation whose
//! reduction classes it. The exhaustive layer stops at every member of every
//! class and requires their cleanups to be equal, so a reduction that merges
//! states of different custody fails there, named.
//!
//! Classes compare boundaries of one pipeline run over one input: the
//! document a construction holds and the input a record holds are the same
//! at every boundary of that run, so a class need not carry their custody.
//!
//! A boundary returns no class when no reduction covers it: every stop there
//! runs in both layers.
use core::any::Any;
use core::cmp::Ordering;
use core::fmt::{self, Debug};

use dcbor::bounded::Limits;
use dcbor::bounded::decode::construction::in_place::{BufferClass, BufferObservation, Session};
use dcbor::bounded::decode::construction::{
    Custody, InputClass, InputDetail, OperationClass, ParseClass, ParseDetail, Position, Reclaim,
    Reduction, TypedPosition,
};
use dcbor::bounded::encoding::{EmitClass, OwnedEmitPosition, PlanClass, PlanDetail};

/// A boundary's cleanup class: its operation's class value, compared as
/// that value, never as a rendering. Classes of different operations are
/// distinct and ordered by operation. A typed decode's class type depends
/// on the value it decodes, so it is held as a [`Decoded`].
///
/// `Debug` renders the operation's class alone, as the class inventory
/// (`rigor::classes`) records it.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    Input(OperationClass<InputClass<BufferClass>>),
    Parse(OperationClass<ParseClass>),
    Decode(Decoded),
    Prepare(OperationClass<PlanClass>),
    Emit(EmitClass),
    /// A planted classifier's class, by its name: what a control that
    /// merges boundaries of different operations claims for all of them.
    Planted(&'static str),
}

impl Debug for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(class) => class.fmt(f),
            Self::Parse(class) => class.fmt(f),
            Self::Decode(class) => class.fmt(f),
            Self::Prepare(class) => class.fmt(f),
            Self::Emit(class) => class.fmt(f),
            Self::Planted(name) => name.fmt(f),
        }
    }
}

/// A typed decode's class, of whatever class type its value's reduction
/// declares (`Reduction::Class`: `Copy + Eq + Ord + Debug`). Two classes of
/// one type compare by that type's own `Eq` and `Ord`; classes of two types
/// are unequal, ordered by their types' identities, which are fixed for one
/// test binary.
pub struct Decoded(Box<dyn DecodedClass>);

/// What [`Decoded`] needs of a class value: its type's comparison, reached
/// through `Any`.
trait DecodedClass: Any + Debug {
    fn as_any(&self) -> &dyn Any;
    fn boxed(&self) -> Box<dyn DecodedClass>;
    /// `self` against `other`, which is of `self`'s type.
    fn compare(&self, other: &dyn Any) -> Ordering;
}

impl<C: Copy + Ord + Debug + 'static> DecodedClass for C {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn boxed(&self) -> Box<dyn DecodedClass> {
        Box::new(*self)
    }

    fn compare(&self, other: &dyn Any) -> Ordering {
        let other = other
            .downcast_ref::<C>()
            .expect("compared only with a class of its own type");
        self.cmp(other)
    }
}

impl Decoded {
    pub fn new<C: Copy + Ord + Debug + 'static>(class: C) -> Self {
        Self(Box::new(class))
    }
}

impl Clone for Decoded {
    fn clone(&self) -> Self {
        Self(self.0.boxed())
    }
}

impl Debug for Decoded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Ord for Decoded {
    fn cmp(&self, other: &Self) -> Ordering {
        let (mine, theirs) = (self.0.as_any(), other.0.as_any());
        Any::type_id(mine)
            .cmp(&Any::type_id(theirs))
            .then_with(|| self.0.compare(theirs))
    }
}

impl PartialOrd for Decoded {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Decoded {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Decoded {}

/// The position of a typed decode of `T`: its construction's detail carries
/// the value's root session observation, its stage and the binding's own.
pub type Typed<T> = TypedPosition<<Session<<T as Reclaim<Limits>>::State> as Custody>::Observation>;

/// The classifiers of one pipeline run: an input acquisition's, a parse's,
/// a typed decode's of the value the run decodes, the owned preparation's of
/// that value's encoding, and its emission's.
pub struct Classes<P> {
    pub input: fn(&Position<InputDetail<BufferObservation>>) -> Option<Class>,
    pub parse: fn(&Position<ParseDetail>) -> Option<Class>,
    pub decode: fn(&P) -> Option<Class>,
    pub prepare: fn(&Position<PlanDetail>) -> Option<Class>,
    pub emit: fn(&OwnedEmitPosition) -> Option<Class>,
}

impl Classes<()> {
    /// Acquisition and inspection: their operations' classes.
    pub fn certified() -> Self {
        Self {
            input,
            parse,
            decode: |_| None,
            prepare,
            emit,
        }
    }
}

impl<P> Classes<P> {
    /// Every boundary its own class: what a planted classifier is compared
    /// against, and what a run claims when it reduces nothing.
    pub fn none() -> Self {
        Self {
            input: |_| None,
            parse: |_| None,
            decode: |_| None,
            prepare: |_| None,
            emit: |_| None,
        }
    }
}

/// A typed decode of `T` whose construction states declare a cleanup
/// reduction: its parse and construction stages both classed.
pub fn reduced<T>() -> Classes<Typed<T>>
where
    T: Reclaim<Limits>,
    Session<T::State>: Reduction<Class: 'static>,
{
    Classes {
        input,
        parse,
        decode: typed::<T>,
        prepare,
        emit,
    }
}

/// A typed decode of `T` whose construction states declare no reduction:
/// its parse stage classed, every construction boundary its own class.
pub fn parsed<T: Reclaim<Limits>>() -> Classes<Typed<T>> {
    Classes {
        input,
        parse,
        decode: |position| match position {
            TypedPosition::Parse(parse_position) => parse(parse_position),
            TypedPosition::Construct(_) | TypedPosition::Finished => None,
        },
        prepare,
        emit,
    }
}

/// An input copy's class (its position's `class`).
pub fn input(position: &Position<InputDetail<BufferObservation>>) -> Option<Class> {
    Some(Class::Input(position.class()))
}

/// A parse's class (its position's `class`).
pub fn parse(position: &Position<ParseDetail>) -> Option<Class> {
    Some(Class::Parse(position.class()))
}

/// A typed decode's class, its value's by its session's reduction
/// ([`TypedPosition::class`]).
pub fn typed<T>(position: &Typed<T>) -> Option<Class>
where
    T: Reclaim<Limits>,
    Session<T::State>: Reduction<Class: 'static>,
{
    Some(Class::Decode(Decoded::new(
        position.class::<Session<T::State>>(),
    )))
}

/// An owned preparation's class, whatever value it encodes (its position's
/// `class`).
pub fn prepare(position: &Position<PlanDetail>) -> Option<Class> {
    Some(Class::Prepare(position.class()))
}

/// An emission boundary's class, whatever value it encodes
/// ([`OwnedEmitPosition::class`]).
pub fn emit(position: &OwnedEmitPosition) -> Option<Class> {
    Some(Class::Emit(position.class()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode classes compare as their values: equal values of one type are
    /// one class, different values two, ordered as their type orders them;
    /// equal renderings of two types are two classes; a clone is its
    /// original's class; and `Debug` renders the value alone, as the
    /// inventory records it.
    #[test]
    fn decode_classes_compare_as_their_typed_values() {
        let one = Class::Decode(Decoded::new(1u8));
        assert_eq!(one, Class::Decode(Decoded::new(1u8)), "equal values");
        assert_eq!(one, one.clone(), "a clone");
        assert_ne!(one, Class::Decode(Decoded::new(2u8)), "different values");
        assert!(
            Decoded::new(1u8) < Decoded::new(2u8),
            "the type's own order"
        );
        assert_ne!(
            one,
            Class::Decode(Decoded::new(1u16)),
            "one rendering of two types"
        );
        assert_eq!(format!("{one:?}"), "1");
        assert_ne!(one, Class::Planted("1"), "another operation's class");
    }
}
