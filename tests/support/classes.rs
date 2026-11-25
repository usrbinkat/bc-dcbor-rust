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
//! A held document's, a held input's and a held source value's cleanups are
//! their holder's, and a stop's cleanup and every position it passes
//! through are classed: so each class carries the held document's, input's
//! and source's own classes, by the input's reduction ([`DecodeInput`]) and
//! the value's, never their presence alone. A value whose construction
//! state declares no reduction is classed by its exact observation
//! ([`Exact`]).
//!
//! A boundary returns no class when no reduction covers it: every stop there
//! runs in both layers.
use core::any::Any;
use core::cmp::Ordering;
use core::convert::Infallible;
use core::fmt::{self, Debug};
use core::marker::PhantomData;

use dcbor::ByteString;
use dcbor::bounded::Limits;
use dcbor::bounded::decode::construction::in_place::{BufferClass, BufferObservation, Session};
use dcbor::bounded::decode::construction::{
    Custody, DecodeInput, InputClass, InputClassOf, InputDetail, InputObservation, OperationClass,
    ParseClass, ParseDetail, Position, Reclaim, Reduction, TypedPosition,
};
use dcbor::bounded::encoding::{OwnedEmitPosition, PlanDetail, ValueObservation};

/// The state of the pipelines' acquired input, a copied byte string
/// ([`Classes::input`], [`Classes::parse`]).
type Copied = <ByteString as Reclaim<Limits>>::State;

/// The identity reduction of a custody observation `O`: every observation
/// its own class, the finest relation, a simulation of any cleanup whose
/// state the observation is, as `Written`'s and `Prefix`'s own reductions
/// are. What a value whose construction state declares no reduction is
/// classed by where it is held (a preparation's or an emission's source).
/// Uninhabited: it names a reduction and is never a state, so nothing is
/// ever observed through it.
pub enum Exact<O> {
    Never(Infallible, PhantomData<O>),
}

impl<O: Copy + Eq + Ord + Debug> Custody for Exact<O> {
    type Observation = O;

    fn observe(&mut self) -> O {
        match self {
            Self::Never(never, _) => match *never {},
        }
    }
}

impl<O: Copy + Eq + Ord + Debug> Reduction for Exact<O> {
    type Class = O;

    fn class(observation: &O) -> O {
        *observation
    }
}

/// A boundary's cleanup class: its operation's class value, compared as
/// that value, never as a rendering. Classes of different operations are
/// distinct and ordered by operation. A typed decode's, an owned
/// preparation's and an emission's class types depend on the value they
/// hold, so each is held as a [`Decoded`].
///
/// `Debug` renders the operation's class alone, as the class inventory
/// (`rigor::classes`) records it.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    Input(OperationClass<InputClass<BufferClass>>),
    Parse(OperationClass<ParseClass<BufferClass>>),
    Decode(Decoded),
    Prepare(Decoded),
    Emit(Decoded),
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

/// A class of whatever class type its operation's reduction declares over
/// the value it holds (`Reduction::Class`: `Copy + Eq + Ord + Debug`): a
/// typed decode's, an owned preparation's, an emission's. Two classes of
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

/// The position of a typed decode of `T` from an input `I`: its parse's
/// and construction's details carry the input's state observation, and the
/// construction's the value's root session observation, its stage and the
/// binding's own.
pub type Typed<I, T> = TypedPosition<InputObservation<I, Limits>, ValueObservation<T, Limits>>;

/// The classifiers of one pipeline run, `N` the input observation and `O`
/// the value observation of the value it decodes: an input acquisition's
/// and a parse's of the copied input, a typed decode's of the value, the
/// owned preparation's of that value's encoding, and its emission's, the
/// last three each holding the value, observed by `N` and `O`.
pub struct Classes<N, O> {
    pub input: fn(&Position<InputDetail<BufferObservation>>) -> Option<Class>,
    pub parse: fn(&Position<ParseDetail<BufferObservation>>) -> Option<Class>,
    pub decode: fn(&TypedPosition<N, O>) -> Option<Class>,
    pub prepare: fn(&Position<PlanDetail<N, O>>) -> Option<Class>,
    pub emit: fn(&OwnedEmitPosition<N, O>) -> Option<Class>,
}

/// The classifiers of a pipeline decoding `T` from an input `I`.
pub type Pipeline<I, T> = Classes<InputObservation<I, Limits>, ValueObservation<T, Limits>>;

impl Classes<(), ()> {
    /// Acquisition and inspection: their operations' classes. They decode
    /// no value, so nothing holding one is classed.
    pub fn certified() -> Self {
        Self {
            input,
            parse,
            decode: |_| None,
            prepare: |_| None,
            emit: |_| None,
        }
    }
}

impl<N, O> Classes<N, O> {
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

/// A typed decode of `T` from an input `I` whose construction states
/// declare a cleanup reduction: its parse and construction stages both
/// classed.
pub fn reduced<I, T>() -> Pipeline<I, T>
where
    I: DecodeInput<Limits>,
    InputClassOf<I, Limits>: 'static,
    T: Reclaim<Limits>,
    Session<T::State>: Reduction<Class: 'static>,
{
    Classes {
        input,
        parse,
        decode: typed::<I, T>,
        prepare: prepare::<I, Session<T::State>>,
        emit: emit::<I, Session<T::State>>,
    }
}

/// A typed decode of `T` from an input `I` whose construction states
/// declare no reduction: its parse stage classed, by the input's reduction,
/// every construction boundary its own class; its preparation and emission
/// classed, the source value they hold by its exact observation
/// ([`Exact`]).
pub fn parsed<I, T>() -> Pipeline<I, T>
where
    I: DecodeInput<Limits>,
    InputClassOf<I, Limits>: 'static,
    T: Reclaim<Limits>,
    <T::State as Custody>::Observation: 'static,
{
    Classes {
        input,
        parse,
        decode: |position| match position {
            TypedPosition::Parse(parse) => Some(Class::Decode(Decoded::new(
                parse.class::<<I as Reclaim<Limits>>::State>(),
            ))),
            TypedPosition::Construct(_) | TypedPosition::Finished => None,
        },
        prepare: prepare::<I, Exact<ValueObservation<T, Limits>>>,
        emit: emit::<I, Exact<ValueObservation<T, Limits>>>,
    }
}

/// An input copy's class (its position's `class`).
pub fn input(position: &Position<InputDetail<BufferObservation>>) -> Option<Class> {
    Some(Class::Input(position.class()))
}

/// A parse's class of the copied input, its input's by the byte string's
/// reduction (its position's `class`).
pub fn parse(position: &Position<ParseDetail<BufferObservation>>) -> Option<Class> {
    Some(Class::Parse(position.class::<Copied>()))
}

/// A typed decode's class, its input's by the input state's reduction and
/// its value's by its session's ([`TypedPosition::class`]).
pub fn typed<I, T>(position: &Typed<I, T>) -> Option<Class>
where
    I: DecodeInput<Limits>,
    InputClassOf<I, Limits>: 'static,
    T: Reclaim<Limits>,
    Session<T::State>: Reduction<Class: 'static>,
{
    Some(Class::Decode(Decoded::new(
        position.class::<<I as Reclaim<Limits>>::State, Session<T::State>>(),
    )))
}

/// An owned preparation's class, its source's input by the input state's
/// reduction and its source value by `S` (its position's `class`).
pub fn prepare<I, S>(
    position: &Position<PlanDetail<InputObservation<I, Limits>, S::Observation>>,
) -> Option<Class>
where
    I: DecodeInput<Limits>,
    InputClassOf<I, Limits>: 'static,
    S: Reduction<Class: 'static>,
{
    Some(Class::Prepare(Decoded::new(
        position.class::<<I as Reclaim<Limits>>::State, S>(),
    )))
}

/// An emission boundary's class, its source's input by the input state's
/// reduction and its source value by `S` ([`OwnedEmitPosition::class`]).
pub fn emit<I, S>(
    position: &OwnedEmitPosition<InputObservation<I, Limits>, S::Observation>,
) -> Option<Class>
where
    I: DecodeInput<Limits>,
    InputClassOf<I, Limits>: 'static,
    S: Reduction<Class: 'static>,
{
    Some(Class::Emit(Decoded::new(
        position.class::<<I as Reclaim<Limits>>::State, S>(),
    )))
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
