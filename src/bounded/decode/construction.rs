//! Stable typed construction with explicit lifecycle custody.
//!
//! One scope owner ([`DecodeOwner`]) holds every record. One controller
//! ([`Operation`]) drives every retained operation: input acquisition
//! ([`InputAcquisition`], [`InputBorrow`]), parsing ([`DocumentDecoder`]),
//! construction ([`Construction`]) and typed decoding ([`TypedDecoder`], a
//! parse followed by a construction).
use super::{Document, Node, wrong_type};

mod construct;
pub mod in_place;
mod input;
mod operation;
mod parse;
pub mod reclamation;
pub(crate) mod stable;

pub use construct::{
    ConstructDetail, ConstructPhase, Construction, TypedDecoder, TypedPosition, TypedValue,
    construction_bound, typed_decode_bound,
};
pub use input::{
    Borrowed, DecodeInput, InputAcquisition, InputBorrow, InputDetail, borrow_bound, copy_bound,
};
pub use operation::{Operation, Position};
pub(crate) use operation::{OperationTerms, Task};
pub use parse::{DocumentDecoder, OwnedDocument, ParseDetail, ParsePhase, parse_bound};
pub use reclamation::{
    Acquisition, Custody, DecodeOwner, OwnedInitialized, OwnedRecord, Prefix, Reclaim, Reclaimed,
    Reduction, ScopePosition, Written, scope_bound,
};

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

/// Place attribution of the owned lifecycle, which this crate's tests record
/// under `std`: a scope's own lifecycle, then each operation run under its
/// own policy, the operations it depends on prepared under others. Each run
/// is checked at every kind of place it charges whose bound names it: its
/// operations' ([`OperationPlace`]), summed over every operation whose
/// records the run allocates, cleans or releases, and its task's own, within
/// the operation's task.
#[cfg(all(test, feature = "std"))]
mod attribution {
    use super::construct::{ConstructPhase, ConstructPlace, ConstructTerms, construct_terms};
    use super::input::{InputPlace, borrow_terms, copy_terms};
    use super::operation::{OperationPlace, OperationTerms};
    use super::parse::{ParsePlace, parse_terms};
    use super::reclamation::{ScopePlace, ScopeTerms};
    use super::*;
    use crate::bounded::decode::Options;
    use crate::bounded::places::{self, Factor, Ledgered, Run};
    use crate::bounded::{Failure, Places, ResourceBound, Resumable, Step};
    use crate::{ByteString, CBOR};
    use core::ops::ControlFlow;
    use std::any::Any;

    type A = Ledgered;
    type Value = Vec<String>;
    type Input = OwnedInitialized<'static, ByteString, A>;

    fn options() -> Options {
        Options::normalizing(4)
    }

    fn len(bytes: &[u8]) -> u64 {
        bytes.len() as u64
    }

    /// How a driven operation ended without publishing: the invalid input it
    /// rejected and the position it rejected it at, if it did, and the
    /// position it finished at.
    #[derive(Debug)]
    struct Ended<P> {
        rejected: Option<String>,
        finished: P,
    }

    /// The one terminal error a run may measure: an input rejected as
    /// invalid. A defect, a refusal or a physical failure fails the run,
    /// naming it, its class and the position the operation was at.
    fn admissible<E: Failure + core::fmt::Debug>(
        name: &str,
        error: &E,
        position: &impl core::fmt::Debug,
    ) -> String
    where
        E::Refusal: core::fmt::Debug,
    {
        assert!(
            matches!(error.class(), crate::bounded::Class::Invalid),
            "{name}: {error:?}, of class {:?}, at {position:?}",
            error.class()
        );
        format!("{error:?} at {position:?}")
    }

    /// Step `operation`, within the steps `bound` allows
    /// ([`crate::bounded::within`]), until it publishes, or finishes after its
    /// own cleanup steps following a terminal error or a cancellation.
    fn drive<O: Resumable<A>>(
        name: &str,
        operation: &mut O,
        policy: &mut A,
        bound: ResourceBound,
    ) -> Result<O::Output, Ended<O::Position>>
    where
        O::Error: core::fmt::Debug,
    {
        let mut rejected = None;
        crate::bounded::within(name, bound, || {
            let position = operation.position();
            match operation.step(policy) {
                Ok(Step::Progress) => ControlFlow::Continue(()),
                Ok(Step::Complete(output)) => {
                    assert!(
                        rejected.is_none(),
                        "{name}: published after rejection at {position:?}"
                    );
                    ControlFlow::Break(Ok(output))
                }
                Ok(Step::Finished) => ControlFlow::Break(Err(Ended {
                    rejected: rejected.take(),
                    finished: operation.position(),
                })),
                Err(error) => {
                    assert!(
                        rejected.is_none(),
                        "{name}: repeated rejection at {position:?}"
                    );
                    rejected = Some(admissible(name, &error, &position));
                    ControlFlow::Continue(())
                }
            }
        })
    }

    /// The bound of a scope's own lifecycle: its initialization, its drain
    /// of nothing and its shutdown.
    fn scope_bound() -> ResourceBound {
        ScopeTerms::of::<A, ()>()
            .and_then(|terms| terms.bound())
            .expect("the scope bound fits in u64")
    }

    /// The bound of copying `bytes`.
    fn copy_bound_of(bytes: &[u8]) -> ResourceBound {
        copy_bound::<A, ()>(len(bytes)).expect("the copy bound fits in u64")
    }

    /// The bound of borrowing an input.
    fn borrow_bound_of() -> ResourceBound {
        borrow_bound::<A, ()>().expect("the borrow bound fits in u64")
    }

    /// The bound of parsing `bytes`.
    fn parse_bound_of(bytes: &[u8]) -> ResourceBound {
        parse_bound::<ByteString, A, ()>(len(bytes), options())
            .expect("the parse bound fits in u64")
    }

    /// The bound of constructing a [`Value`] from a document of `bytes`.
    fn construction_bound_of(bytes: &[u8]) -> ResourceBound {
        construction_bound::<ByteString, Value, A, ()>(len(bytes))
            .expect("the construction bound fits in u64")
    }

    /// A scope initialized under a policy of its own.
    fn scope() -> DecodeOwner<'static, A> {
        let mut owner = DecodeOwner::new();
        owner
            .initialize_step(&mut Ledgered::new())
            .expect("a scope initializes without limits");
        owner
    }

    /// `bytes` copied under a policy of its own.
    fn copied(owner: &DecodeOwner<'static, A>, bytes: &[u8]) -> Input {
        drive(
            "copy",
            &mut owner.copy_input(bytes),
            &mut Ledgered::new(),
            copy_bound_of(bytes),
        )
        .expect("a copy completes")
    }

    /// `bytes` copied and parsed under policies of their own.
    fn parsed(
        owner: &DecodeOwner<'static, A>,
        bytes: &[u8],
    ) -> OwnedDocument<'static, ByteString, A> {
        let input = copied(owner, bytes);
        drive(
            "parse",
            &mut DocumentDecoder::parse(input, options()),
            &mut Ledgered::new(),
            parse_bound_of(bytes),
        )
        .expect("a valid input parses")
    }

    /// A scope and the handles its runs published, held until every run is
    /// checked, then released and the scope drained and shut down, within
    /// `bound`: the scope's own lifecycle and the bound of every operation
    /// whose records the handles hold, each of which covers its cleanup.
    struct Kept {
        owner: DecodeOwner<'static, A>,
        handles: Vec<Box<dyn Any>>,
        bound: ResourceBound,
    }

    impl Kept {
        /// `owner` holding `handles`, the records of operations of `bounds`.
        fn new(
            owner: DecodeOwner<'static, A>,
            handles: Vec<Box<dyn Any>>,
            bounds: &[ResourceBound],
        ) -> Self {
            let bound = bounds.iter().fold(scope_bound(), |total, bound| {
                total
                    .then::<()>(*bound)
                    .expect("a kept scope's bound fits in u64")
            });
            Self {
                owner,
                handles,
                bound,
            }
        }

        /// Retire the handles and measure the real queue-removal path, which
        /// operation-local cancellation does not take.
        fn retire(&mut self, policy: &mut Ledgered) {
            self.handles.clear();
            let owner = &mut self.owner;
            crate::bounded::within("scope drain", self.bound, || {
                match owner.step(policy).expect("a scope drains without limits") {
                    Reclaimed::Done => ControlFlow::Break(()),
                    Reclaimed::Progress => ControlFlow::Continue(()),
                    Reclaimed::Waiting => panic!("every handle of the scope was released"),
                }
            });
            assert_eq!(
                policy.ledger().total().retained,
                0,
                "retirement retained storage"
            );
        }

        fn release(mut self) {
            let mut policy = Ledgered::new();
            self.retire(&mut policy);
            let Self {
                mut owner,
                handles,
                bound,
            } = self;
            assert!(handles.is_empty());
            crate::bounded::within("scope shutdown", bound, || {
                match owner
                    .shutdown_step(&mut policy)
                    .expect("a scope shuts down without limits")
                {
                    Reclaimed::Done => ControlFlow::Break(()),
                    _ => ControlFlow::Continue(()),
                }
            });
        }
    }

    /// The bound of each operation the runs depend on, of `bytes`, and the
    /// in-place cleanup of each record a later operation holds and reclaims.
    struct Bounds {
        copy: OperationTerms,
        parse: OperationTerms,
        /// A copied input's record reclaimed in place.
        input: ResourceBound,
        /// A published document's record reclaimed in place, its input's
        /// record included.
        document: ResourceBound,
    }

    fn bounds(bytes: &[u8]) -> Bounds {
        // The copy's buffer released ([`ByteString`]'s binding); its record's
        // release was paid for by the record's acquisition, which the copy's
        // record term counts.
        let input = super::in_place::text::buffer_cleanup::<ByteString>();
        let (parse, task) = parse_terms::<ByteString, A, ()>(len(bytes), options(), input).unwrap();
        // The document's record: its transition, its arena's cleanup and an
        // emptied slot; its input's record; its released parser's one unit.
        // The record's own release was paid for by its acquisition, which
        // the parse's record term counts.
        let document = task
            .term(ParsePlace::Cleanup)
            .then::<()>(task.term(ParsePlace::Input))
            .and_then(|bound| {
                bound.then(ResourceBound::of_work(
                    crate::bounded::decode::cursor::finished_cleanup()?,
                ))
            })
            .unwrap();
        Bounds {
            copy: copy_terms::<A, ()>(len(bytes)).unwrap().0,
            parse,
            input,
            document,
        }
    }

    /// Where a construction run is cancelled.
    #[derive(Clone, Copy, Debug)]
    enum Cancel {
        Never,
        /// Once it reaches this phase, which it must.
        At(ConstructPhase),
        /// After this many steps, unless it published or finished before.
        After(usize),
    }

    /// One construction of a [`Value`] from `bytes`, parsed under a policy of
    /// its own, then constructed under one recording at operation places
    /// and at construction places: whether it published, its run at the
    /// operations it touches (its own, the parse whose document it reclaims
    /// and the copy whose input it reclaims), its run at its own places, and
    /// what to release once both are checked.
    fn constructed(
        name: &str,
        bytes: &[u8],
        cancel: Cancel,
    ) -> (bool, Run<Vec<OperationTerms>>, Run<ConstructTerms>, Kept) {
        let valid = Value::try_from(
            CBOR::try_from_data(bytes).expect("construction input parses symbolically"),
        )
        .is_ok();
        let owner = scope();
        let document = parsed(&owner, bytes);
        let mut policy = Ledgered::new();
        let mut operation: Construction<'static, ByteString, Value, A> =
            Construction::construct(document);
        let mut value = None;
        match cancel {
            Cancel::Never => {}
            Cancel::At(phase) => {
                crate::bounded::within(name, construction_bound_of(bytes), || {
                    if operation.position().detail.phase == Some(phase) {
                        return ControlFlow::Break(());
                    }
                    assert!(matches!(operation.step(&mut policy), Ok(Step::Progress)));
                    ControlFlow::Continue(())
                });
                operation.cancel();
            }
            Cancel::After(steps) => {
                for _ in 0..steps {
                    let position = operation.position();
                    match operation.step(&mut policy) {
                        Ok(Step::Progress) => {}
                        Ok(Step::Complete(published)) => {
                            value = Some(published);
                            break;
                        }
                        Ok(Step::Finished) => break,
                        Err(error) => {
                            admissible(name, &error, &position);
                        }
                    }
                }
                operation.cancel();
            }
        }
        if value.is_none() {
            match drive(
                name,
                &mut operation,
                &mut policy,
                construction_bound_of(bytes),
            ) {
                Ok(published) => value = Some(published),
                Err(ended) => {
                    if matches!(cancel, Cancel::Never) {
                        assert!(
                            ended.rejected.is_some(),
                            "{name}: finished without rejection at {:?}",
                            ended.finished
                        );
                    }
                }
            }
        }
        drop(operation);
        let bounds = bounds(bytes);
        let (operation, task) =
            construct_terms::<ByteString, Value, A, ()>(len(bytes), bounds.document, bounds.input)
                .unwrap();
        let published = value.is_some();
        match cancel {
            Cancel::Never => assert_eq!(published, valid, "{name}: declared construction outcome"),
            Cancel::At(_) => assert!(!published, "{name}: published after cancellation"),
            Cancel::After(_) => assert!(!published || valid, "{name}: published an invalid value"),
        }
        (
            published,
            Run {
                name: name.to_string(),
                outcome: if published {
                    places::Outcome::Published
                } else if matches!(cancel, Cancel::Never) {
                    places::Outcome::Invalid
                } else {
                    places::Outcome::Cancelled
                },
                policy: policy.shared(),
                terms: vec![operation, bounds.parse, bounds.copy],
            },
            Run {
                name: name.to_string(),
                outcome: if published {
                    places::Outcome::Published
                } else if matches!(cancel, Cancel::Never) {
                    places::Outcome::Invalid
                } else {
                    places::Outcome::Cancelled
                },
                policy,
                terms: task,
            },
            Kept::new(
                owner,
                value
                    .into_iter()
                    .map(|v| Box::new(v) as Box<dyn Any>)
                    .collect(),
                &[
                    copy_bound_of(bytes),
                    parse_bound_of(bytes),
                    construction_bound_of(bytes),
                ],
            ),
        )
    }

    /// Every place of a construction is within its term on generated
    /// inputs: canonical values of every major type, most not of the
    /// constructed type, and arrays of generated texts, which are; every
    /// third cancelled after a number of steps, and every sixth, an array of
    /// texts, cancelled once its input is detached, so the input's own
    /// reclamation is exercised. Checked at the operations each run touches
    /// and at its own places within its task.
    #[test]
    fn every_place_of_a_construction_is_within_its_term_on_generated_inputs() {
        let mut generator = crate::bounded::tests::Generator::new(0x5eed_0004);
        let mut operations = Vec::new();
        let mut constructs = Vec::new();
        let mut kept = Vec::new();
        for index in 0..200usize {
            let bytes = if index % 2 == 0 {
                generator.value(3).to_cbor_data()
            } else {
                let len = generator.below(6);
                let texts: Vec<String> = (0..len).map(|_| generator.text(40)).collect();
                CBOR::from(texts).to_cbor_data()
            };
            // An odd index is an array of texts, which reaches publication.
            let cancel = match index % 6 {
                0 | 3 => Cancel::After(index % 30 + 1),
                1 => Cancel::At(ConstructPhase::Publish),
                _ => Cancel::Never,
            };
            let (_, operation, construct, scope) =
                constructed(&format!("generated {index}, {cancel:?}"), &bytes, cancel);
            operations.push(operation);
            constructs.push(construct);
            kept.push(scope);
        }
        // Publication and local cancellation above retain their independent
        // oracles. This additional run measures retirement through the queue,
        // including the removal charge absent from local reclamation.
        let bytes = CBOR::from(vec!["retired".to_string()]).to_cbor_data();
        let (published, mut operation, mut construct, mut scope) =
            constructed("retired construction", &bytes, Cancel::Never);
        assert!(published);
        // Detachment queued the parser record independently of the live
        // construction. Drain it under its own policy before measuring the
        // construction's retirement: its ParsePlace charges are not charges
        // of ConstructPlace. The live value must keep the queue waiting.
        let mut parser_cleanup = Ledgered::new();
        let parser_bound = bounds(&bytes).parse.bound::<()>().unwrap();
        let owner = &mut scope.owner;
        crate::bounded::within("detached parser's cleanup", parser_bound, || {
            match owner.step(&mut parser_cleanup).unwrap() {
                Reclaimed::Progress => ControlFlow::Continue(()),
                Reclaimed::Waiting => ControlFlow::Break(()),
                Reclaimed::Done => panic!("published construction lost its record"),
            }
        });
        scope.retire(&mut operation.policy);
        operation.outcome = places::Outcome::Exact;
        construct.outcome = places::Outcome::Exact;
        operations.push(operation);
        constructs.push(construct);
        kept.push(scope);
        places::check(&operations);
        places::check_within(&constructs, OperationPlace::Task);
        for scope in kept {
            scope.release();
        }
    }

    /// Every place of the owned lifecycle is within its term, at every kind
    /// of place a run charges; every admission and request is made at some
    /// place of each kind it is checked at; each place's witness charges it.
    /// Beside the witnesses: a copy and a borrow published.
    #[test]
    fn every_place_of_the_owned_lifecycle_is_within_its_term() {
        let valid = CBOR::from(vec!["a".repeat(150), "b".repeat(3)]).to_cbor_data();
        let mixed = CBOR::from(vec![CBOR::from("c".repeat(90)), CBOR::from(1u64)]).to_cbor_data();
        // An element per input byte: what an affine cost per byte
        // ([`in_place::ConstructionCost`]) charges most for.
        let empties = CBOR::from(vec![String::new(); 500]).to_cbor_data();
        let mut truncated = valid.clone();
        truncated.truncate(valid.len() - 10);
        let borrowed: &'static [u8] = valid.clone().leak();

        let mut kept = Vec::new();
        let mut scopes = Vec::new();
        let mut scope_witnesses = Vec::new();
        let mut operations: Vec<Run<Vec<OperationTerms>>> = Vec::new();
        let mut operation_witnesses = Vec::new();
        let mut copies = Vec::new();
        let mut copy_witnesses = Vec::new();
        let mut borrows = Vec::new();
        let mut borrow_witnesses = Vec::new();
        let mut parses = Vec::new();
        let mut parse_witnesses = Vec::new();
        let mut constructs = Vec::new();
        let mut construct_witnesses = Vec::new();

        // A scope's own lifecycle: initialized, then shut down empty.
        {
            let mut policy = Ledgered::new();
            let mut owner = DecodeOwner::<'static, A>::new();
            owner
                .initialize_step(&mut policy)
                .expect("a scope initializes without limits");
            crate::bounded::within("scope shutdown", scope_bound(), || {
                match owner
                    .shutdown_step(&mut policy)
                    .expect("a scope shuts down without limits")
                {
                    Reclaimed::Done => ControlFlow::Break(()),
                    _ => ControlFlow::Continue(()),
                }
            });
            scope_witnesses.push((scopes.len(), ScopePlace::Initialization));
            scopes.push(Run {
                outcome: places::Outcome::Published,
                name: "scope".to_string(),
                policy,
                terms: ScopeTerms::of::<A, ()>().unwrap(),
            });
        }

        // A copy, published.
        {
            let owner = scope();
            let mut policy = Ledgered::new();
            let input = drive(
                "copy",
                &mut owner.copy_input(&valid),
                &mut policy,
                copy_bound_of(&valid),
            )
            .expect("a copy completes");
            let (operation, task) = copy_terms::<A, ()>(len(&valid)).unwrap();
            operation_witnesses.push((operations.len(), OperationPlace::Record));
            operation_witnesses.push((operations.len(), OperationPlace::Task));
            copies.push(Run {
                name: "copy".to_string(),
                outcome: places::Outcome::Published,
                policy: policy.shared(),
                terms: task,
            });
            operations.push(Run {
                name: "copy".to_string(),
                outcome: places::Outcome::Published,
                policy,
                terms: vec![operation],
            });
            kept.push(Kept::new(
                owner,
                vec![Box::new(input)],
                &[copy_bound_of(&valid)],
            ));
        }

        // A copy cancelled mid-copy: its partial copy and its record cleaned
        // and released in place, then its scope reference retired.
        {
            let owner = scope();
            let mut policy = Ledgered::new();
            let mut operation = owner.copy_input(&valid);
            for _ in 0..5 {
                assert!(matches!(operation.step(&mut policy), Ok(Step::Progress)));
            }
            operation.cancel();
            let ended = drive(
                "cancelled copy",
                &mut operation,
                &mut policy,
                copy_bound_of(&valid),
            )
            .err()
            .expect("a cancelled copy finishes unpublished");
            assert!(ended.rejected.is_none(), "{ended:?}");
            drop(operation);
            let (operation, task) = copy_terms::<A, ()>(len(&valid)).unwrap();
            copy_witnesses.push((copies.len(), InputPlace::Settle));
            copies.push(Run {
                name: "cancelled copy".to_string(),
                outcome: places::Outcome::Cancelled,
                policy: policy.shared(),
                terms: task,
            });
            operations.push(Run {
                name: "cancelled copy".to_string(),
                outcome: places::Outcome::Cancelled,
                policy,
                terms: vec![operation],
            });
            kept.push(Kept::new(owner, Vec::new(), &[]));
        }

        // A published copy retired through the queue, witnessing removal.
        // Local cancellation above releases its record directly and must not
        // be used as evidence for this distinct charge.
        {
            let owner = scope();
            let mut policy = Ledgered::new();
            let input = drive(
                "retired copy",
                &mut owner.copy_input(&valid),
                &mut policy,
                copy_bound_of(&valid),
            )
            .expect("a copy completes");
            let mut retired = Kept::new(owner, vec![Box::new(input)], &[copy_bound_of(&valid)]);
            retired.retire(&mut policy);
            operation_witnesses.push((operations.len(), OperationPlace::Release));
            operations.push(Run {
                name: "retired copy".to_string(),
                outcome: places::Outcome::Exact,
                policy,
                terms: vec![copy_terms::<A, ()>(len(&valid)).unwrap().0],
            });
            kept.push(retired);
        }

        // A borrow, published.
        {
            let owner = scope();
            let mut policy = Ledgered::new();
            let input = drive(
                "borrow",
                &mut owner.borrow_input(borrowed),
                &mut policy,
                borrow_bound_of(),
            )
            .expect("a borrow completes");
            let (operation, task) = borrow_terms::<A, ()>().unwrap();
            operation_witnesses.push((operations.len(), OperationPlace::Initialization));
            borrow_witnesses.push((borrows.len(), InputPlace::Settle));
            borrows.push(Run {
                name: "borrow".to_string(),
                outcome: places::Outcome::Published,
                policy: policy.shared(),
                terms: task,
            });
            operations.push(Run {
                name: "borrow".to_string(),
                outcome: places::Outcome::Published,
                policy,
                terms: vec![operation],
            });
            kept.push(Kept::new(
                owner,
                vec![Box::new(input)],
                &[borrow_bound_of()],
            ));
        }

        // A borrow cancelled once recorded: the borrow retired and its record
        // released in place, then its scope reference retired.
        {
            let owner = scope();
            let mut policy = Ledgered::new();
            let mut operation = owner.borrow_input(borrowed);
            for _ in 0..2 {
                assert!(matches!(operation.step(&mut policy), Ok(Step::Progress)));
            }
            operation.cancel();
            let ended = drive(
                "cancelled borrow",
                &mut operation,
                &mut policy,
                borrow_bound_of(),
            )
            .err()
            .expect("a cancelled borrow finishes unpublished");
            assert!(ended.rejected.is_none(), "{ended:?}");
            drop(operation);
            let (operation, task) = borrow_terms::<A, ()>().unwrap();
            borrow_witnesses.push((borrows.len(), InputPlace::Borrow));
            borrows.push(Run {
                name: "cancelled borrow".to_string(),
                outcome: places::Outcome::Cancelled,
                policy: policy.shared(),
                terms: task,
            });
            operations.push(Run {
                name: "cancelled borrow".to_string(),
                outcome: places::Outcome::Cancelled,
                policy,
                terms: vec![operation],
            });
            kept.push(Kept::new(owner, Vec::new(), &[]));
        }

        // A parse, published; and a parse of a truncated input, whose
        // cleanup reclaims its arena, its parser and its input in place.
        for (name, bytes, published) in [
            ("parse", &valid, true),
            ("truncated parse", &truncated, false),
        ] {
            let owner = scope();
            let input = copied(&owner, bytes);
            let mut policy = Ledgered::new();
            let document = drive(
                name,
                &mut DocumentDecoder::parse(input, options()),
                &mut policy,
                parse_bound_of(bytes),
            );
            assert_eq!(document.is_ok(), published, "{name}");
            if let Err(ended) = &document {
                assert!(
                    ended.rejected.is_some(),
                    "{name}: finished without rejecting its input at {:?}",
                    ended.finished
                );
            }
            let bounds = bounds(bytes);
            let (operation, task) =
                parse_terms::<ByteString, A, ()>(len(bytes), options(), bounds.input).unwrap();
            places::nested(
                ParsePlace::Parse,
                task.term(ParsePlace::Parse),
                crate::bounded::decode::cursor::retained_decode_bound::<places::Permit, ()>(
                    len(bytes),
                    options(),
                )
                .unwrap(),
            );
            let witnessed: &[ParsePlace] = if published {
                &[ParsePlace::Parse, ParsePlace::Transfer, ParsePlace::Publish]
            } else {
                &[ParsePlace::Cleanup, ParsePlace::Input]
            };
            parse_witnesses.extend(witnessed.iter().map(|&place| (parses.len(), place)));
            parses.push(Run {
                name: name.to_string(),
                outcome: if published {
                    places::Outcome::Published
                } else {
                    places::Outcome::Invalid
                },
                policy: policy.shared(),
                terms: task,
            });
            operations.push(Run {
                name: name.to_string(),
                outcome: if published {
                    places::Outcome::Published
                } else {
                    places::Outcome::Invalid
                },
                policy,
                terms: vec![operation, bounds.copy],
            });
            kept.push(Kept::new(
                owner,
                document
                    .into_iter()
                    .map(|d| Box::new(d) as Box<dyn Any>)
                    .collect(),
                &[copy_bound_of(bytes), parse_bound_of(bytes)],
            ));
        }

        // A construction, published; one failing on a value of the wrong
        // type after building a string, which reclaims the value and the
        // document in place; and one cancelled after detaching the input,
        // which reclaims the value and the input in place.
        for (name, bytes, cancel) in [
            ("construction", &valid, Cancel::Never),
            ("construction of empty strings", &empties, Cancel::Never),
            ("wrongly typed construction", &mixed, Cancel::Never),
            (
                "cancelled construction",
                &valid,
                Cancel::At(ConstructPhase::Publish),
            ),
        ] {
            let (published, operation, construct, scope) = constructed(name, bytes, cancel);
            let witnessed: &[ConstructPlace] = match (bytes == &empties, published, cancel) {
                (true, _, _) => &[ConstructPlace::Build],
                (false, true, _) => &[ConstructPlace::Detach, ConstructPlace::Publish],
                (false, false, Cancel::Never) => {
                    &[ConstructPlace::Cleanup, ConstructPlace::Document]
                }
                (false, false, _) => &[ConstructPlace::Input],
            };
            construct_witnesses.extend(witnessed.iter().map(|&place| (constructs.len(), place)));
            constructs.push(construct);
            operations.push(operation);
            kept.push(scope);
        }

        // The whole chain under one policy: a copy, its parse and the
        // construction of its texts, each record moved into the next or
        // retired with the scope: what a caller is charged for decoding a
        // value from bytes it holds, each at two sizes. Undecided texts whose
        // marks run unbroken drive its work; empty strings, a node and an
        // element per byte, its storage.
        let mut chains = Vec::new();
        let undecided = |texts: usize, pairs: usize| {
            CBOR::from(vec![format!("q{}", "\u{316}\u{301}".repeat(pairs)); texts]).to_cbor_data()
        };
        let empty = |count: usize| CBOR::from(vec![String::new(); count]).to_cbor_data();
        for (name, bytes, dimensions) in [
            ("4 texts of 100 pairs", undecided(4, 100), places::WORK),
            ("16 texts of 400 pairs", undecided(16, 400), places::WORK),
            ("500 empty strings", empty(500), places::STORAGE),
            ("4000 empty strings", empty(4000), places::STORAGE),
        ] {
            let owner = scope();
            let mut policy = Ledgered::new();
            let input = drive(
                "chained copy",
                &mut owner.copy_input(&bytes),
                &mut policy,
                copy_bound_of(&bytes),
            )
            .expect("a copy completes");
            let document = drive(
                "chained parse",
                &mut DocumentDecoder::parse(input, options()),
                &mut policy,
                parse_bound_of(&bytes),
            )
            .expect("canonical texts parse");
            let mut construction: Construction<'static, ByteString, Value, A> =
                Construction::construct(document);
            let value = drive(
                "chained construction",
                &mut construction,
                &mut policy,
                construction_bound_of(&bytes),
            )
            .expect("an array of texts constructs");
            drop(construction);
            let bounds = bounds(&bytes);
            let (construct, _) = construct_terms::<ByteString, Value, A, ()>(
                len(&bytes),
                bounds.document,
                bounds.input,
            )
            .unwrap();
            // What a caller holding the bytes composes from the public
            // bounds: the copy, then the typed decode while the copy's
            // record is held in the document's.
            let public = copy_bound::<A, ()>(len(&bytes))
                .unwrap()
                .then::<()>(
                    typed_decode_bound::<ByteString, Value, A, ()>(len(&bytes), options()).unwrap(),
                )
                .unwrap();
            let chain = format!("typed decode chain of {name}");
            chains.push((chain.clone(), dimensions, public));
            operations.push(Run {
                name: chain,
                outcome: places::Outcome::Published,
                policy,
                terms: vec![construct, bounds.parse, bounds.copy],
            });
            // The decoded value's owned preparation under a policy of its
            // own, its value moved into the plan's record: the same inputs
            // drive its normalization and its arenas.
            let shape = crate::bounded::encoding::Shape::of(
                value.value(),
                &mut crate::bounded::Limits::unlimited(),
            )
            .expect("a decoded value walks without limits");
            let mut policy = Ledgered::new();
            let public =
                crate::bounded::encoding::owned_prepare_bound::<ByteString, Value, A, ()>(shape)
                    .unwrap();
            let prepared = drive(
                "owned preparation",
                &mut crate::bounded::encoding::OwnedPreparation::prepare(value),
                &mut policy,
                public,
            )
            .expect("a decoded value prepares");
            let preparation = format!("owned preparation of {name}");
            chains.push((preparation.clone(), dimensions, public));
            operations.push(Run {
                name: preparation,
                outcome: places::Outcome::Published,
                policy,
                terms: vec![
                    crate::bounded::encoding::owned_prepare_terms::<ByteString, Value, A, ()>(
                        shape,
                    )
                    .unwrap(),
                ],
            });
            kept.push(Kept::new(
                owner,
                vec![Box::new(prepared)],
                &[
                    copy_bound_of(&bytes),
                    parse_bound_of(&bytes),
                    construction_bound_of(&bytes),
                    public,
                ],
            ));
        }

        places::check(&scopes);
        places::witnessed(&scopes, &scope_witnesses);
        places::Tightness::new("lifecycle_scope")
            .places(&scopes, &scope_witnesses, |place| match place {
                ScopePlace::Initialization => Factor::Measured,
            })
            .joint(
                &scopes,
                "scope",
                places::EVERY,
                "a scope's whole lifecycle: initialized field by field, then shut down empty",
            )
            .finish();
        places::check(&operations);
        places::witnessed(&operations, &operation_witnesses);
        let work = "undecided texts whose marks run unbroken: the parse's normalization, the \
                    dominant work term, at every merge level; every byte copied once and every \
                    text constructed in place; prepared, each text normalized again";
        let storage = "empty strings, a node and an element per input byte: the parse's arena \
                       at its most beside the copied input, then the value's elements; \
                       prepared, a head per element in the plan's arena";
        let mut operations_tightness = places::Tightness::new("lifecycle_operations");
        operations_tightness.places(&operations, &operation_witnesses, |place| match place {
            OperationPlace::Record
            | OperationPlace::Initialization
            | OperationPlace::Task
            | OperationPlace::Release => Factor::Measured,
        });
        // Each chain against the public bounds a caller composes, not the
        // sum of its operations' terms.
        for (chain, dimensions, public) in &chains {
            let derivation = if *dimensions == places::WORK {
                work
            } else {
                storage
            };
            operations_tightness.joint_bound(
                &operations,
                chain,
                "public",
                *public,
                dimensions,
                derivation,
            );
        }
        // A copy's and a borrow's costs are affine in the input's bytes and
        // constant, so any input published drives every dimension at once.
        operations_tightness
            .joint(
                &operations,
                "copy",
                places::EVERY,
                "a copy published: every byte copied once in quanta, its buffer and record \
                 held",
            )
            .joint(
                &operations,
                "borrow",
                places::EVERY,
                "a borrow published: its record initialized field by field and held",
            );
        operations_tightness.finish();
        // A copy's own places cover only its scope reference; its bytes are
        // its binding's, covered at its operation's task above.
        places::check_terms(&copies);
        places::witnessed(&copies, &copy_witnesses);
        let input = |place| match place {
            InputPlace::Settle | InputPlace::Borrow => Factor::Measured,
        };
        places::Tightness::new("lifecycle_copy")
            .places(&copies, &copy_witnesses, input)
            .finish();
        places::check_within(&borrows, OperationPlace::Task);
        places::witnessed(&borrows, &borrow_witnesses);
        places::Tightness::new("lifecycle_borrow")
            .places(&borrows, &borrow_witnesses, input)
            .finish();
        places::check_within(&parses, OperationPlace::Task);
        places::witnessed(&parses, &parse_witnesses);
        places::Tightness::new("lifecycle_parse")
            .places(&parses, &parse_witnesses, |place| match place {
                ParsePlace::Parse => Factor::Nested("decode::cursor::attribution"),
                ParsePlace::Transfer
                | ParsePlace::Publish
                | ParsePlace::Cleanup
                | ParsePlace::Input => Factor::Measured,
            })
            .finish();
        places::check_within(&constructs, OperationPlace::Task);
        places::witnessed(&constructs, &construct_witnesses);
        places::Tightness::new("lifecycle_construct")
            .places(&constructs, &construct_witnesses, |place| match place {
                ConstructPlace::Build
                | ConstructPlace::Detach
                | ConstructPlace::Publish
                | ConstructPlace::Cleanup
                | ConstructPlace::Document
                | ConstructPlace::Input => Factor::Measured,
            })
            .finish();
        for scope in kept {
            scope.release();
        }
    }
}
