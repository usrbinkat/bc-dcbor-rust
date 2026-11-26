use super::*;
use crate::bounded::boundary::{Bound, Predicate, boundary};
use crate::bounded::decode::construction::reclamation::{Cleanup, PeekSlot, Slot};
use crate::bounded::decode::initialization::field;
use crate::bounded::{CustodySink, PermitsObserved};
use core::ptr::addr_of_mut;

/// What a record holds of its document arena, the arena's custody: the
/// ownership parts transferred into it from the parser, in order (the node
/// storage's parts, [`Storage::TRANSFER_PARTS`], then the owner its
/// acquisitions were bound under), and the parts released, each counted. A
/// slot pairs the arena's place with it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ArenaParts {
    pub(crate) transferred: usize,
    pub(crate) released: usize,
}

/// The node storage's parts a transfer writes into the arena, before its
/// owner.
const STORAGE_PARTS: usize = Storage::<Entry, (), ()>::TRANSFER_PARTS;

impl<I, P, O: Origin> ParserContinuation<I, P, O> {
    /// Transfer the validated arena into `arena`, its retained destination
    /// paired with its parts, one ownership field per admitted unit: the
    /// node storage's parts, then the identity of the owner the parser's
    /// arena stored, which the published arena carries for its life
    /// (observational identity, never settlement authority). Refused unless
    /// the parser is ready to publish, once the arena's release has begun,
    /// and past the last part. True once every part is transferred.
    pub(crate) fn publish_arena_step<A: Allocator<Permit = P, Origin = O>>(
        &mut self,
        mut arena: Slot<'_, DocumentArena<P>, ArenaParts>,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        if !self.ready_to_publish()
            || Bound::new(Predicate::Prefix, 0).exceeded(a, arena.custody().released)
        {
            return Err(BoundedError::PlanMismatch);
        }
        if Bound::new(Predicate::Prefix, STORAGE_PARTS).reached(a, arena.custody().transferred) {
            // Read before the write: the parser's arena keeps its stored
            // owner after its storage moved out.
            let owner = self.entries.owner_id();
            let (place, parts) = arena.parts();
            if Bound::new(Predicate::Prefix, STORAGE_PARTS + 1).reached(a, parts.transferred) {
                return Err(BoundedError::PlanMismatch);
            }
            let raw = place.as_ptr(parts);
            // SAFETY: the slot's place is valid, aligned and writable for
            // the arena; the owner field is reached by field syntax, forming
            // no reference to the whole, and is unwritten: its part is next.
            unsafe { field(addr_of_mut!((*raw).owner), || owner, a)? };
            parts.transferred += 1;
            self.phase = Phase::Finished;
            return Ok(true);
        }
        // SAFETY: the arena's node storage is projected by field syntax, and
        // the parts transferred below the storage's are exactly its units
        // written.
        let entries = unsafe {
            arena.child(
                |arena| addr_of_mut!((*arena).entries),
                |parts| &mut parts.transferred,
            )
        };
        self.entries.transfer_step(entries, a)?;
        Ok(false)
    }

    pub(crate) fn ready_to_publish(&self) -> bool {
        self.phase == Phase::Publish
    }

    /// The identity of the owner the parser's arena stored, under which its
    /// storage's acquisitions were bound, read from that retained custody
    /// ([`Storage::owner_id`]); `None` before its first acquisition. What a
    /// transferred arena's permit is grouped under until the arena's own
    /// owner field is written ([`DocumentArena::observe_prefix`]).
    pub(crate) fn arena_owner(&self) -> Option<Identity> {
        self.entries.owner_id()
    }
}

impl<P> DocumentArena<P> {
    /// Releasing the arena's items: one value and the vector's bytes.
    const ITEMS: Unit<Caller> = Unit::of::<Vec<Entry>>(Caller);

    /// Releasing the arena's permit: one value and the slot's bytes.
    const PERMIT: Unit<Caller> = Unit::of::<Option<P>>(Caller);

    /// Writing the arena's owner, the transfer's last part: the unit the
    /// field write admits for its type.
    const OWNER: Unit<Caller> = Unit::written::<Option<Identity>>(Caller);

    /// The work of transferring the arena from its parser
    /// ([`ParserContinuation::publish_arena_step`]): its storage's transfer,
    /// then its owner's write.
    pub(crate) fn transfer_work<R>() -> Result<WriteWork, BoundedError<R>> {
        // The transfer's units are the arena fields' sizes, which no origin
        // changes: the arena's own pending custody is not transferred.
        WriteWork::checked_sequence(&[
            Storage::<Entry, P, ()>::transfer_work()?,
            Self::OWNER.times(1)?,
        ])
        .ok_or(BoundedError::Overflow)
    }

    /// The work of releasing every part ([`Self::release_parts_step`]),
    /// transferred or not: one unit per part that owns anything. The owner
    /// is a plain identity: nothing to release.
    pub(crate) fn release_work<R>() -> Result<WriteWork, BoundedError<R>> {
        WriteWork::checked_sequence(&[Self::ITEMS.times(1)?, Self::PERMIT.times(1)?])
            .ok_or(BoundedError::Overflow)
    }

    /// Release one transferred part of the arena in `arena`, its place
    /// paired with its parts, per admitted unit: the node vector if it was
    /// transferred, then the permit if it was. The owner, a plain identity,
    /// needs no release. The caller holds the arena past every document view
    /// of it. A cleanup step, under the cleanup capability: every unit is
    /// admitted as cleanup, and no new allocation can be requested.
    pub(crate) fn release_parts_step<A: Allocator<Permit = P>>(
        mut arena: Slot<'_, Self, ArenaParts>,
        cleanup: &mut Cleanup<'_, A>,
    ) -> BoundedResult<bool, A> {
        let (place, parts) = arena.parts();
        let ArenaParts {
            transferred,
            released,
        } = *parts;
        let raw = place.as_ptr(parts);
        match released {
            0 => {
                Self::ITEMS.admit(cleanup)?;
                if Bound::new(Predicate::Prefix, 1).reached(cleanup, transferred) {
                    // SAFETY: the parts pair with the arena's place, and a
                    // first part transferred is the node vector written,
                    // reached by field syntax and dropped once: the parts
                    // released advance past it below.
                    unsafe { core::ptr::drop_in_place(addr_of_mut!((*raw).entries.items)) };
                }
            }
            1 => {
                Self::PERMIT.admit(cleanup)?;
                if boundary!(cleanup, Predicate::Prefix, transferred, STORAGE_PARTS).is_ge() {
                    // SAFETY: as above, the storage's last part transferred
                    // is the permit written.
                    unsafe { core::ptr::drop_in_place(addr_of_mut!((*raw).entries.permit)) };
                }
            }
            2 => return Ok(true),
            _ => return Err(BoundedError::PlanMismatch),
        }
        parts.released += 1;
        Ok(parts.released == 2)
    }

    /// The permit the arena in `arena` holds, by its parts transferred and
    /// released, reported as its own group ([`CustodySink`]): the one
    /// traversal of an arena a record holds, every prefix included. Before
    /// the storage's last part the permit is still the parser's, which
    /// reports it; from that part until the owner field is written, under
    /// `parser_owner`, the owner the parser's arena stored
    /// ([`ParserContinuation::arena_owner`]); once written, under the arena's
    /// own owner field; once released, nothing. Only the fields the parts
    /// say are initialized and unreleased are read, each by projection: at
    /// one part released the vector is destroyed and the permit is reached
    /// without forming a reference to the arena or its vector. Never
    /// contended.
    pub(crate) fn observe_prefix(
        mut arena: PeekSlot<'_, Self, ArenaParts>,
        parser_owner: Option<Identity>,
        sink: &mut dyn CustodySink<P>,
    ) -> PermitsObserved {
        let (place, parts) = arena.parts();
        let ArenaParts {
            transferred,
            released,
        } = *parts;
        if transferred < STORAGE_PARTS || released >= 2 {
            return PermitsObserved::Complete;
        }
        let owner = if transferred > STORAGE_PARTS {
            // SAFETY: the parts record the owner field written, by
            // projection, and it is read shared under the parts' borrow.
            unsafe {
                *place
                    .project(|arena| addr_of_mut!((*arena).owner))
                    .get(&*parts)
            }
        } else {
            parser_owner
        };
        // SAFETY: the parts record the storage's last part, the permit,
        // written and not yet released; it is reached by field projection,
        // forming no reference to the arena or its vector.
        let permit = unsafe {
            place
                .project(|arena| addr_of_mut!((*arena).entries.permit))
                .get(&*parts)
        };
        if let Some(permit) = permit {
            sink.begin(owner);
            sink.permit(permit, None);
            sink.end();
        }
        PermitsObserved::Complete
    }

    /// The most calls [`Self::release_parts_step`] still takes after
    /// `released` parts, the one returning true included: one per part not
    /// yet released, or one once both are.
    pub(crate) fn release_remaining(released: usize) -> u64 {
        match released {
            0 => 2,
            _ => 1,
        }
    }
}
