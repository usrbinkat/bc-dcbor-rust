use super::*;

/// The calls [`reclaim`] still takes from `state`: no metadata, or only a
/// prefix of it, one. Otherwise, by phase, the parts still ahead, and only
/// those: entering cleanup, one; the entries, the entry arena settled, each
/// record's value, key and removal not yet reclaimed (the newest record's
/// value is reclaimed from `ReclaimKey` on, its key too from
/// `ReclaimEntry`), then one to leave them; the nodes, the pending node's
/// release, the node arena settled, one per node, then one to leave them;
/// the arenas not yet released, each to its release, then the metadata's.
/// Every successful call lowers it: nothing reclaimed is counted again, and
/// nothing a phase no longer owes is computed, so no count of finished work
/// can refuse one that fits. `None` when the count does not fit in `u64`,
/// never saturated.
pub(super) fn remaining<K: Reclaim<A>, V: Reclaim<A>, A: Allocator>(
    state: &mut State<K, V, A>,
) -> Option<u64> {
    if state.initialized < INIT {
        return Some(1);
    }
    let Some(block) = state.meta.as_mut() else {
        return Some(1);
    };
    // SAFETY: the whole metadata prefix is initialized, and the state's
    // exclusive custody reaches the block.
    let m = unsafe { block.get().assume_init_mut() };
    let phase = m.phase;
    // An arena already released is stepped no further ([`reclaim`] skips
    // it), so it owes nothing. Every phase owes the arenas.
    let arenas = m
        .entries
        .unreleased_remaining()?
        .checked_add(m.nodes.unreleased_remaining()?)?
        .checked_add(m.order[1].unreleased_remaining()?)?
        .checked_add(m.order[0].unreleased_remaining()?)?
        .checked_add(1)?;
    if phase == Phase::ReleaseArenas {
        return Some(arenas);
    }
    let nodes = u64::from(m.pending_node.is_some())
        .checked_add(m.nodes.settle_remaining()?)?
        .checked_add(u64::try_from(m.nodes.len()).ok()?)?
        .checked_add(1)?;
    if phase == Phase::ReleaseNodes {
        return nodes.checked_add(arenas);
    }
    // The newest record, the one cleanup is working on, by identity: the
    // arena's newest element in every state, relocation included
    // (`Storage::last_mut`). Which of its parts are already reclaimed is
    // read from the phase, and those are never counted.
    let newest = m
        .entries
        .last_mut()
        .map(|entry| core::ptr::from_mut(entry).cast_const());
    let mut owed = Owed::new(m.entries.settle_remaining()?);
    m.entries.for_each_mut(|entry| {
        let current = newest == Some(core::ptr::from_mut(entry).cast_const());
        let (value_done, key_done) = match phase {
            Phase::ReclaimKey if current => (true, false),
            Phase::ReclaimEntry if current => (true, true),
            _ => (false, false),
        };
        let value = if value_done {
            Some(0)
        } else {
            // SAFETY: each record holds its key's and value's stable places
            // in the node it was built in, paired with their own states.
            remaining_part::<V, A>(unsafe {
                Slot::new(entry.value.observe(), &mut *entry.value_state)
            })
        };
        let key = if key_done {
            Some(0)
        } else {
            // SAFETY: as for the value.
            remaining_part::<K, A>(unsafe { Slot::new(entry.key.observe(), &mut *entry.key_state) })
        };
        owed.record(value, key);
    });
    let entries = owed.total()?;
    match phase {
        Phase::ReclaimValue | Phase::ReclaimKey | Phase::ReclaimEntry => {
            entries.checked_add(nodes)?.checked_add(arenas)
        }
        _ => entries
            .checked_add(nodes)?
            .checked_add(arenas)?
            .checked_add(1),
    }
}

/// What the entries still owe, summed record by record: the entry arena's
/// settlement and the one unit leaving them, then each record's
/// outstanding value and key counts and its removal. Only outstanding work
/// is ever added, so a count that fits is never refused for work finished.
struct Owed(Option<u64>);

impl Owed {
    /// The arena's settlement, `settle` units, and the unit leaving the
    /// entries.
    fn new(settle: u64) -> Self {
        Self(settle.checked_add(1))
    }

    /// One record: its value's and key's outstanding counts (zero for a
    /// part already reclaimed, never its count) and its removal.
    fn record(&mut self, value: Option<u64>, key: Option<u64>) {
        self.0 = self
            .0
            .and_then(|owed| owed.checked_add(value?)?.checked_add(key?)?.checked_add(1));
    }

    /// The sum, `None` when it does not fit in `u64`.
    fn total(self) -> Option<u64> {
        self.0
    }
}

/// One unit of the tree's cleanup in `slot`, from any state: with nothing
/// held, one admitted unit reporting `Done`. Runs under `a`, the cleanup
/// capability ([`Cleanup`]): an arena still relocating is settled by its
/// relocation, which acquires nothing (`Storage::settle_step`).
pub(super) fn reclaim<K: Reclaim<A>, V: Reclaim<A>, A: Allocator>(
    mut slot: Slot<'_, BTreeMap<K, V>, State<K, V, A>>,
    a: &mut Cleanup<'_, A>,
) -> BoundedResult<Reclaimed, A> {
    let (place, state) = slot.parts();
    if state.meta.is_none() {
        STEP.admit(a)?;
        // The block's acquisition, if pending, had its credit settled at the
        // operation's cleanup entry: the ticket is forgotten.
        state.ticket = None;
        return Ok(Reclaimed::Done);
    }
    if Bound::new(Predicate::Prefix, INIT).below(a, state.initialized) {
        // The initialized metadata prefix owns no allocation and no
        // admitted credit, but each arena written holds its own owner
        // capability: those are dropped in place first, then the block is
        // freed. The outer MaybeUninit is always initialized and has no
        // destructor.
        let raw = state
            .meta
            .as_mut()
            .ok_or(BoundedError::PlanMismatch)?
            .get()
            .as_mut_ptr();
        // SAFETY: the state's prefix records which units are written; none
        // holds an allocation or admitted credit, and the block is freed
        // below, so nothing reads them again.
        unsafe {
            drop_prefix_arenas(raw, state.initialized);
            stable::uninstall(&mut state.meta);
        }
        state.initialized = 0;
        return Ok(Reclaimed::Done);
    }
    let m = meta(state)?;
    match m.phase {
        Phase::ReclaimValue | Phase::ReclaimKey => {
            let Some(entries) = m.entries.settle_step(a)? else {
                return Ok(Reclaimed::Progress);
            };
            let Some(entry) = entries.as_mut_slice().last_mut() else {
                STEP.admit(a)?;
                m.phase = Phase::ReleaseNodes;
                return Ok(Reclaimed::Progress);
            };
            // SAFETY: the map was detached if published. Each record pairs
            // its key's and value's places with their exact states, including
            // an unstarted value's INITIAL state.
            let done = if m.phase == Phase::ReclaimValue {
                let value = unsafe { Slot::new(entry.value, &mut *entry.value_state) };
                reclaim_part::<V, A>(value, a)?
            } else {
                let key = unsafe { Slot::new(entry.key, &mut *entry.key_state) };
                reclaim_part::<K, A>(key, a)?
            };
            if done == Reclaimed::Done {
                if m.phase == Phase::ReclaimValue {
                    m.phase = Phase::ReclaimKey;
                } else {
                    m.phase = Phase::ReclaimEntry;
                }
            }
        }
        Phase::ReclaimEntry => {
            let Some(entries) = m.entries.settle_step(a)? else {
                return Ok(Reclaimed::Progress);
            };
            // Child completion may consume the entire turn. Retain it before
            // admitting the record move, so refusal cannot replay child cleanup.
            sized::<Entry<K, V, A>>().admit(a)?;
            entries.items.pop().ok_or(BoundedError::PlanMismatch)?;
            m.phase = Phase::ReclaimValue;
        }
        Phase::ReleaseNodes => {
            if let Some(node) = m.pending_node.take() {
                // SAFETY: this node has not entered the node arena and has
                // no initialized entries. Its allocation's release is prepaid.
                unsafe {
                    node.deallocate(m.pending_shape.height == 0);
                }
                drop(m.pending_permit.take());
                return Ok(Reclaimed::Progress);
            }
            let Some(nodes) = m.nodes.settle_step(a)? else {
                return Ok(Reclaimed::Progress);
            };
            if let Some(node) = nodes.items.pop() {
                // SAFETY: all entries are reclaimed. Deallocation follows no
                // edge. Reverse allocation order frees children first, and
                // each allocation is freed before its permit.
                unsafe {
                    node.raw.deallocate(node.shape.height == 0);
                }
                drop(node.permit);
            } else {
                STEP.admit(a)?;
                m.phase = Phase::ReleaseArenas;
            }
        }
        Phase::ReleaseArenas => {
            if !m.entries.is_released() {
                m.entries.reclaim_step(a)?;
            } else if !m.nodes.is_released() {
                m.nodes.reclaim_step(a)?;
            } else if !m.order[1].is_released() {
                m.order[1].reclaim_copy_step(a)?;
            } else if !m.order[0].is_released() {
                m.order[0].reclaim_copy_step(a)?;
            } else {
                // Every arena is released, but each still holds its pending
                // custody's owner, made by its first acquisition: a session
                // reference only the arena's own drop ends. The block runs
                // no destructor, so the arenas are dropped in place first,
                // as a prefix's are, then the block is freed.
                let raw = state
                    .meta
                    .as_mut()
                    .ok_or(BoundedError::PlanMismatch)?
                    .get()
                    .as_mut_ptr();
                // SAFETY: the whole metadata is initialized; every arena is
                // released (no element, allocation, reservation or staged
                // growth), its pending idle, so its drop frees nothing and
                // records nothing but its owner's end; the pending node and
                // permit were taken in `ReleaseNodes`, and the other fields
                // are plain values. The map was never initialized or was
                // detached, so its destructor has nothing to release, and
                // nothing reads the block after it is freed.
                unsafe {
                    drop_prefix_arenas(raw, state.initialized);
                    stable::uninstall(&mut state.meta);
                }
                state.initialized = 0;
                return Ok(Reclaimed::Done);
            }
        }
        _ => {
            sized::<BTreeMap<K, V>>().admit(a)?;
            if m.phase == Phase::Complete {
                // SAFETY: only Complete initialized the map; its caller ended
                // all borrows before entering reclamation. The borrow covers
                // the map's own bytes, in which no place lies: every entry's
                // places are rooted in node allocations.
                unsafe {
                    place.with_mut(state, |map| map.detach_in_place());
                }
            }
            let m = meta(state)?;
            m.phase = Phase::ReclaimValue;
            // Every arena's cleanup entered in this admitted unit, before
            // any unit of its own: each growth's admissions settled into
            // their families by this cleanup's performer and a staging
            // growth made idle (`Storage::enter_held_cleanup`). Whether an
            // arena's acquisition was under way is pending custody, which a
            // refused build step may leave admitted and the tree's progress
            // does not carry; once entered, `ReleaseArenas` steps exactly the
            // arenas whose position holds something, whatever it was.
            let by = a.performer();
            m.entries.enter_held_cleanup(by);
            m.nodes.enter_held_cleanup(by);
            m.order[0].enter_held_cleanup(by);
            m.order[1].enter_held_cleanup(by);
            // A node's acquisition pending (`AllocateRelease`, `Allocate`)
            // had its credit settled at the operation's cleanup entry: the
            // ticket is forgotten, and no phase of cleanup acquires.
            state.ticket = None;
        }
    }
    Ok(Reclaimed::Progress)
}

#[cfg(test)]
mod tests {
    use super::Owed;
    use super::{
        BTreeMap, Cleanup, INIT, MaybeUninit, Pending, Place, Reclaim, Reclaimed, Slot, State,
        initialize, reclaim, remaining,
    };
    use crate::bounded::{Budget, Capacity, Effect, Event, Identity, Limits, Performer, Session};
    use core::ptr::NonNull;

    /// S5: the metadata block installed, then every prefix of its units
    /// written: none; each arena's own units, a prefix ending inside each
    /// arena among them; the plain fields; and the whole, the boundary where
    /// initialization completes. A partial prefix is reclaimed in one call
    /// (its arenas dropped by exactly the units written,
    /// `drop_prefix_arenas`, then the block freed); the whole, whose phase
    /// is still `Header`, through every cleanup phase within the count it
    /// declares (`remaining`). Either way the cleanup ends `Done`, the
    /// block's custody removed and the state `INITIAL` again, no storage
    /// live. Under a recorded policy, whose session then finishes complete:
    /// nothing the prefix wrote holds the session (each arena's owner is made
    /// only by its first acquisition, which no prefix reaches,
    /// `Storage::new`); the block's one acquisition is bound once; and the
    /// one permit released is the one its grant reserved, by its identity,
    /// released once, by its drop. A prefix's cleanup dropping an arena's
    /// field beyond what was written reads uninitialized memory, which Miri
    /// refuses.
    #[test]
    fn every_metadata_prefix_is_reclaimed_and_releases_its_block() {
        type Tree = BTreeMap<u64, u64>;
        for prefix in 0..=INIT {
            let session = Session::new(Capacity::DEFAULT);
            let mut a = Limits::recorded_unlimited(&session);
            let mut pending = Pending::new(a.owner().expect("the custody's owner is minted"));
            let mut state: State<u64, u64, Limits> = <Tree as Reclaim<Limits>>::INITIAL;
            assert_eq!(
                initialize(&mut state, &mut pending, &mut a),
                Ok(false),
                "{prefix}: the block installed"
            );
            assert!(pending.is_idle(), "{prefix}: the block's acquisition ended");
            assert_ne!(a.live_bytes(), 0, "{prefix}: the block's permit is held");
            for unit in 0..prefix {
                assert_eq!(
                    initialize(&mut state, &mut pending, &mut a),
                    Ok(unit + 1 == INIT),
                    "{prefix}: unit {unit}"
                );
            }
            assert_eq!(state.initialized, prefix);
            let declared = remaining(&mut state).expect("a fixture's cleanup count fits in u64");
            if prefix < INIT {
                assert_eq!(declared, 1, "{prefix}: a partial prefix declares one call");
            }
            let mut destination = MaybeUninit::<Tree>::uninit();
            let mut calls = 0u64;
            loop {
                calls += 1;
                assert!(
                    calls <= declared,
                    "{prefix}: cleanup exceeded the {declared} calls it declared"
                );
                // SAFETY: the test owns the destination, never initialized
                // (no prefix publishes), and pairs it with the state
                // recording that; the slot is its only access for the call.
                let slot =
                    unsafe { Slot::new(Place::root(NonNull::from(&mut destination)), &mut state) };
                match reclaim(slot, &mut Cleanup::new(&mut a)) {
                    Ok(Reclaimed::Done) => break,
                    Ok(Reclaimed::Progress) => {}
                    other => panic!("{prefix}: cleanup step {calls}: {other:?}"),
                }
            }
            assert!(state.meta.is_none(), "{prefix}: the block is freed");
            assert!(state.ticket.is_none(), "{prefix}: no acquisition is kept");
            assert_eq!(state.initialized, 0, "{prefix}: INITIAL again");
            assert!(pending.is_idle(), "{prefix}: no credit is held");
            assert_eq!(
                a.live_bytes(),
                0,
                "{prefix}: the block's permit is released"
            );
            drop((pending, a));
            let observed = session.finish().unwrap_or_else(|incomplete| {
                panic!("{prefix}: incomplete evidence {incomplete:?}")
            });
            let bound: Vec<Identity> = observed
                .iter()
                .filter_map(|o| match o.event {
                    Event::Bound { acquisition, .. } => Some(acquisition),
                    _ => None,
                })
                .collect();
            assert_eq!(bound.len(), 1, "{prefix}: the block's one acquisition");
            let reserved: Vec<(Identity, Identity)> = observed
                .iter()
                .filter_map(|o| match o.event {
                    Event::Effect(Effect::Reserved {
                        permit,
                        acquisition,
                    }) => Some((permit, acquisition)),
                    _ => None,
                })
                .collect();
            assert_eq!(reserved.len(), 1, "{prefix}: one permit reserved");
            assert_eq!(
                reserved[0].1, bound[0],
                "{prefix}: the permit reserved for the block's acquisition"
            );
            let released: Vec<(Identity, Performer)> = observed
                .iter()
                .filter_map(|o| match o.event {
                    Event::Released(permit) => Some((permit, o.by)),
                    _ => None,
                })
                .collect();
            assert_eq!(
                released,
                [(reserved[0].0, Performer::None)],
                "{prefix}: the block's permit released by its identity, once, by its drop"
            );
        }
    }

    /// The form [`Owed`] replaced, kept as the planted control: every
    /// record's whole count summed, then the newest record's finished parts
    /// subtracted.
    fn summed_then_subtracted(settle: u64, records: &[(u64, u64)], finished: u64) -> Option<u64> {
        let mut total = settle.checked_add(1)?;
        for &(value, key) in records {
            total = total.checked_add(value)?.checked_add(key)?.checked_add(1)?;
        }
        total.checked_sub(finished)
    }

    /// A newest record in `ReclaimKey` whose finished value still reports a
    /// count that, added, overflows: what remains (its key, its removal,
    /// the settlement and the exit) fits, so the outstanding count is
    /// `Some`, where summing the finished value first refuses it.
    #[test]
    fn finished_work_never_refuses_an_outstanding_count_that_fits() {
        let finished_value = u64::MAX - 2;
        let key = 3;
        let mut owed = Owed::new(0);
        owed.record(Some(0), Some(key));
        assert_eq!(owed.total(), Some(1 + key + 1));
        assert_eq!(
            summed_then_subtracted(0, &[(finished_value, key)], finished_value),
            None,
            "the control: summing finished work first overflows"
        );
        let mut overflowing = Owed::new(u64::MAX);
        overflowing.record(Some(0), Some(0));
        assert_eq!(
            overflowing.total(),
            None,
            "outstanding work past u64 is refused"
        );
    }
}
