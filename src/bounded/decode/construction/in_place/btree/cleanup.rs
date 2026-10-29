use super::*;

/// The calls [`reclaim`] still takes from `state`: no metadata, or only a
/// prefix of it, one. Otherwise, by phase, the parts still ahead: entering
/// cleanup, one; the entries, the entry arena settled, each record's value,
/// key and removal, less what the newest record's phase has already
/// reclaimed (its value from `ReclaimKey`, its key too from
/// `ReclaimEntry`), then one to leave them; the nodes, the pending node's
/// release, the node arena settled, one per node, then one to leave them;
/// the arenas not yet released, each to its release, then the metadata's.
/// Every successful call lowers it: nothing reclaimed is counted again.
pub(super) fn remaining<K: Reclaim<A>, V: Reclaim<A>, A: Allocator>(
    state: &mut State<K, V, A>,
) -> u64 {
    if state.initialized < INIT {
        return 1;
    }
    let Some(block) = state.meta.as_mut() else {
        return 1;
    };
    // SAFETY: the whole metadata prefix is initialized, and the state's
    // exclusive custody reaches the block.
    let m = unsafe { block.get().assume_init_mut() };
    // An arena already released is stepped no further ([`reclaim`] skips
    // it), so it owes nothing.
    let arenas = m
        .entries
        .unreleased_remaining()
        .saturating_add(m.nodes.unreleased_remaining())
        .saturating_add(m.order[1].unreleased_remaining())
        .saturating_add(m.order[0].unreleased_remaining())
        .saturating_add(1);
    let nodes = u64::from(m.pending_node.is_some())
        .saturating_add(m.nodes.settle_remaining())
        .saturating_add(m.nodes.len() as u64)
        .saturating_add(1);
    let mut entries = m.entries.settle_remaining().saturating_add(1);
    m.entries.for_each_mut(|entry| {
        // SAFETY: each record holds its key's and value's stable places in
        // the node it was built in, paired with their own states.
        let (value, key) = unsafe {
            (
                V::remaining(Slot::new(entry.value.observe(), &mut *entry.value_state)),
                K::remaining(Slot::new(entry.key.observe(), &mut *entry.key_state)),
            )
        };
        entries = entries
            .saturating_add(value)
            .saturating_add(key)
            .saturating_add(1);
    });
    // The newest record is the one cleanup is working on: its value is
    // reclaimed once its key's turn comes, and its key once its removal's.
    let phase = m.phase;
    if let Some(entry) = m.entries.last_mut() {
        // SAFETY: as above, the record's own places and states.
        let reclaimed = unsafe {
            match phase {
                Phase::ReclaimKey => {
                    V::remaining(Slot::new(entry.value.observe(), &mut *entry.value_state))
                }
                Phase::ReclaimEntry => {
                    V::remaining(Slot::new(entry.value.observe(), &mut *entry.value_state))
                        .saturating_add(K::remaining(Slot::new(
                            entry.key.observe(),
                            &mut *entry.key_state,
                        )))
                }
                _ => 0,
            }
        };
        entries = entries.saturating_sub(reclaimed);
    }
    match m.phase {
        Phase::ReleaseArenas => arenas,
        Phase::ReleaseNodes => nodes.saturating_add(arenas),
        Phase::ReclaimValue | Phase::ReclaimKey | Phase::ReclaimEntry => {
            entries.saturating_add(nodes).saturating_add(arenas)
        }
        _ => entries
            .saturating_add(nodes)
            .saturating_add(arenas)
            .saturating_add(1),
    }
}

/// One unit of the tree's cleanup in `slot`, from any state: with nothing
/// held, one admitted unit reporting `Done`.
pub(super) fn reclaim<K: Reclaim<A>, V: Reclaim<A>, A: Allocator>(
    mut slot: Slot<'_, BTreeMap<K, V>, State<K, V, A>>,
    a: &mut A,
) -> BoundedResult<Reclaimed, A> {
    let (place, state) = slot.parts();
    if state.meta.is_none() {
        STEP.admit(a)?;
        return Ok(Reclaimed::Done);
    }
    if state.initialized < INIT {
        // SAFETY: the initialized metadata prefix owns no resources. The
        // outer MaybeUninit is always initialized and has no destructor.
        unsafe {
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
                V::reclaim_step(value, a)?
            } else {
                let key = unsafe { Slot::new(entry.key, &mut *entry.key_state) };
                K::reclaim_step(key, a)?
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
                // SAFETY: no resources remain. The map was never initialized
                // or was detached, so its destructor has nothing to release.
                unsafe {
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
            meta(state)?.phase = Phase::ReclaimValue;
        }
    }
    Ok(Reclaimed::Progress)
}
