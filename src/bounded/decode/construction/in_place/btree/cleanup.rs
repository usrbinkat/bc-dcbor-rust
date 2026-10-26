use super::*;

/// The calls [`reclaim`] still takes from `state`: no metadata, or only a
/// prefix of it, one. Otherwise, by phase, the parts still ahead: entering
/// cleanup, one; the entries, the entry arena settled, each record's value,
/// key and removal, then one to leave them; the nodes, the pending node's
/// release, the node arena settled, one per node, then one to leave them;
/// the arenas, each to its release, then the metadata's.
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
    let arenas = m
        .entries
        .reclaim_remaining()
        .saturating_add(m.nodes.reclaim_remaining())
        .saturating_add(m.order[1].reclaim_remaining())
        .saturating_add(m.order[0].reclaim_remaining())
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
                V::remaining(entry.value, &mut *entry.value_state),
                K::remaining(entry.key, &mut *entry.key_state),
            )
        };
        entries = entries
            .saturating_add(value)
            .saturating_add(key)
            .saturating_add(1);
    });
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

pub(super) unsafe fn reclaim<K: Reclaim<A>, V: Reclaim<A>, A: Allocator>(
    place: NonNull<MaybeUninit<BTreeMap<K, V>>>,
    state: &mut State<K, V, A>,
    a: &mut A,
) -> BoundedResult<Reclaimed, A> {
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
    // SAFETY: the whole metadata prefix is initialized.
    let m = unsafe {
        state
            .meta
            .as_mut()
            .ok_or(BoundedError::PlanMismatch)?
            .get()
            .assume_init_mut()
    };
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
            // SAFETY: the map was detached if published. Each record retains
            // exact child state, including an unstarted value's INITIAL state.
            let done = unsafe {
                if m.phase == Phase::ReclaimValue {
                    V::reclaim_step(entry.value, &mut entry.value_state, a)?
                } else {
                    K::reclaim_step(entry.key, &mut entry.key_state, a)?
                }
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
                // all borrows before entering reclamation.
                unsafe {
                    (*place.as_ptr().cast::<BTreeMap<K, V>>()).detach_in_place();
                }
            }
            m.phase = Phase::ReclaimValue;
        }
    }
    Ok(Reclaimed::Progress)
}
