use super::*;

pub(super) const fn allocate_write<K, V, P>() -> Unit<Caller> {
    Unit::new(
        Caller,
        1,
        crate::bounded::write_extent(
            InPlaceNode::<K, V>::INITIALIZE_BYTES
                + size_of::<Option<InPlaceNode<K, V>>>()
                + size_of::<Option<P>>(),
        ),
    )
}

pub(super) const fn link<K, V>() -> Unit<Caller> {
    Unit::new(
        Caller,
        1,
        crate::bounded::write_extent(InPlaceNode::<K, V>::LINK_BYTES),
    )
}

/// One arena's affine envelope. At most n+1 growths, fewer than 2n+4
/// relocated elements and 4n+8 element slots requested, plus one staging
/// block per growth. Each growth writes four units and prepays two releases.
const fn arena<T, P>() -> ConstructionCost {
    let each = plus(
        times(unit(size_of::<T>()), 4),
        plus(times(unit(64), 4), times(stable::release_cost::<P>(), 2)),
    );
    let staging = size_of::<stable::Held<crate::bounded::Owned<T, P>, P>>();
    let storage = held(4 * size_of::<T>() + staging);
    ConstructionCost::fixed(plus(times(each, 2), times(storage, 2)))
        .plus(ConstructionCost::per_byte(plus(each, storage)))
}

pub(super) const fn cost<K: InPlace<A>, V: InPlace<A>, A: Allocator>() -> ConstructionCost {
    // A pair consumes at least one input byte. There are at most as many
    // nodes as pairs; no node or constructed child is ever reallocated.
    let node = InPlaceNode::<K, V>::layout(false).size();
    let metadata = size_of::<stable::Held<MaybeUninit<Meta<K, V, A>>, A::Permit>>();
    let fixed = plus(
        held(metadata),
        plus(
            times(unit(64), INIT as u64 + 8),
            stable::release_cost::<A::Permit>(),
        ),
    );
    // At most usize::BITS merge levels. Each key pays for at most two scans
    // and two terminal comparisons per level. Selection, index writes and
    // run transitions fit within eight bounded units per input byte per level.
    let sorting = times(unit(64), 8 * usize::BITS as u64);
    // Shape, node acquisition, linking, child records, sealing and cleanup:
    // a fixed number of bounded units per node or pair.
    let structure = plus(
        times(unit(64), 24),
        plus(held(node), stable::release_cost::<A::Permit>()),
    );
    ConstructionCost::fixed(fixed)
        .plus(ConstructionCost::per_byte(plus(sorting, structure)))
        .plus(arena::<usize, A::Permit>())
        .plus(arena::<usize, A::Permit>())
        .plus(arena::<Node<K, V, A::Permit>, A::Permit>())
        .plus(arena::<Entry<K, V, A>, A::Permit>())
        .plus(K::COST.children())
        .plus(V::COST.children())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The units a node's allocation and each link admit, evaluated at run
    /// time (the engine evaluates both only in constants), against what each
    /// step writes. The allocation writes the new node's parent pointer and
    /// length (the fork's `try_allocate`), then the pending node handle and
    /// the pending permit; a link writes one edge, the child's parent pointer
    /// and its parent index.
    #[test]
    fn a_nodes_allocation_and_link_admit_exactly_the_fields_they_write() {
        let pointer = size_of::<usize>();
        let length = size_of::<u16>();
        let allocate = allocate_write::<u64, u64, u64>();
        assert_eq!(allocate.values(), 1);
        assert_eq!(
            allocate.bytes(),
            (pointer + length + pointer + size_of::<Option<u64>>()) as u64
        );
        let link = link::<u64, u64>();
        assert_eq!(link.values(), 1);
        assert_eq!(link.bytes(), (pointer + pointer + length) as u64);
    }
}
