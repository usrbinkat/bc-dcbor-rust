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
/// None when a quantity does not fit in `u64`.
const fn arena<T, P>() -> Option<ConstructionCost> {
    let elements = cost!(unit(size_of::<T>()).checked_mul(4));
    let writes = cost!(unit(64).checked_mul(4));
    let releases = cost!(stable::release_cost::<P>().checked_mul(2));
    let each = cost!(elements.checked_add(cost!(writes.checked_add(releases))));
    let staging = Storage::<T, P>::STAGING.block();
    let slots = cost!(size_of::<T>().checked_mul(4));
    let storage = held(cost!(slots.checked_add(staging)));
    let fixed = cost!(cost!(each.checked_mul(2)).checked_add(cost!(storage.checked_mul(2))));
    ConstructionCost::fixed(fixed).checked_add(cost!(ConstructionCost::checked_per_byte(cost!(
        each.checked_add(storage)
    ))))
}

/// The cost of a tree of keys `K` and values `V` under allocator `A`. None
/// when a quantity does not fit in `u64`.
pub(super) const fn cost<K: InPlace<A>, V: InPlace<A>, A: Allocator>() -> Option<ConstructionCost> {
    // A pair consumes at least one input byte. There are at most as many
    // nodes as pairs; no node or constructed child is ever reallocated.
    let node = InPlaceNode::<K, V>::layout(false).size();
    let metadata = contract::<K, V, A>().block();
    let initialized = cost!(unit(64).checked_mul(INIT as u64 + 8));
    let fixed = cost!(held(metadata).checked_add(cost!(
        initialized.checked_add(stable::release_cost::<A::Permit>())
    )));
    // At most usize::BITS merge levels. Each key pays for at most two scans
    // and two terminal comparisons per level. Selection, index writes and
    // run transitions fit within eight bounded units per input byte per level.
    let sorting = cost!(unit(64).checked_mul(8 * usize::BITS as u64));
    // Shape, node acquisition, linking, child records, sealing and cleanup:
    // a fixed number of bounded units per node or pair.
    let structure = cost!(cost!(unit(64).checked_mul(24)).checked_add(cost!(
        held(node).checked_add(stable::release_cost::<A::Permit>())
    )));
    let own = cost!(ConstructionCost::fixed(fixed).checked_add(cost!(
        ConstructionCost::checked_per_byte(cost!(sorting.checked_add(structure)))
    )));
    let arenas = cost!(
        cost!(cost!(arena::<usize, A::Permit>()).checked_add(cost!(arena::<usize, A::Permit>())))
            .checked_add(cost!(
                cost!(arena::<Node<K, V, A::Permit>, A::Permit>()).checked_add(cost!(arena::<
                    Entry<K, V, A>,
                    A::Permit,
                >(
                )))
            ))
    );
    let children =
        cost!(cost!(K::COST.checked_children()).checked_add(cost!(V::COST.checked_children())));
    cost!(own.checked_add(arenas)).checked_add(children)
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
