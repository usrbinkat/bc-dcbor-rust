//! Real BTreeMap construction through the fork's fixed-address nodes.
#![cfg(all(feature = "std", feature = "custom-std-collections"))]
#![forbid(unsafe_code)]
// The observed construction driver witnesses physical storage.
#[global_allocator]
static HEAP: support::heap::Heap = support::heap::Heap;
use dcbor::ByteString;
use dcbor::bounded::Limits;
use dcbor::bounded::decode::construction::in_place::{
    EntryObservation, TreeCustody, TreeObservation, TreePhase,
};
use dcbor::bounded::decode::storage::{StoragePosition, StorageStage};
use dcbor_test_support as support;
use std::collections::BTreeMap;
use std::rc::Rc;
use support::budgets::{Budgets, counts};
use support::legality::{Legality, initial, not_last, storage_build, storage_clean};

// `variant!()`: this build's record suffix ([`dcbor_record::declare_variant`]).
dcbor_record::declare_variant!(variant);

/// The occupancy witnesses through `limit` entries: both counts on each side
/// of every edge between occupancy classes
/// (`in_place::tree_occupancy`, emptiness and height), so every class is
/// witnessed by its least and, below the limit, its greatest count. Every
/// planning path a count selects is selected by its class; the plan's
/// arithmetic within a class is certified for every count separately
/// (`btree::plan_tests`), and the fork's node code branches on nothing but
/// leaf against internal.
fn occupancy_witnesses(limit: usize) -> Vec<usize> {
    use dcbor::bounded::decode::construction::in_place::tree_occupancy;
    let mut counts = vec![0];
    for count in 1..=limit {
        if tree_occupancy(count) != tree_occupancy(count - 1) {
            if counts.last() != Some(&(count - 1)) {
                counts.push(count - 1);
            }
            counts.push(count);
        }
    }
    counts
}

/// The occupancy witnesses derive from the occupancy classes exactly: empty,
/// then the edges of each height, where `raised` takes the tree a level up
/// (one leaf to 11 entries, two levels to 143, three to 1727).
#[test]
fn the_occupancy_witnesses_are_each_classes_edges() {
    assert_eq!(
        occupancy_witnesses(1728),
        [0, 1, 11, 12, 143, 144, 1727, 1728]
    );
    assert_eq!(occupancy_witnesses(144), [0, 1, 11, 12, 143, 144]);
}

/// The wide map: 256 entries whose values carry 80 bytes more each, which
/// alone reaches the two-byte count head and the four-byte bound head
/// ([`node_occupancy_boundaries_preserve_rust_order_and_canonical_encoding`]).
const WIDE: (usize, usize) = (256, 80);

/// The maps the occupancy run builds under `rigor`, each `(entries, value
/// padding)`. Fast runs cross the leaf/internal boundary: the witnesses
/// through the first tree with an internal node, the least count of height
/// one (a leaf has height zero): empty, one leaf, a full leaf, a root over
/// leaves, which reach every
/// branch of the fork's node code, which branches only on leaf against
/// internal. Exhaustive runs retain every height boundary through
/// `full_limit` ([`occupancy_witnesses`]) and the wide encoding witness; each
/// deeper witness repeats the node paths at a cost growing with its entries.
fn occupancy_maps(rigor: support::rigor::Rigor, full_limit: usize) -> Vec<(usize, usize)> {
    use dcbor::bounded::decode::construction::in_place::{TreeOccupancy, tree_occupancy};
    use support::rigor::Rigor;
    let limit = match rigor {
        Rigor::Fast => (1..=full_limit)
            .find(|&count| tree_occupancy(count) == TreeOccupancy::Height(1))
            .expect("the witness limit reaches a tree with an internal node"),
        Rigor::Exhaustive => full_limit,
    };
    occupancy_witnesses(limit)
        .into_iter()
        .map(|count| (count, 0))
        .chain((rigor == Rigor::Exhaustive).then_some(WIDE))
        .collect()
}

#[test]
fn expensive_occupancy_maps_require_exhaustive_rigor() {
    use support::rigor::Rigor;
    assert_eq!(
        occupancy_maps(Rigor::Fast, 1728),
        [(0, 0), (1, 0), (11, 0), (12, 0)]
    );
    assert_eq!(
        occupancy_maps(Rigor::Exhaustive, 1728),
        [
            (0, 0),
            (1, 0),
            (11, 0),
            (12, 0),
            (143, 0),
            (144, 0),
            (1727, 0),
            (1728, 0),
            (256, 80),
        ]
    );
    assert_eq!(
        occupancy_maps(Rigor::Exhaustive, 144),
        [
            (0, 0),
            (1, 0),
            (11, 0),
            (12, 0),
            (143, 0),
            (144, 0),
            (256, 80)
        ]
    );
}

/// Fast runs cover empty, singleton, full leaf and first internal node.
/// Exhaustive runs cover each occupancy witness ([`occupancy_witnesses`]): every class's
/// edges, through the fourth level's first count at full witness sizes and
/// the third's at minimal sizes, the reach map requiring the minimal run to
/// execute every region the full run does (`tests/reach-map.sh`); and a wide
/// map, 256 entries whose values carry 80 bytes more each. What only the
/// wide map reaches is head width, not a tree path: a count of at least 256
/// (a two-byte head) and an input of at least 21,846 bytes, whose parse bound
/// of three part bytes a byte (`text::PART_BYTES_PER_BYTE`) reaches 65,536 (a
/// four-byte head).
#[test]
fn node_occupancy_boundaries_preserve_rust_order_and_canonical_encoding() {
    let maps = occupancy_maps(support::rigor::rigor(), support::rigor::sized(1728, 144));
    let maps = maps.as_slice();
    let key = |count, padding| format!("round-trip/{count}/{padding}");
    let mut budgets = Budgets::new(
        "btree-occupancy",
        variant!(),
        maps.iter()
            .map(|&(count, padding)| key(count, padding))
            .collect(),
    );
    // Each map reported as it runs, with the time since the first: which
    // boundary's map dominates the interpreted run is measured, not assumed.
    let mut progress = support::rigor::Progress::new("node occupancy boundaries");
    progress.stage("maps", maps.len(), maps.len());
    for &(count, padding) in maps {
        progress.case(format!("{count} entries, values padded by {padding} bytes"));
        let key = key(count, padding);
        let report = occupancy_round_trip(count, padding, &mut budgets, &key);
        let turns = report.boundaries.len();
        eprintln!(
            "[node occupancy boundaries] {count} entries padded by {padding}: {} events, {} \
             permit records, {turns} turns, {:?}",
            report.observed.len(),
            counts(&report.observed).permits,
            report.phases,
        );
    }
    budgets.finish();
}

/// The same complete round-trip schedule for qualification and recording.
fn occupancy_round_trip(
    count: usize,
    padding: usize,
    budgets: &mut Budgets,
    key: &str,
) -> support::pipeline::Report {
    let expected: BTreeMap<String, String> = (0..count)
        .map(|n| {
            (
                format!("{n:x}"),
                format!("value-{n}{}", "x".repeat(padding)),
            )
        })
        .collect();
    let mut symbolic = dcbor::Map::new();
    for (key, value) in &expected {
        symbolic.insert(key.clone(), value.clone()).unwrap();
    }
    let wire = dcbor::CBOR::from(symbolic).to_cbor_data();
    if (count, padding) == WIDE {
        assert!(
            count >= 256 && wire.len() >= 21_846,
            "the wide map of {count} entries and {} bytes no longer reaches the two-byte \
                 count head and the four-byte bound head",
            wire.len()
        );
    }
    budgets.encode_checked(key, &wire, |value: &BTreeMap<String, String>| {
        assert_eq!(value, &expected, "{count} entries");
        for (key, wanted) in &expected {
            assert_eq!(value.get(key), Some(wanted));
        }
    })
}

/// A map's declared dispatch depth is one more than the deeper of its key's
/// and its value's, as `Reclaim::DISPATCH_DEPTH` requires of a binding that
/// delegates to children: with the key deeper than the value, the value
/// deeper than the key, and both alike, so every branch of the declaration
/// is taken. The children's depths are their own declarations.
#[test]
fn a_map_dispatches_one_deeper_than_its_deeper_child() {
    use dcbor::bounded::decode::construction::reclamation::Reclaim;
    fn depth<T: Reclaim<Limits>>() -> usize {
        T::DISPATCH_DEPTH
    }
    let (deep, shallow) = (depth::<Vec<Vec<u64>>>(), depth::<u64>());
    assert!(deep > shallow, "the nested vector dispatches deeper");
    assert_eq!(
        depth::<BTreeMap<Vec<Vec<u64>>, u64>>(),
        deep + 1,
        "the key deeper than the value"
    );
    assert_eq!(
        depth::<BTreeMap<u64, Vec<Vec<u64>>>>(),
        deep + 1,
        "the value deeper than the key"
    );
    assert_eq!(
        depth::<BTreeMap<u64, u64>>(),
        shallow + 1,
        "the key and value alike"
    );
}

#[test]
fn integer_keys_are_built_in_numeric_order() {
    let mut map = dcbor::Map::new();
    for n in [i64::MIN, -100i64, -2, -1, 0, 1, 24, 100, i64::MAX] {
        map.insert(n, n).unwrap();
    }
    let wire = dcbor::CBOR::from(map).to_cbor_data();
    support::pipeline::round_trip(&wire, |value: &BTreeMap<i64, i64>| {
        assert_eq!(
            value.keys().copied().collect::<Vec<_>>(),
            [i64::MIN, -100, -2, -1, 0, 1, 24, 100, i64::MAX]
        );
    });
}

#[test]
fn byte_keys_preserve_prefix_order_and_embedded_zeroes() {
    let expected: BTreeMap<ByteString, bool> = [
        (vec![], false),
        (vec![0], true),
        (vec![0, 0], false),
        (vec![0, 255], true),
        (vec![255], false),
    ]
    .into_iter()
    .map(|(key, value)| (ByteString::from(key), value))
    .collect();
    let mut map = dcbor::Map::new();
    for (key, value) in &expected {
        map.insert(key.clone(), *value).unwrap();
    }
    let wire = dcbor::CBOR::from(map).to_cbor_data();
    support::pipeline::round_trip(&wire, |value: &BTreeMap<ByteString, bool>| {
        assert_eq!(value, &expected);
    });
}

/// The arenas of a tree's custody, in its observation's order: the two
/// index arenas, the nodes, the entry records, each its execution
/// observation.
fn arenas<K, V>(custody: &TreeCustody<K, V>) -> [StoragePosition; 4] {
    [
        custody.order[0],
        custody.order[1],
        custody.nodes,
        custody.entries,
    ]
}

/// An arena that holds nothing: the position of a new arena, settled,
/// empty, unallocated ([`StoragePosition::default`]).
fn empty() -> StoragePosition {
    StoragePosition::default()
}

/// Whether `after`'s arenas are `before`'s but for at most one of those
/// `allowed`, moved by one unit `step` relates.
fn one_arena(
    before: &[StoragePosition; 4],
    after: &[StoragePosition; 4],
    allowed: &[usize],
    step: impl Fn(&StoragePosition, &StoragePosition) -> bool,
) -> bool {
    let moved: Vec<usize> = (0..4)
        .filter(|&arena| before[arena] != after[arena])
        .collect();
    match moved.as_slice() {
        [] => true,
        [arena] => allowed.contains(arena) && step(&before[*arena], &after[*arena]),
        _ => false,
    }
}

/// One unit of a relocation a cleanup step drives before it reads an arena
/// (`Storage::settle_step` on an arena whose elements are moving).
fn relocation(before: &StoragePosition, after: &StoragePosition) -> bool {
    matches!(
        before.stage,
        StorageStage::Relocating | StorageStage::Relocated
    ) && storage_build(before, after)
}

/// Popping through `settle_step` leaves a growth beside a settled arena
/// untouched. This differs from `reclaim_step`, which releases that growth
/// before draining the arena. Every field of the position except the
/// element count is kept, the growth's stage among them.
fn popped(before: &StoragePosition, after: &StoragePosition) -> bool {
    matches!(
        before.stage,
        StorageStage::Settled | StorageStage::Staged | StorageStage::Ready | StorageStage::Retired
    ) && before.initialized > 0
        && *after
            == StoragePosition {
                initialized: before.initialized - 1,
                ..*before
            }
}

/// The successor relations of a B-tree over its key's and value's, read
/// from `btree::build` and `btree::cleanup::reclaim`. Built: the metadata
/// block installed (its acquisition's binding and credit the operation's
/// custody, never this progress); its units initialized one per step (the phase, each of the
/// four arenas' own units, the eleven plain fields); the header read; per
/// entry its document index
/// gathered and a scratch slot pushed, each arena growing by its own units;
/// the merge sort's starts, comparisons and writes, the index arenas
/// relocating as they settle; the height raised; the root planned; per node
/// its write and release admitted, the node allocated with its permit
/// pending, stored in the node arena, linked, and its children planned;
/// per entry its record pushed with the key's and value's initial states,
/// the key's and then the value's own build steps; the nodes sealed; the
/// map published. At most one arena moves in a step, by one unit of its
/// own growth or use, and only an arena the phase reaches. Cleaned: cleanup
/// begins; per entry, newest first, the value's units, the key's, the
/// record popped, an older entry becoming newest; a pending node freed;
/// the nodes popped; each arena released, one unit at a time; the metadata
/// released. A metadata block not yet fully written is freed at once. The
/// sort, planning and slot progress, which depend on node shapes, are not
/// related; no remaining cleanup or claim is determined past the metadata's
/// own initialization.
fn tree<K, V>(key: Legality<K>, value: Legality<V>) -> Legality<TreeObservation<K, V>>
where
    K: Copy + PartialEq + 'static,
    V: Copy + PartialEq + 'static,
{
    use TreeObservation::{Held, Initializing, Unallocated};
    use TreePhase::{
        Allocate, AllocateRelease, AllocateWrite, Complete, Entry, Expand, Gather, Header, Height,
        Key, Link, PlanRoot, Publish, ReclaimEntry, ReclaimKey, ReclaimValue, ReleaseArenas,
        ReleaseNodes, Scratch, Seal, Sort, SortStart, SortWrite, Store, Value,
    };
    // The metadata's units, each initialized in a step of its own: the
    // phase, four arenas of `ARENA` units each, and eleven plain fields
    // (`btree::INIT`). An arena's units are its state, its holder's ticket
    // and its pending credit's four (`Storage::INIT_STEPS`).
    const ARENA: u8 = 6;
    const FIELDS: u8 = 1 + 4 * ARENA + 11;
    let Legality {
        initial: first_key,
        build: grow_key,
        clean: shrink_key,
        remaining: key_units,
        ..
    } = key;
    let Legality {
        initial: first_value,
        build: grow_value,
        clean: shrink_value,
        remaining: value_units,
        ..
    } = value;
    Legality {
        initial: Some(Unallocated),
        build: Rc::new(move |before, after| match (*before, *after) {
            (Unallocated, Initializing(0)) => true,
            (Initializing(done), Initializing(next)) => next == done + 1 && next < FIELDS,
            (Initializing(done), Held(custody)) => {
                done + 1 == FIELDS
                    && custody.phase == Header
                    && custody.count == 0
                    && custody.height == 0
                    && !custody.pending_node
                    && !custody.pending_permit
                    && custody.newest.is_none()
                    && arenas(&custody) == [empty(); 4]
            }
            (Held(held), Held(next)) => {
                let (from, to) = (arenas(&held), arenas(&next));
                let moved = |allowed: &[usize]| one_arena(&from, &to, allowed, storage_build);
                let shaped = next.count == held.count && next.height == held.height;
                let pending = next.pending_node == held.pending_node
                    && next.pending_permit == held.pending_permit;
                let kept = shaped && pending && next.newest == held.newest;
                // The newest entry's key grown by one of its own build steps,
                // its value untouched; or its value grown, its key untouched.
                let key_grown = match (held.newest, next.newest) {
                    (Some(entry), Some(grown)) => {
                        grown.value == entry.value && grow_key(&entry.key, &grown.key)
                    }
                    _ => false,
                };
                let value_grown = match (held.newest, next.newest) {
                    (Some(entry), Some(grown)) => {
                        grown.key == entry.key && grow_value(&entry.value, &grown.value)
                    }
                    _ => false,
                };
                match (held.phase, next.phase) {
                    (Header, Gather) => {
                        next.height == held.height
                            && pending
                            && next.newest == held.newest
                            && moved(&[])
                    }
                    (Gather, Gather | Scratch) => kept && moved(&[0]),
                    (Scratch, Scratch | Gather) => kept && moved(&[1]),
                    (Sort, Sort) | (SortWrite, SortWrite) => kept && moved(&[0, 1]),
                    (Gather, SortStart)
                    | (SortStart, Sort | Height)
                    | (Sort, SortStart | SortWrite)
                    | (SortWrite, Sort)
                    | (Height, PlanRoot)
                    | (PlanRoot, Publish | AllocateWrite)
                    | (AllocateWrite, AllocateRelease)
                    | (AllocateRelease, Allocate)
                    | (Link, Expand)
                    | (Expand, Entry | AllocateWrite)
                    | (Entry, Seal)
                    | (Seal, Publish)
                    | (Publish, Complete) => kept && moved(&[]),
                    (Height, Height) => {
                        next.count == held.count
                            && next.height == held.height + 1
                            && pending
                            && next.newest == held.newest
                            && moved(&[])
                    }
                    (Allocate, Store) => {
                        shaped
                            && !held.pending_node
                            && !held.pending_permit
                            && next.pending_node
                            && next.pending_permit
                            && next.newest == held.newest
                            && moved(&[])
                    }
                    (Store, Store) | (Link, Link) | (Expand, Expand) | (Seal, Seal) => {
                        kept && moved(&[2])
                    }
                    (Store, Link) => {
                        shaped
                            && held.pending_node
                            && held.pending_permit
                            && !next.pending_node
                            && !next.pending_permit
                            && next.newest == held.newest
                            && moved(&[2])
                    }
                    (Entry, Entry) => kept && moved(&[2, 3]),
                    (Entry, Key) => match next.newest {
                        Some(EntryObservation { key, value }) => {
                            shaped
                                && pending
                                && initial(&first_key, &key)
                                && initial(&first_value, &value)
                                && moved(&[3])
                        }
                        None => false,
                    },
                    (Key, Key) => {
                        (kept && moved(&[3])) || (shaped && pending && key_grown && moved(&[]))
                    }
                    (Key, Value) => shaped && pending && key_grown && moved(&[]),
                    (Value, Value) => {
                        (kept && moved(&[3])) || (shaped && pending && value_grown && moved(&[]))
                    }
                    (Value, Entry) => shaped && pending && value_grown && moved(&[]),
                    _ => false,
                }
            }
            _ => false,
        }),
        clean: Rc::new(move |before, after| match (*before, *after) {
            // The unit ending an unacquired tree's custody: the credit was
            // settled at the operation's cleanup entry.
            (Unallocated, Unallocated) | (Initializing(_), Unallocated) => true,
            (Held(held), Held(next)) => {
                let (from, to) = (arenas(&held), arenas(&next));
                let shaped = next.count == held.count && next.height == held.height;
                let pending = next.pending_node == held.pending_node
                    && next.pending_permit == held.pending_permit;
                let kept = shaped && pending && next.newest == held.newest;
                // The newest entry's key or value cleaned by one of its own
                // units, the other untouched, `last` its last unit or not.
                let key_unit = |last: bool| match (held.newest, next.newest) {
                    (Some(entry), Some(reclaimed)) => {
                        reclaimed.value == entry.value
                            && not_last(&key_units, &entry.key, !last)
                            && shrink_key(&entry.key, &reclaimed.key)
                    }
                    _ => false,
                };
                let value_unit = |last: bool| match (held.newest, next.newest) {
                    (Some(entry), Some(reclaimed)) => {
                        reclaimed.key == entry.key
                            && not_last(&value_units, &entry.value, !last)
                            && shrink_value(&entry.value, &reclaimed.value)
                    }
                    _ => false,
                };
                let reclaiming = matches!(
                    held.phase,
                    ReclaimValue | ReclaimKey | ReclaimEntry | ReleaseNodes | ReleaseArenas
                );
                match (held.phase, next.phase) {
                    (_, ReclaimValue) if !reclaiming => {
                        next == TreeCustody {
                            phase: ReclaimValue,
                            ..held
                        }
                    }
                    (ReclaimValue, ReclaimValue) => {
                        (kept && one_arena(&from, &to, &[3], relocation))
                            || (shaped && pending && from == to && value_unit(false))
                    }
                    (ReclaimValue, ReclaimKey) => {
                        shaped && pending && from == to && value_unit(true)
                    }
                    (ReclaimValue, ReleaseNodes) => kept && held.newest.is_none() && from == to,
                    (ReclaimKey, ReclaimKey) => {
                        (kept && one_arena(&from, &to, &[3], relocation))
                            || (shaped && pending && from == to && key_unit(false))
                    }
                    (ReclaimKey, ReclaimEntry) => shaped && pending && from == to && key_unit(true),
                    (ReclaimEntry, ReclaimEntry) => kept && one_arena(&from, &to, &[3], relocation),
                    (ReclaimEntry, ReclaimValue) => {
                        shaped
                            && pending
                            && one_arena(&from, &to, &[3], popped)
                            && next.entries.initialized + 1 == held.entries.initialized
                            && next.newest.is_some() == (next.entries.initialized > 0)
                    }
                    (ReleaseNodes, ReleaseNodes) => {
                        let freed = held.pending_node
                            && held.pending_permit
                            && !next.pending_node
                            && !next.pending_permit
                            && from == to;
                        let popped = !held.pending_node
                            && pending
                            && one_arena(&from, &to, &[2], |before, after| {
                                popped(before, after) || relocation(before, after)
                            });
                        shaped && next.newest == held.newest && (freed || popped)
                    }
                    (ReleaseNodes, ReleaseArenas) => {
                        kept && !held.pending_node && !held.pending_permit && from == to
                    }
                    (ReleaseArenas, ReleaseArenas) => {
                        kept && one_arena(&from, &to, &[0, 1, 2, 3], storage_clean)
                    }
                    _ => false,
                }
            }
            (Held(held), Unallocated) => {
                held.phase == ReleaseArenas && arenas(&held) == [empty(); 4]
            }
            _ => false,
        }),
        remaining: Rc::new(|observation| match observation {
            Unallocated | Initializing(_) => Some(1),
            Held(_) => None,
        }),
        // The metadata block, written unit by unit before anything else is
        // acquired; past it, the arenas' and nodes' blocks are not observed
        // one by one.
        permits: Rc::new(|observation| match observation {
            Unallocated => Some(Vec::new()),
            Initializing(_) => Some(vec![0]),
            Held(_) => None,
        }),
        physical: Rc::new(|observation| match observation {
            Unallocated => Some(Vec::new()),
            Initializing(_) => Some(vec![0]),
            Held(_) => None,
        }),
    }
}

/// The canonical encoding of a map of `count` entries, `key` and `value` of
/// each entry's index.
fn map_wire<K: dcbor::CBOREncodable, V: dcbor::CBOREncodable>(
    count: usize,
    key: impl Fn(usize) -> K,
    value: impl Fn(usize) -> V,
) -> Vec<u8> {
    let mut symbolic = dcbor::Map::new();
    for n in 0..count {
        symbolic.insert(key(n), value(n)).unwrap();
    }
    dcbor::CBOR::from(symbolic).to_cbor_data()
}

/// Every state a tree's construction reaches has a complete observation
/// ([`support::observation`]), and every transition is in the tree's
/// successor relations over its key's and value's ([`support::legal`]), over
/// sizes enumerated whole: text-keyed trees of every count from empty
/// through one past a full leaf, the first to plan a root over two leaves;
/// integer keys; and a key of the wrong kind, rejected while gathering. At
/// each further height boundary, 143 and 144 entries (two levels) and, in
/// the exhaustive layer, 1727 and 1728 (three), the whole construction and
/// the cleanup of the built tree are checked, with integer entries: a text
/// entry holds four allocations (each string's metadata block and buffer),
/// so a tree of 143 text entries holds more live allocations than the heap
/// observer records (512). At minimal witness sizes the exhaustive layer
/// keeps the two-level boundaries only, the reach map requiring the same
/// regions as at full sizes. Fast runs check the complete build and cleanup
/// transitions; exhaustive runs additionally rebuild and cancel at every
/// construction prefix for each small text-keyed fixture. Each height
/// boundary records into its configuration's measured budget ([`Budgets`]).
#[test]
fn tree_construction_is_complete_and_its_transitions_legal() {
    use support::legality::{buffer, written};
    use support::rigor::{Rigor, rigor, sized};
    use support::{construction, legal, observation};
    for count in 0..=13 {
        let wire = map_wire(count, |n| format!("{n:x}"), |n| format!("v{n}"));
        let name = format!("BTreeMap<String, String> of {count} entries");
        let runs = match rigor() {
            Rigor::Fast => vec![construction::<BTreeMap<String, String>>(
                &wire,
                None,
                |map| {
                    assert_eq!(map.len(), count);
                    for n in 0..count {
                        assert_eq!(map.get(&format!("{n:x}")), Some(&format!("v{n}")));
                    }
                },
            )],
            Rigor::Exhaustive => observation::<BTreeMap<String, String>, _>(&name, &wire, |o| *o),
        };
        legal(&name, &runs, &tree(buffer(), buffer()));
    }
    let boundaries: &[usize] = match rigor() {
        Rigor::Fast => &[143, 144],
        Rigor::Exhaustive => sized(&[143, 144, 1727, 1728], &[143, 144]),
    };
    let key = |count| format!("integer-construction/{count}");
    let mut budgets = Budgets::new(
        "btree-construction",
        variant!(),
        boundaries.iter().map(|&count| key(count)).collect(),
    );
    for &count in boundaries {
        let wire = map_wire(count, |n| n as u64, |n| n as u64);
        let name = format!("BTreeMap<u64, u64> of {count} entries");
        let built = budgets.construction::<BTreeMap<u64, u64>>(&key(count), &wire, |map| {
            assert_eq!(map.len(), count, "{count} entries")
        });
        eprintln!(
            "[tree construction] {count} integer entries: {} events, {} permit records, {:?}",
            built.observed.len(),
            counts(&built.observed).permits,
            built.phases,
        );
        legal(&name, &[built], &tree(written(), written()));
    }
    budgets.finish();
    let mut integers = dcbor::Map::new();
    for n in [-2i64, 0, 24, 100] {
        integers.insert(n, n).unwrap();
    }
    let wire = dcbor::CBOR::from(integers).to_cbor_data();
    let name = "BTreeMap<i64, i64>";
    legal(
        name,
        &observation::<BTreeMap<i64, i64>, _>(name, &wire, |o| *o),
        &tree(written(), written()),
    );
    let name = "BTreeMap<String, i64> of integer keys";
    legal(
        name,
        &observation::<BTreeMap<String, i64>, _>(name, &wire, |o| *o),
        &tree(buffer(), written()),
    );
}
