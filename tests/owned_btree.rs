//! Real BTreeMap construction through the fork's fixed-address nodes.
#![cfg(all(feature = "std", feature = "custom-std-collections"))]
#![forbid(unsafe_code)]
// The observed construction driver witnesses physical storage.
#[global_allocator]
static HEAP: support::heap::Heap = support::heap::Heap;
use dcbor::ByteString;
use dcbor::bounded::Limits;
use dcbor::bounded::decode::Options;
use dcbor::bounded::decode::construction::in_place::{
    EntryObservation, TreeCustody, TreeObservation, TreePhase,
};
use dcbor::bounded::decode::construction::reclamation::Admitted;
use dcbor::bounded::decode::construction::{TypedDecoder, TypedValue};
use dcbor::bounded::decode::storage::{StoragePosition, StorageStage};
use dcbor::bounded::encoding::OwnedPreparation;
use dcbor_test_support as support;
use std::collections::BTreeMap;
use std::rc::Rc;
use support::legality::{Legality, initial, not_last, storage_build, storage_clean};

/// Node occupancy boundaries: empty, one entry, around a node's minimum and
/// its capacity (a full leaf, then the first split), and around each further
/// height; and a wide map, 256 entries whose values carry 80 bytes more
/// each. At minimal witness sizes the third level's (1727, 1728) is dropped:
/// the reach map requires the minimal run to execute every region the full
/// run does (`tests/reach-map.sh`). What only those maps reach is head
/// width, not a tree path: a count of at least 256 (a two-byte head) and an
/// input of at least 21,846 bytes, whose parse bound of three part bytes a
/// byte (`text::PART_BYTES_PER_BYTE`) reaches 65,536 (a four-byte head).
/// The wide map has both at a fraction of their entries.
#[test]
fn node_occupancy_boundaries_preserve_rust_order_and_canonical_encoding() {
    const WIDE: (usize, usize) = (256, 80);
    let maps: &[(usize, usize)] = support::rigor::sized(
        &[
            (0, 0),
            (1, 0),
            (5, 0),
            (6, 0),
            (10, 0),
            (11, 0),
            (12, 0),
            (13, 0),
            (70, 0),
            (71, 0),
            (72, 0),
            (143, 0),
            (144, 0),
            (145, 0),
            (1727, 0),
            (1728, 0),
            WIDE,
        ],
        &[
            (0, 0),
            (1, 0),
            (5, 0),
            (6, 0),
            (10, 0),
            (11, 0),
            (12, 0),
            (13, 0),
            (70, 0),
            (71, 0),
            (72, 0),
            (143, 0),
            (144, 0),
            (145, 0),
            WIDE,
        ],
    );
    for &(count, padding) in maps {
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
            symbolic.insert(key.clone(), value.clone());
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
        let mut m = Limits::unlimited().logged().strict();
        let mut owner = support::scope(&mut m);
        let input = support::copy(&owner, &mut m, &wire);
        let value: TypedValue<'static, ByteString, BTreeMap<String, String>, Limits> =
            support::drive_within(
                &mut m,
                &mut TypedDecoder::new(input, Options::normalizing(8)),
                support::typed_turns::<BTreeMap<String, String>>(wire.len()),
            )
            .expect("tree decode");
        assert_eq!(value.value(), &expected, "{count} entries");
        for (key, wanted) in &expected {
            assert_eq!(value.value().get(key), Some(wanted));
        }
        let shape = dcbor::bounded::encoding::Shape::of(value.value(), &mut Limits::unlimited())
            .expect("tree shape");
        let bound = support::turns(
            dcbor::bounded::encoding::owned_prepare_bound::<
                ByteString,
                BTreeMap<String, String>,
                Limits,
                (),
            >(shape)
            .expect("owned tree preparation bound"),
        );
        let plan = support::drive_within(&mut m, &mut OwnedPreparation::prepare(value), bound)
            .expect("tree preparation");
        let len = plan.len();
        let bytes = support::emit(&mut m, &mut plan.into_writer(), len);
        assert_eq!(bytes, wire, "{count} entries");
        support::drain(&mut owner, &mut m);
        assert_eq!(m.live_bytes(), 0);
    }
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
        map.insert(n, n);
    }
    let wire = dcbor::CBOR::from(map).to_cbor_data();
    let mut m = Limits::unlimited().logged().strict();
    let mut owner = support::scope(&mut m);
    let input = support::copy(&owner, &mut m, &wire);
    let value: TypedValue<'static, ByteString, BTreeMap<i64, i64>, Limits> =
        support::decode(&mut m, input, Options::normalizing(8)).expect("integer tree decode");
    assert_eq!(
        value.value().keys().copied().collect::<Vec<_>>(),
        [i64::MIN, -100, -2, -1, 0, 1, 24, 100, i64::MAX]
    );
    drop(value);
    support::drain(&mut owner, &mut m);
    assert_eq!(m.live_bytes(), 0);
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
        map.insert(key.clone(), *value);
    }
    let wire = dcbor::CBOR::from(map).to_cbor_data();
    let mut m = Limits::unlimited().logged().strict();
    let mut owner = support::scope(&mut m);
    let input = support::copy(&owner, &mut m, &wire);
    let value: TypedValue<'static, ByteString, BTreeMap<ByteString, bool>, Limits> =
        support::decode(&mut m, input, Options::normalizing(8)).expect("byte-key tree decode");
    assert_eq!(value.value(), &expected);
    let bound = support::turns(
        dcbor::bounded::encoding::owned_prepare_bound::<
            ByteString,
            BTreeMap<ByteString, bool>,
            Limits,
            (),
        >(support::shape(value.value()))
        .expect("owned byte-key tree preparation bound"),
    );
    let plan = support::drive_within(&mut m, &mut OwnedPreparation::prepare(value), bound)
        .expect("byte-key tree preparation");
    let len = plan.len();
    assert_eq!(support::emit(&mut m, &mut plan.into_writer(), len), wire);
    support::drain(&mut owner, &mut m);
    assert_eq!(m.live_bytes(), 0);
}

/// The arenas of a tree's custody, in its observation's order: the two
/// index arenas, the nodes, the entry records.
fn arenas<K, V>(custody: &TreeCustody<K, V>) -> [StoragePosition; 4] {
    [
        custody.order[0],
        custody.order[1],
        custody.nodes,
        custody.entries,
    ]
}

/// An arena that holds nothing: settled, empty, unallocated.
const EMPTY: StoragePosition = StoragePosition {
    stage: StorageStage::Settled,
    initialized: 0,
    reserved_capacity: 0,
    physical_capacity: 0,
    relocating_remaining: 0,
    has_current_permit: false,
    staged_reserved_capacity: 0,
    staged_physical_capacity: 0,
    has_staged_permit: false,
    has_relocating_permit: false,
};

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
/// before draining the arena. Every field except the element count is kept.
fn popped(before: &StoragePosition, after: &StoragePosition) -> bool {
    matches!(
        before.stage,
        StorageStage::Settled
            | StorageStage::Staging(_)
            | StorageStage::Staged(_)
            | StorageStage::Ready
            | StorageStage::Retired
    ) && before.initialized > 0
        && *after
            == StoragePosition {
                initialized: before.initialized - 1,
                ..*before
            }
}

/// The successor relations of a B-tree over its key's and value's, read
/// from `btree::build` and `btree::cleanup::reclaim`. Built: the metadata
/// block installed, its admissions only advancing; its sixteen fields
/// initialized one per step; the header read; per entry its document index
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
    // The metadata's fields, each initialized in a step of its own.
    const FIELDS: u8 = 16;
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
        initial: Some(Unallocated(Admitted::Nothing)),
        build: Rc::new(move |before, after| match (*before, *after) {
            (Unallocated(admitted), Unallocated(next)) => next > admitted,
            (Unallocated(_), Initializing(0)) => true,
            (Initializing(done), Initializing(next)) => next == done + 1 && next < FIELDS,
            (Initializing(done), Held(custody)) => {
                done + 1 == FIELDS
                    && custody.phase == Header
                    && custody.count == 0
                    && custody.height == 0
                    && !custody.pending_node
                    && !custody.pending_permit
                    && custody.newest.is_none()
                    && arenas(&custody) == [EMPTY; 4]
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
            (Unallocated(admitted), Unallocated(next)) => next == admitted,
            (Initializing(_), Unallocated(next)) => next == Admitted::Nothing,
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
            (Held(held), Unallocated(next)) => {
                held.phase == ReleaseArenas
                    && arenas(&held) == [EMPTY; 4]
                    && next == Admitted::Nothing
            }
            _ => false,
        }),
        remaining: Rc::new(|observation| match observation {
            Unallocated(_) | Initializing(_) => Some(1),
            Held(_) => None,
        }),
        // The metadata block, written field by field before anything else is
        // acquired; past it, the arenas' and nodes' blocks are not observed
        // one by one.
        permits: Rc::new(|observation| match observation {
            Unallocated(_) => Some(Vec::new()),
            Initializing(_) => Some(vec![0]),
            Held(_) => None,
        }),
        physical: Rc::new(|observation| match observation {
            Unallocated(_) => Some(Vec::new()),
            Initializing(_) => Some(vec![0]),
            Held(_) => None,
        }),
    }
}

/// The canonical encoding of a map of `count` entries, `key` and `value` of
/// each entry's index.
fn map_wire<K: Into<dcbor::CBOR>, V: Into<dcbor::CBOR>>(
    count: usize,
    key: impl Fn(usize) -> K,
    value: impl Fn(usize) -> V,
) -> Vec<u8> {
    let mut symbolic = dcbor::Map::new();
    for n in 0..count {
        symbolic.insert(key(n), value(n));
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
/// regions as at full sizes.
#[test]
fn tree_construction_is_complete_and_its_transitions_legal() {
    use support::legality::{buffer, written};
    use support::rigor::{Rigor, rigor, sized};
    use support::{construction, legal, observation};
    for count in 0..=13 {
        let wire = map_wire(count, |n| format!("{n:x}"), |n| format!("v{n}"));
        let name = format!("BTreeMap<String, String> of {count} entries");
        legal(
            &name,
            &observation::<BTreeMap<String, String>, _>(&name, &wire, |o| *o),
            &tree(buffer(), buffer()),
        );
    }
    let boundaries: &[usize] = match rigor() {
        Rigor::Fast => &[143, 144],
        Rigor::Exhaustive => sized(&[143, 144, 1727, 1728], &[143, 144]),
    };
    for &count in boundaries {
        let wire = map_wire(count, |n| n as u64, |n| n as u64);
        let name = format!("BTreeMap<u64, u64> of {count} entries");
        let built = construction::<BTreeMap<u64, u64>>(&wire, None, |map| {
            assert_eq!(map.len(), count, "{count} entries");
        });
        legal(&name, &[built], &tree(written(), written()));
    }
    let mut integers = dcbor::Map::new();
    for n in [-2i64, 0, 24, 100] {
        integers.insert(n, n);
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
