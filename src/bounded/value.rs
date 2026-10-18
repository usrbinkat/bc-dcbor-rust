//! Additional representations. Dynamic Rust maps retain their complete sorted
//! encoding during preparation; symbolic maps already own canonical key order.
import_stdlib!();
use super::*;
use crate::{CBOR, CBORCase, Date, Map, Simple};

/// An explicit tag around a bounded value. This does not call the allocating
/// `CBORTaggedEncodable` interface. Derived tagged types still encode their
/// untagged representation unless wrapped here.
pub struct Tagged<T> {
    pub tag: u64,
    pub value: T,
}

impl<T: BoundedEncodable> BoundedEncodable for Tagged<T> {
    fn measure<A: Allocator>(
        &self,
        plan: &mut Plan<A::Permit>,
        allocator: &mut A,
    ) -> BoundedResult<Measure, A> {
        allocator.traverse(1, 0).map_err(BoundedError::Refused)?;
        let inner = self.value.measure(plan, allocator)?;
        Ok(Measure {
            len: item_len(self.tag, inner.len)?,
            write: WriteWork::new(1, 0).then(inner.write)?,
        })
    }
    fn write<P, B: Budget>(
        &self,
        plan: &mut Cursor<'_, P>,
        output: &mut Output<'_>,
        budget: &mut B,
    ) -> BoundedResult<(), B> {
        budget.traverse(1, 0).map_err(BoundedError::Refused)?;
        output.head(MajorType::Tagged, self.tag)?;
        self.value.write(plan, output, budget)
    }
}

/// Standalone options use null for None and the contained encoding for Some.
/// As with other nullable wire formats, Some(null) and None are not distinct.
/// Derived optional map fields keep their existing omission semantics.
impl<T: BoundedEncodable> BoundedEncodable for Option<T> {
    fn measure<A: Allocator>(
        &self,
        plan: &mut Plan<A::Permit>,
        allocator: &mut A,
    ) -> BoundedResult<Measure, A> {
        allocator.traverse(1, 0).map_err(BoundedError::Refused)?;
        match self {
            None => Ok(Measure::leaf(1, 0)),
            Some(value) => {
                let inner = value.measure(plan, allocator)?;
                Ok(Measure {
                    len: inner.len,
                    write: WriteWork::new(1, 0).then(inner.write)?,
                })
            }
        }
    }
    fn write<P, B: Budget>(
        &self,
        plan: &mut Cursor<'_, P>,
        output: &mut Output<'_>,
        budget: &mut B,
    ) -> BoundedResult<(), B> {
        budget.traverse(1, 0).map_err(BoundedError::Refused)?;
        match self {
            None => output.head(MajorType::Simple, NULL),
            Some(value) => value.write(plan, output, budget),
        }
    }
}

impl BoundedEncodable for Date {
    fn measure<A: Allocator>(
        &self,
        plan: &mut Plan<A::Permit>,
        allocator: &mut A,
    ) -> BoundedResult<Measure, A> {
        // Admit timestamp conversion before evaluating it.
        allocator.traverse(1, 0).map_err(BoundedError::Refused)?;
        let inner = Tagged {
            tag: crate::TAG_DATE,
            value: self.timestamp(),
        }
        .measure(plan, allocator)?;
        Ok(Measure {
            len: inner.len,
            write: WriteWork::new(1, 0).then(inner.write)?,
        })
    }
    fn write<P, B: Budget>(
        &self,
        plan: &mut Cursor<'_, P>,
        output: &mut Output<'_>,
        budget: &mut B,
    ) -> BoundedResult<(), B> {
        budget.traverse(1, 0).map_err(BoundedError::Refused)?;
        Tagged {
            tag: crate::TAG_DATE,
            value: self.timestamp(),
        }
        .write(plan, output, budget)
    }
}

impl BoundedEncodable for Simple {
    fn measure<A: Allocator>(
        &self,
        plan: &mut Plan<A::Permit>,
        allocator: &mut A,
    ) -> BoundedResult<Measure, A> {
        allocator.traverse(1, 0).map_err(BoundedError::Refused)?;
        let inner = match self {
            Self::Float(value) => value.measure(plan, allocator)?,
            _ => Measure {
                len: 1,
                write: WriteWork::default(),
            },
        };
        Ok(Measure {
            len: inner.len,
            write: WriteWork::new(1, 0).then(inner.write)?,
        })
    }
    fn write<P, B: Budget>(
        &self,
        plan: &mut Cursor<'_, P>,
        output: &mut Output<'_>,
        budget: &mut B,
    ) -> BoundedResult<(), B> {
        budget.traverse(1, 0).map_err(BoundedError::Refused)?;
        match self {
            Self::False => output.head(MajorType::Simple, 20),
            Self::True => output.head(MajorType::Simple, 21),
            Self::Null => output.head(MajorType::Simple, 22),
            Self::Float(value) => value.write(plan, output, budget),
        }
    }
}

impl BoundedEncodable for CBOR {
    fn measure<A: Allocator>(
        &self,
        plan: &mut Plan<A::Permit>,
        allocator: &mut A,
    ) -> BoundedResult<Measure, A> {
        allocator.traverse(1, 0).map_err(BoundedError::Refused)?;
        if plan.depth >= 128 {
            return Err(BoundedError::DepthLimit);
        }
        plan.depth += 1;
        let result = match self.as_case() {
            CBORCase::Unsigned(n) => n.measure(plan, allocator),
            CBORCase::Negative(n) if *n <= i64::MAX as u64 => {
                (-1 - *n as i64).measure(plan, allocator)
            }
            CBORCase::Negative(_) => Err(BoundedError::OutOfRange),
            CBORCase::ByteString(bytes) => bytes.measure(plan, allocator),
            CBORCase::Text(text) => text.measure(plan, allocator),
            CBORCase::Array(values) => values.measure(plan, allocator),
            CBORCase::Map(map) => map.measure(plan, allocator),
            CBORCase::Tagged(tag, value) => Tagged {
                tag: tag.value(),
                value,
            }
            .measure(plan, allocator),
            CBORCase::Simple(value) => value.measure(plan, allocator),
        };
        plan.depth -= 1;
        let inner = result?;
        Ok(Measure {
            len: inner.len,
            write: WriteWork::new(1, 0).then(inner.write)?,
        })
    }
    fn write<P, B: Budget>(
        &self,
        plan: &mut Cursor<'_, P>,
        output: &mut Output<'_>,
        budget: &mut B,
    ) -> BoundedResult<(), B> {
        budget.traverse(1, 0).map_err(BoundedError::Refused)?;
        match self.as_case() {
            CBORCase::Unsigned(n) => n.write(plan, output, budget),
            CBORCase::Negative(n) if *n <= i64::MAX as u64 => {
                (-1 - *n as i64).write(plan, output, budget)
            }
            CBORCase::Negative(_) => Err(BoundedError::OutOfRange),
            CBORCase::ByteString(bytes) => bytes.write(plan, output, budget),
            CBORCase::Text(text) => text.write(plan, output, budget),
            CBORCase::Array(values) => values.write(plan, output, budget),
            CBORCase::Map(map) => map.write(plan, output, budget),
            CBORCase::Tagged(tag, value) => Tagged {
                tag: tag.value(),
                value,
            }
            .write(plan, output, budget),
            CBORCase::Simple(value) => value.write(plan, output, budget),
        }
    }
}

impl BoundedEncodable for Map {
    fn measure<A: Allocator>(
        &self,
        plan: &mut Plan<A::Permit>,
        allocator: &mut A,
    ) -> BoundedResult<Measure, A> {
        allocator.traverse(1, 0).map_err(BoundedError::Refused)?;
        let mut measured = Measure::leaf(widen(head_len(widen(self.len())?))?, 0);
        for (key, value) in self.iter() {
            for value in [key, value] {
                let inner = value.measure(plan, allocator)?;
                measured.len = add(measured.len, inner.len)?;
                measured.write = measured.write.then(inner.write)?;
            }
        }
        Ok(measured)
    }
    fn write<P, B: Budget>(
        &self,
        plan: &mut Cursor<'_, P>,
        output: &mut Output<'_>,
        budget: &mut B,
    ) -> BoundedResult<(), B> {
        budget.traverse(1, 0).map_err(BoundedError::Refused)?;
        output.head(MajorType::Map, widen(self.len())?)?;
        for (key, value) in self.iter() {
            key.write(plan, output, budget)?;
            value.write(plan, output, budget)?;
        }
        Ok(())
    }
}

type EncodedEntry<P> = (Encoded<P>, Encoded<P>);

fn compare_keys<P, B: Budget>(
    left: &EncodedEntry<P>,
    right: &EncodedEntry<P>,
    budget: &mut B,
) -> BoundedResult<cmp::Ordering, B> {
    let (left, right) = (left.0.as_ref(), right.0.as_ref());
    budget
        .traverse(1, widen(left.len().min(right.len()))?)
        .map_err(BoundedError::Refused)?;
    Ok(left.cmp(right))
}

// In-place heapsort gives O(n log n) comparisons and moves, with no hidden
// sorting allocation. Comparisons and swaps can each refuse before executing.
fn sort_entries<P, B: Budget>(
    entries: &mut [EncodedEntry<P>],
    budget: &mut B,
) -> BoundedResult<(), B> {
    fn sift<P, B: Budget>(
        entries: &mut [EncodedEntry<P>],
        mut root: usize,
        budget: &mut B,
    ) -> BoundedResult<(), B> {
        while root < entries.len() / 2 {
            let mut child = root * 2 + 1;
            if child + 1 < entries.len()
                && compare_keys(&entries[child], &entries[child + 1], budget)?
                    == cmp::Ordering::Less
            {
                child += 1;
            }
            if compare_keys(&entries[root], &entries[child], budget)? != cmp::Ordering::Less {
                break;
            }
            swap(entries, root, child, budget)?;
            root = child;
        }
        Ok(())
    }
    fn swap<P, B: Budget>(
        entries: &mut [EncodedEntry<P>],
        left: usize,
        right: usize,
        budget: &mut B,
    ) -> BoundedResult<(), B> {
        budget
            .traverse(1, mul(3, widen(core::mem::size_of::<EncodedEntry<P>>())?)?)
            .map_err(BoundedError::Refused)?;
        entries.swap(left, right);
        Ok(())
    }
    for root in (0..entries.len() / 2).rev() {
        sift(&mut *entries, root, budget)?;
    }
    for end in (1..entries.len()).rev() {
        swap(entries, 0, end, budget)?;
        sift(&mut entries[..end], 0, budget)?;
    }
    Ok(())
}

fn measure_dynamic_map<'a, K: BoundedEncodable + 'a, V: BoundedEncodable + 'a, A: Allocator>(
    entries: impl Iterator<Item = (&'a K, &'a V)>,
    plan: &mut Plan<A::Permit>,
    allocator: &mut A,
) -> BoundedResult<Measure, A> {
    allocator.traverse(1, 0).map_err(BoundedError::Refused)?;
    let mut sorted: Owned<EncodedEntry<A::Permit>, A::Permit> = Owned::new();
    for (key, value) in entries {
        allocator.traverse(1, 0).map_err(BoundedError::Refused)?;
        let key = encode(key, allocator)?;
        let value = encode(value, allocator)?;
        sorted.push((key, value), allocator)?;
    }
    sort_entries(&mut sorted.items, allocator)?;
    for pair in sorted.as_slice().windows(2) {
        if compare_keys(&pair[0], &pair[1], allocator)? == cmp::Ordering::Equal {
            return Err(BoundedError::DuplicateKey);
        }
    }
    let mut bytes = Owned::new();
    let mut head = [0; MAX_HEAD_LEN];
    let length = write_argument(
        MajorType::Map,
        Argument::Shortest(widen(sorted.len())?),
        &mut head,
    );
    allocator
        .traverse(0, widen(length)?)
        .map_err(BoundedError::Refused)?;
    bytes.extend_from_slice(&head[..length], allocator)?;
    for (key, value) in sorted.drain() {
        for data in [key.as_ref(), value.as_ref()] {
            allocator
                .traverse(0, widen(data.len())?)
                .map_err(BoundedError::Refused)?;
            bytes.extend_from_slice(data, allocator)?;
        }
    }
    let length = widen(bytes.len())?;
    plan.blobs.push(bytes, allocator)?;
    Ok(Measure::leaf(length, length))
}

fn write_dynamic_map<P, B: Budget>(
    plan: &mut Cursor<'_, P>,
    output: &mut Output<'_>,
    budget: &mut B,
) -> BoundedResult<(), B> {
    let bytes = plan
        .blobs
        .get(plan.next_blob)
        .ok_or(BoundedError::PlanMismatch)?
        .as_slice();
    budget
        .traverse(1, widen(bytes.len())?)
        .map_err(BoundedError::Refused)?;
    output.slice(bytes)?;
    plan.next_blob += 1;
    Ok(())
}

impl<K: BoundedEncodable, V: BoundedEncodable> BoundedEncodable for BTreeMap<K, V> {
    fn measure<A: Allocator>(
        &self,
        plan: &mut Plan<A::Permit>,
        allocator: &mut A,
    ) -> BoundedResult<Measure, A> {
        allocator
            .traverse(add(widen(self.len())?, 1)?, 0)
            .map_err(BoundedError::Refused)?;
        measure_dynamic_map(self.iter(), plan, allocator)
    }
    fn write<P, B: Budget>(
        &self,
        plan: &mut Cursor<'_, P>,
        output: &mut Output<'_>,
        budget: &mut B,
    ) -> BoundedResult<(), B> {
        write_dynamic_map(plan, output, budget)
    }
}

impl<K: BoundedEncodable, V: BoundedEncodable, S> BoundedEncodable for HashMap<K, V, S> {
    fn measure<A: Allocator>(
        &self,
        plan: &mut Plan<A::Permit>,
        allocator: &mut A,
    ) -> BoundedResult<Measure, A> {
        // Hash-table iteration scans empty buckets too, even for an empty map
        // retaining a large allocation. Admit that scan before constructing it.
        let scan = add(mul(widen(self.capacity())?, 2)?, 1)?;
        allocator
            .traverse(scan, scan)
            .map_err(BoundedError::Refused)?;
        measure_dynamic_map(self.iter(), plan, allocator)
    }
    fn write<P, B: Budget>(
        &self,
        plan: &mut Cursor<'_, P>,
        output: &mut Output<'_>,
        budget: &mut B,
    ) -> BoundedResult<(), B> {
        write_dynamic_map(plan, output, budget)
    }
}
