//! Owning, movable references to the same intrusive reclamation mechanism.
//!
//! The scope owns queued records. Each live record handle owns one scope
//! reference. Only a record handle accesses its payload; after retirement only
//! the scope's active cleanup slot does. Shutdown releases the scope allocation
//! only when no other handle exists and the intrusive owner is empty.
use super::*;

struct Scope<A: Allocator> {
    owner: Reclaimer<A>,
    references: Cell<usize>,
    permit: A::Permit,
}

/// Single-threaded movable cleanup authority. `new` allocates nothing.
/// Initialize with `initialize_step`, retain this authority while handles are
/// live, then call `shutdown_step` until Done. Drop never drains resources.
pub struct OwnedReclaimer<A: Allocator> {
    scope: Option<NonNull<Scope<A>>>,
    admitted: bool,
}

impl<A: Allocator> Default for OwnedReclaimer<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Allocator> OwnedReclaimer<A> {
    pub const fn new() -> Self {
        Self {
            scope: None,
            admitted: false,
        }
    }

    pub fn initialize_step(&mut self, a: &mut A) -> BoundedResult<bool, A> {
        if self.scope.is_some() {
            return Ok(true);
        }
        let layout = Layout::new::<Scope<A>>();
        if layout.size() > 64 {
            return Err(BoundedError::PlanMismatch);
        }
        if !self.admitted {
            a.traverse(1, layout.size() as u64)
                .map_err(BoundedError::Refused)?;
            self.admitted = true;
        }
        let permit = a
            .allocate(layout.size() as u64)
            .map_err(BoundedError::Refused)?;
        let raw = NonNull::new(unsafe { alloc(layout) }.cast::<Scope<A>>()).ok_or(
            BoundedError::Allocation {
                bytes: layout.size() as u64,
            },
        )?;
        unsafe {
            raw.as_ptr().write(Scope {
                owner: Reclaimer::new(),
                references: Cell::new(1),
                permit,
            });
        }
        self.scope = Some(raw);
        self.admitted = false;
        Ok(true)
    }

    fn duplicate(&self) -> Self {
        let scope = self.scope.expect("initialized scope");
        let references = unsafe { &scope.as_ref().references };
        references.set(
            references
                .get()
                .checked_add(1)
                .expect("scope reference overflow"),
        );
        Self {
            scope: Some(scope),
            admitted: false,
        }
    }

    fn owner(&self) -> &Reclaimer<A> {
        unsafe { &self.scope.expect("initialized scope").as_ref().owner }
    }

    pub fn outstanding(&self) -> usize {
        self.scope
            .map_or(0, |scope| unsafe { scope.as_ref().owner.outstanding() })
    }

    pub fn allocate_step<T: Reclaim<A> + 'static>(
        &self,
        a: &mut A,
        admitted: &mut bool,
    ) -> BoundedResult<OwnedRecord<T, A>, A> {
        if self.scope.is_none() {
            return Err(BoundedError::PlanMismatch);
        }
        let record =
            core::mem::ManuallyDrop::new(self.owner().allocate_retained::<T>(a, admitted)?);
        Ok(OwnedRecord {
            block: record.block,
            scope: self.duplicate(),
            marker: PhantomData,
        })
    }

    pub fn step(&self, a: &mut A) -> BoundedResult<Reclaimed, A> {
        match self.scope {
            Some(_) => self.owner().step(a),
            None => Ok(Reclaimed::Done),
        }
    }

    pub fn shutdown_step(&mut self, a: &mut A) -> BoundedResult<Reclaimed, A> {
        let Some(scope) = self.scope else {
            return Ok(Reclaimed::Done);
        };
        if self.owner().shutdown_step(a)? != Reclaimed::Done {
            return Ok(Reclaimed::Progress);
        }
        if unsafe { scope.as_ref().references.get() } != 1 {
            return Ok(Reclaimed::Progress);
        }
        a.traverse(1, size_of::<A::Permit>() as u64)
            .map_err(BoundedError::Refused)?;
        self.scope = None;
        unsafe {
            let permit = ptr::addr_of!((*scope.as_ptr()).permit).read();
            dealloc(scope.as_ptr().cast(), Layout::new::<Scope<A>>());
            drop(permit);
        }
        Ok(Reclaimed::Done)
    }
}

impl<A: Allocator> Drop for OwnedReclaimer<A> {
    fn drop(&mut self) {
        if let Some(scope) = self.scope {
            let references = unsafe { &scope.as_ref().references };
            let count = references.get();
            // The allocation is deliberately retained on misuse: unwinding may
            // not invalidate queued resources or run unadmitted destructors.
            assert!(count > 1, "owned reclamation scope dropped before shutdown");
            references.set(count - 1);
        }
    }
}

/// An owning stable destination; retirement transfers to the scope's queue.
pub struct OwnedRecord<T: Reclaim<A>, A: Allocator> {
    block: NonNull<Block<T, A>>,
    scope: OwnedReclaimer<A>,
    marker: InvariantOwned<T>,
}

impl<T: Reclaim<A>, A: Allocator> OwnedRecord<T, A> {
    /// # Safety
    /// Same stable initialization and cursor obligations as Record::destination.
    pub unsafe fn destination(&mut self) -> (NonNull<MaybeUninit<T>>, &mut Cursor) {
        unsafe {
            (
                NonNull::new_unchecked(ptr::addr_of_mut!((*self.block.as_ptr()).value)),
                &mut (*self.block.as_ptr()).cursor,
            )
        }
    }

    /// # Safety
    /// T must be fully initialized and its cursor must describe all resources.
    pub unsafe fn publish(self) -> OwnedInitialized<T, A> {
        OwnedInitialized { record: self }
    }
}

impl<T: Reclaim<A>, A: Allocator> Drop for OwnedRecord<T, A> {
    fn drop(&mut self) {
        // A real, short-lived borrow of the stable scope; no lifetime erasure.
        drop(Record {
            block: self.block,
            owner: self.scope.owner(),
            marker: PhantomData::<(T, fn(T) -> T)>,
        });
    }
}

pub struct OwnedInitialized<T: Reclaim<A>, A: Allocator> {
    record: OwnedRecord<T, A>,
}

impl<T: Reclaim<A>, A: Allocator> OwnedInitialized<T, A> {
    pub(crate) fn scope(&self) -> OwnedReclaimer<A> {
        self.record.scope.duplicate()
    }
    pub fn value(&self) -> &T {
        unsafe { (&*ptr::addr_of!((*self.record.block.as_ptr()).value)).assume_init_ref() }
    }
}
