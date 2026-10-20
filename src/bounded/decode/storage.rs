//! Retained arena relocation. Both allocations keep their permits while a
//! move is suspended; each admitted turn moves at most one element.
use super::super::*;

struct Moving<T, P> {
    // Field order frees the old allocation before releasing its permit.
    remaining: <Vec<T> as IntoIterator>::IntoIter,
    _permit: Option<P>,
}

/// Storage used by retained parser stages. Access is available only when
/// relocation has completed, so partial moves cannot escape as a document.
pub struct Storage<T, P> {
    value: Owned<T, P>,
    moving: Option<Moving<T, P>>,
}

/// Constant-time storage observations, including interrupted relocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoragePosition {
    pub initialized: usize,
    pub reserved_capacity: usize,
    pub physical_capacity: usize,
    pub relocating_remaining: usize,
    pub has_current_permit: bool,
    pub has_relocation: bool,
}

impl<T, P> Storage<T, P> {
    pub fn position(&self) -> StoragePosition {
        StoragePosition {
            initialized: self.value.items.len(),
            reserved_capacity: self.value.capacity,
            physical_capacity: self.value.items.capacity(),
            relocating_remaining: self
                .moving
                .as_ref()
                .map_or(0, |moving| moving.remaining.len()),
            has_current_permit: self.value.permit.is_some(),
            has_relocation: self.moving.is_some(),
        }
    }

    pub(crate) const INIT_STEPS: usize = 4;

    /// Initialize one empty metadata field directly in its final destination.
    /// Partial initialization owns no resources and may be abandoned without Drop.
    ///
    /// # Safety
    /// The destination is unique and stable; step starts at zero and is retained.
    pub(crate) unsafe fn initialize_step<A: Allocator<Permit = P>>(
        place: *mut Self,
        step: &mut usize,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        use super::initialization::field;
        use core::ptr::addr_of_mut;
        unsafe {
            match *step {
                0 => field(addr_of_mut!((*place).value.items), Vec::new, a)?,
                1 => field(addr_of_mut!((*place).value.capacity), || 0, a)?,
                2 => field(addr_of_mut!((*place).value.permit), || None, a)?,
                3 => field(addr_of_mut!((*place).moving), || None, a)?,
                _ => return Err(BoundedError::PlanMismatch),
            }
        }
        *step += 1;
        Ok(*step == Self::INIT_STEPS)
    }

    pub const fn new() -> Self {
        Self {
            value: Owned::new(),
            moving: None,
        }
    }

    pub fn len(&self) -> usize {
        self.value.len()
            + self
                .moving
                .as_ref()
                .map_or(0, |moving| moving.remaining.len())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn relocated(&self) -> usize {
        self.value.len()
    }

    pub fn ready(&self) -> Option<&[T]> {
        self.moving.is_none().then(|| self.value.as_slice())
    }

    pub(crate) fn ready_mut(&mut self) -> Option<&mut [T]> {
        if self.moving.is_some() {
            None
        } else {
            Some(&mut self.value.items)
        }
    }

    pub(crate) fn pop_ready(&mut self) -> Option<T> {
        if self.moving.is_some() {
            None
        } else {
            self.value.items.pop()
        }
    }

    /// Remove at most one value, including during an interrupted relocation.
    ///
    /// Both backing allocations and their permits remain owned by this storage.
    /// The caller must finish destroying the returned value before releasing
    /// this storage. Removal does not bound the returned value's destructor;
    /// nested values require their own retained cleanup operation.
    pub fn drain_step<A: Allocator<Permit = P>>(
        &mut self,
        allocator: &mut A,
    ) -> BoundedResult<Option<T>, A> {
        if self.is_empty() {
            return Ok(None);
        }
        allocator
            .traverse(1, widen(core::mem::size_of::<T>())?)
            .map_err(BoundedError::Refused)?;
        if let Some(value) = self.value.items.pop() {
            return Ok(Some(value));
        }
        Ok(self
            .moving
            .as_mut()
            .and_then(|moving| moving.remaining.next_back()))
    }

    /// Release one empty backing allocation and then its permit. Values must
    /// first be drained and their cleanup completed by the caller. Returns true
    /// only after both sides of an interrupted relocation have been released.
    pub fn release_step<A: Allocator<Permit = P>>(
        &mut self,
        allocator: &mut A,
    ) -> BoundedResult<bool, A> {
        if !self.is_empty() {
            return Err(BoundedError::PlanMismatch);
        }
        let bytes = if self.moving.is_some() {
            core::mem::size_of::<Option<Moving<T, P>>>()
        } else if self.value.capacity != 0 || self.value.permit.is_some() {
            core::mem::size_of::<Owned<T, P>>()
        } else {
            return Ok(true);
        };
        if bytes > 64 {
            return Err(BoundedError::PlanMismatch);
        }
        allocator
            .traverse(1, bytes as u64)
            .map_err(BoundedError::Refused)?;
        if self.moving.is_some() {
            self.moving = None;
            return Ok(false);
        }
        if self.value.capacity != 0 || self.value.permit.is_some() {
            self.value = Owned::new();
        }
        Ok(true)
    }

    /// Release storage as part of a caller's phase transition. Even when no
    /// allocation exists, admit the caller's state change before returning true.
    /// The caller must commit that transition immediately on success.
    pub(crate) fn release_transition_step<A: Allocator<Permit = P>>(
        &mut self,
        allocator: &mut A,
    ) -> BoundedResult<bool, A> {
        if self.is_empty()
            && self.moving.is_none()
            && self.value.capacity == 0
            && self.value.permit.is_none()
        {
            allocator.traverse(1, 0).map_err(BoundedError::Refused)?;
            return Ok(true);
        }
        self.release_step(allocator)
    }

    /// Reserve one slot, performing at most one element move. Returns true
    /// only once the slot and every previously stored element are accessible.
    pub fn reserve_step<A: Allocator<Permit = P>>(
        &mut self,
        allocator: &mut A,
    ) -> BoundedResult<bool, A> {
        self.reserve_capped_step(usize::MAX, allocator)
    }

    /// Reserve one slot without growing the allocation beyond `maximum`.
    /// Existing allocations are retained; callers choose a nondecreasing cap.
    pub(crate) fn reserve_capped_step<A: Allocator<Permit = P>>(
        &mut self,
        maximum: usize,
        allocator: &mut A,
    ) -> BoundedResult<bool, A> {
        if let Some(moving) = &mut self.moving {
            if !moving.remaining.as_slice().is_empty() {
                let bytes = widen(core::mem::size_of::<T>())?;
                allocator
                    .traverse(1, bytes)
                    .map_err(BoundedError::Refused)?;
                // The nonempty iterator above proves next has one element.
                if let Some(value) = moving.remaining.next() {
                    self.value.items.push(value);
                }
            }
            if moving.remaining.as_slice().is_empty() {
                self.moving = None;
                return Ok(true);
            }
            return Ok(false);
        }
        if self.value.len() < self.value.capacity {
            return Ok(true);
        }
        let grown = if self.value.capacity == 0 {
            4
        } else {
            self.value
                .capacity
                .checked_mul(2)
                .ok_or(BoundedError::Overflow)?
        };
        let grown = grown.min(maximum);
        if grown <= self.value.len() {
            return Err(BoundedError::PlanMismatch);
        }
        let bytes = mul(widen(grown)?, widen(core::mem::size_of::<T>())?)?;
        let permit = allocator.allocate(bytes).map_err(BoundedError::Refused)?;
        let mut replacement = Vec::new();
        replacement
            .try_reserve_exact(grown)
            .map_err(|_| BoundedError::Allocation { bytes })?;
        let old = core::mem::replace(
            &mut self.value,
            Owned {
                items: replacement,
                capacity: grown,
                permit: Some(permit),
            },
        );
        if old.items.is_empty() {
            // No values need relocation; old drops allocation before permit.
            return Ok(true);
        }
        self.moving = Some(Moving {
            remaining: old.items.into_iter(),
            _permit: old.permit,
        });
        Ok(false)
    }

    pub fn push_reserved(&mut self, value: T) -> Result<(), T> {
        if self.moving.is_some() || self.value.len() == self.value.capacity {
            return Err(value);
        }
        self.value.items.push(value);
        Ok(())
    }

    pub fn into_owned(self) -> Result<Owned<T, P>, Self> {
        if self.moving.is_some() {
            Err(self)
        } else {
            Ok(self.value)
        }
    }

    /// # Safety
    /// Destination is stable uninitialized Owned storage. Retain part from zero
    /// and do not use this storage except to finish transfer or reclaim it.
    pub(crate) unsafe fn transfer_step<A: Allocator<Permit = P>>(
        &mut self,
        destination: *mut Owned<T, P>,
        part: &mut usize,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        use core::{mem, ptr::addr_of_mut};
        if self.moving.is_some() {
            return Err(BoundedError::PlanMismatch);
        }
        let bytes = match *part {
            0 => 2 * mem::size_of::<Vec<T>>(),
            1 => 2 * mem::size_of::<usize>(),
            2 => 2 * mem::size_of::<Option<P>>(),
            _ => return Err(BoundedError::PlanMismatch),
        };
        if bytes > 64 {
            return Err(BoundedError::PlanMismatch);
        }
        a.traverse(1, bytes as u64).map_err(BoundedError::Refused)?;
        unsafe {
            match *part {
                0 => addr_of_mut!((*destination).items).write(mem::take(&mut self.value.items)),
                1 => {
                    addr_of_mut!((*destination).capacity).write(mem::take(&mut self.value.capacity))
                }
                2 => addr_of_mut!((*destination).permit).write(self.value.permit.take()),
                _ => unreachable!("validated transfer part"),
            }
        }
        *part += 1;
        Ok(*part == 3)
    }
}

impl<T, P> Default for Storage<T, P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy, P> Storage<T, P> {
    /// Discard plain data without walking it. Copy excludes destructors; the
    /// allocation and its reservation remain owned until explicit release.
    pub fn truncate_copy_step<A: Allocator<Permit = P>>(
        &mut self,
        len: usize,
        a: &mut A,
    ) -> BoundedResult<(), A> {
        if self.moving.is_some() || len > self.value.len() {
            return Err(BoundedError::PlanMismatch);
        }
        a.traverse(1, 0).map_err(BoundedError::Refused)?;
        self.value.items.truncate(len);
        Ok(())
    }

    pub(crate) fn spare_ready(&self) -> usize {
        if self.moving.is_some() {
            0
        } else {
            self.value.capacity - self.value.len()
        }
    }

    pub(crate) fn extend_reserved(&mut self, values: &[T]) -> Result<(), ()> {
        if values.len() > self.spare_ready() {
            return Err(());
        }
        self.value.items.extend_from_slice(values);
        Ok(())
    }
}
