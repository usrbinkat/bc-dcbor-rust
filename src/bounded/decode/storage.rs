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

impl<T, P> Storage<T, P> {
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
        if self.moving.is_some() {
            allocator.traverse(1, 0).map_err(BoundedError::Refused)?;
            self.moving = None;
            return Ok(false);
        }
        if self.value.capacity != 0 {
            allocator.traverse(1, 0).map_err(BoundedError::Refused)?;
            self.value = Owned::new();
        }
        Ok(true)
    }

    /// Reserve one slot, performing at most one element move. Returns true
    /// only once the slot and every previously stored element are accessible.
    pub fn reserve_step<A: Allocator<Permit = P>>(
        &mut self,
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
}

impl<T, P> Default for Storage<T, P> {
    fn default() -> Self {
        Self::new()
    }
}
