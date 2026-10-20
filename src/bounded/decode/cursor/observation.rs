use super::super::storage::StoragePosition;
use super::*;

/// Read-only resource custody at the parser boundary. No allocation or traversal
/// is performed, including during staged normalizer initialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resources {
    pub entries: StoragePosition,
    pub stack: StoragePosition,
    pub normalizer_initialized: usize,
    pub normalizer_initialization_steps: usize,
    pub normalized_bytes: usize,
}

impl<P> Decoder<'_, P> {
    pub fn resources(&self) -> Resources {
        Resources {
            entries: self.entries.position(),
            stack: self.stack.position(),
            normalizer_initialized: self.normalizer_init,
            normalizer_initialization_steps: TextEncoder::<P>::INIT_STEPS,
            normalized_bytes: self
                .normalized
                .as_ref()
                .map_or(0, |bytes| bytes.as_ref().len()),
        }
    }
}
