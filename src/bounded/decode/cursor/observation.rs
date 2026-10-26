use super::super::storage::StoragePosition;
use super::*;

/// Read-only resource custody at the parser boundary. No allocation or traversal
/// is performed, including during staged normalizer initialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Resources {
    pub entries: StoragePosition,
    pub stack: StoragePosition,
    pub normalizer_initialized: usize,
    pub normalizer_initialization_steps: usize,
    /// Present only after every normalizer field has been initialized.
    pub normalizer: Option<text_cursor::Position>,
    /// An empty output and no output are distinct custody states.
    pub normalized_output: bool,
    pub normalized_bytes: usize,
}

impl<I, P> ParserContinuation<I, P> {
    pub fn resources(&self) -> Resources {
        Resources {
            entries: self.entries.position(),
            stack: self.stack.position(),
            normalizer_initialized: self.normalizer_init,
            normalizer_initialization_steps: TextContinuation::<(), P>::INIT_STEPS,
            normalizer: if self.normalizer_init == TextContinuation::<(), P>::INIT_STEPS {
                // SAFETY: the retained prefix proves every field is initialized.
                // An incomplete prefix is never dereferenced by observation.
                Some(unsafe { self.normalizer.assume_init_ref() }.position())
            } else {
                None
            },
            normalized_output: self.normalized.is_some(),
            normalized_bytes: self
                .normalized
                .as_ref()
                .map_or(0, |bytes| bytes.as_ref().len()),
        }
    }
}
