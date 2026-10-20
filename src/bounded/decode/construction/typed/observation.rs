use super::*;

/// Allocation-free observation of retained lifecycle state. Counters describe
/// committed progress, not work allowances. Reading this never advances cleanup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TypedPosition {
    pub phase: &'static str,
    pub initialized: usize,
    pub initialization_steps: usize,
    pub document_initialized: usize,
    pub document_released: usize,
    pub build_position: usize,
    pub build_has_state: bool,
    pub parser: Option<Position>,
    pub resources: Option<crate::bounded::decode::cursor::Resources>,
    pub outstanding_records: usize,
    pub aborting: bool,
    pub finished: bool,
}

impl<T: InPlace<A>, A: Allocator> TypedDecoder<'_, '_, T, A> {
    pub fn position(&mut self) -> TypedPosition {
        let mut position = TypedPosition {
            phase: if self.finished {
                "Finished"
            } else {
                "Allocate"
            },
            initialized: 0,
            initialization_steps: State::<T, A::Permit>::INIT_STEPS,
            document_initialized: 0,
            document_released: 0,
            build_position: 0,
            build_has_state: false,
            parser: None,
            resources: None,
            outstanding_records: self.owner.outstanding(),
            aborting: self.aborting,
            finished: self.finished,
        };
        let Some(record) = self.record.as_mut() else {
            return position;
        };
        // SAFETY: the controller exclusively owns the record. Read metadata only
        // after its retained initialization cursor proves the entire prefix valid.
        let (place, cursor) = unsafe { record.destination() };
        position.initialized = cursor.position;
        if cursor.position < position.initialization_steps {
            position.phase = "Initialize";
            return position;
        }
        let state = unsafe { &*place.as_ptr().cast::<State<'_, T, A::Permit>>() };
        position.phase = match state.phase {
            Phase::Parse => "Parse",
            Phase::Transfer => "Transfer",
            Phase::Build => "Build",
            Phase::ReleaseDocument => "ReleaseDocument",
            Phase::ReleaseParser => "ReleaseParser",
            Phase::Publish => "Publish",
            Phase::ReclaimValue => "ReclaimValue",
            Phase::ReclaimDocument => "ReclaimDocument",
            Phase::ReclaimParser => "ReclaimParser",
            Phase::Done => "Done",
        };
        position.document_initialized = state.document_initialized;
        position.document_released = state.document_released;
        position.build_position = state.build.position;
        position.build_has_state = state.build.state != 0;
        position.parser = Some(unsafe { state.parser.assume_init_ref() }.position());
        position.resources = Some(unsafe { state.parser.assume_init_ref() }.resources());
        position
    }
}
