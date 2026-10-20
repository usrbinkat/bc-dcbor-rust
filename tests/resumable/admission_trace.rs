use super::{Call, Refusal};
use dcbor::bounded::decode::construction::TypedPosition;

#[derive(Clone, Copy, Debug)]
pub struct Admission {
    pub index: usize,
    pub call: Call,
    pub result: Result<(), Refusal>,
    pub work: (u64, u64),
    pub capacity: (u64, u64),
    pub position: Option<TypedPosition>,
}

/// Fixed storage: observing an allocation must not allocate itself. Preserve
/// the first refusal separately so long resumptions cannot overwrite its cause.
pub struct AdmissionTrace {
    recent: [Option<Admission>; 32],
    count: usize,
    first_refusal: Option<Admission>,
    context: Option<TypedPosition>,
}

impl AdmissionTrace {
    pub const fn new() -> Self {
        Self {
            recent: [None; 32],
            count: 0,
            first_refusal: None,
            context: None,
        }
    }

    pub fn context(&mut self, position: TypedPosition) {
        self.context = Some(position);
    }

    pub fn record(
        &mut self,
        index: usize,
        call: Call,
        result: Result<(), Refusal>,
        work: (u64, u64),
        capacity: (u64, u64),
    ) {
        let event = Admission {
            index,
            call,
            result,
            work,
            capacity,
            position: self.context,
        };
        if result.is_err() && self.first_refusal.is_none() {
            self.first_refusal = Some(event);
        }
        self.recent[self.count % self.recent.len()] = Some(event);
        self.count += 1;
    }

    pub fn assert_calls(&self, actual: &[Call], expected: &[Call], schedule: usize) {
        if actual == expected {
            return;
        }
        let at = actual
            .iter()
            .zip(expected)
            .position(|(a, b)| a != b)
            .unwrap_or(actual.len().min(expected.len()));
        let start = at.saturating_sub(2);
        panic!(
            "admission replay: schedule={schedule}, first_difference={at}, actual_len={}, expected_len={}\nactual_window={:?}\nexpected_window={:?}\n{self:?}",
            actual.len(),
            expected.len(),
            &actual[start..actual.len().min(at + 4)],
            &expected[start..expected.len().min(at + 4)]
        );
    }
}

impl core::fmt::Debug for AdmissionTrace {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(
            f,
            "first_refusal={:?}; total_events={}",
            self.first_refusal, self.count
        )?;
        for index in self.count.saturating_sub(self.recent.len())..self.count {
            if let Some(event) = self.recent[index % self.recent.len()] {
                writeln!(
                    f,
                    "call={} {:?} -> {:?}; admitted_work={:?}; live_peak={:?}; before={:?}",
                    event.index,
                    event.call,
                    event.result,
                    event.work,
                    event.capacity,
                    event.position
                )?;
            }
        }
        Ok(())
    }
}
