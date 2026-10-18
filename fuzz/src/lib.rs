//! Bounded-size property runners. Specification fixtures remain authoritative;
//! symbolic comparison here supplements value, length and resource assertions.
use dcbor::bounded::*;
use std::{cell::Cell, rc::Rc};

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    Scheduled,
    Limit,
}

struct Permit {
    live: Rc<Cell<u64>>,
    bytes: u64,
}
impl Drop for Permit {
    fn drop(&mut self) {
        self.live
            .set(self.live.get().checked_sub(self.bytes).unwrap());
    }
}

struct Policy {
    live: Rc<Cell<u64>>,
    calls: usize,
    refuse_at: Option<usize>,
    work: WriteWork,
}
impl Policy {
    fn new(refuse_at: Option<usize>) -> Self {
        Self {
            live: Rc::new(Cell::new(0)),
            calls: 0,
            refuse_at,
            work: WriteWork::default(),
        }
    }
    fn admit(&mut self) -> Result<(), Refusal> {
        let index = self.calls;
        self.calls += 1;
        if Some(index) == self.refuse_at {
            Err(Refusal::Scheduled)
        } else {
            Ok(())
        }
    }
}
impl Budget for Policy {
    type Refusal = Refusal;
    fn traverse(&mut self, values: u64, bytes: u64) -> Result<(), Refusal> {
        self.admit()?;
        let work = self
            .work
            .then::<()>(WriteWork::new(values, bytes))
            .map_err(|_| Refusal::Limit)?;
        if work.values > 2_000_000 || work.bytes > 32_000_000 {
            return Err(Refusal::Limit);
        }
        self.work = work;
        Ok(())
    }
}
impl Allocator for Policy {
    type Permit = Permit;
    fn allocate(&mut self, bytes: u64) -> Result<Permit, Refusal> {
        self.admit()?;
        let live = self.live.get().checked_add(bytes).ok_or(Refusal::Limit)?;
        if live > 4_000_000 {
            return Err(Refusal::Limit);
        }
        self.live.set(live);
        Ok(Permit {
            live: self.live.clone(),
            bytes,
        })
    }
}

fn expected_failure(error: BoundedError<Refusal>, policy: &Policy) {
    match error {
        BoundedError::Refused(Refusal::Scheduled) => {
            assert_eq!(Some(policy.calls - 1), policy.refuse_at);
        }
        BoundedError::Refused(Refusal::Limit) => {}
        other => panic!("encoding invariant failed: {other:?}"),
    }
}

/// Output storage and its reservation share one owner, with storage dropped
/// first. Failed attempts never publish partial output.
struct OutputStorage {
    bytes: Vec<u8>,
    _permit: Permit,
}

pub fn exercise<T: BoundedEncodable + ?Sized>(value: &T, expected: &[u8], refusal: Option<usize>) {
    // Select the phase independently. Reusing one refusal index in both
    // passes can stop preparation before the write refusal is ever reached.
    let preparation_refusal = refusal
        .filter(|index| index % 2 == 0)
        .map(|index| index / 2);
    let write_refusal = refusal
        .filter(|index| index % 2 != 0)
        .map(|index| index / 2);
    let mut allocator = Policy::new(preparation_refusal);
    let live = allocator.live.clone();
    let result = prepare(value, &mut allocator);
    match result {
        Err(error) => expected_failure(error, &allocator),
        Ok(prepared) => {
            assert_eq!(prepared.len(), u64::try_from(expected.len()).unwrap());
            let size = usize::try_from(prepared.len()).unwrap();
            // The output reservation is admitted before the fallible heap call.
            // Keep it separate from the injected scratch schedule.
            let mut output_policy = Policy::new(None);
            let output_live = output_policy.live.clone();
            let permit = output_policy.allocate(prepared.len()).unwrap();
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(size).unwrap();
            output_policy.traverse(0, prepared.len()).unwrap();
            bytes.resize(size, 0xee);
            let mut output = OutputStorage {
                bytes,
                _permit: permit,
            };
            let mut budget = Policy::new(write_refusal);
            match prepared.encode_into(&mut output.bytes, &mut budget) {
                Ok(()) => {
                    assert_eq!(output.bytes, expected);
                    assert!(prepared.write_work().covers(&budget.work));
                    assert_eq!(
                        dcbor::CBOR::try_from_data(&output.bytes)
                            .unwrap()
                            .to_cbor_data(),
                        expected
                    );
                }
                Err(error) => expected_failure(error, &budget),
            }
            // Each encode attempt starts with a fresh cursor, including after
            // refusal. Retry must be canonical and exactly measured.
            let mut retry = Policy::new(None);
            prepared.encode_into(&mut output.bytes, &mut retry).unwrap();
            assert_eq!(output.bytes, expected);
            assert!(prepared.write_work().covers(&retry.work));
            drop(output);
            assert_eq!(output_live.get(), 0);
        }
    }
    assert_eq!(live.get(), 0);
}

pub fn exercise_decode(input: &[u8], refusal: Option<usize>) {
    use dcbor::bounded::decode::{decode, DecodeError};
    let mut policy = Policy::new(refusal);
    match decode(input, 32, &mut policy) {
        Ok(document) => {
            assert_eq!(document.root().encoded(), input);
            // Only successful bounded validation reaches the recursive oracle:
            // its depth is now known and its text is canonical.
            let symbolic = dcbor::CBOR::try_from_data(input).unwrap();
            assert_eq!(symbolic.to_cbor_data(), input);
            assert!(document.node_count() <= input.len());
        }
        Err(DecodeError::Resource(error)) => expected_failure(error, &policy),
        Err(DecodeError::Invalid(_) | DecodeError::DepthLimit { .. }) => {}
    }
    assert_eq!(policy.live.get(), 0);
}
