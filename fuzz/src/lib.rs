//! Bounded-size property runners. Specification fixtures remain authoritative;
//! symbolic comparison here supplements value, length and resource assertions.
use dcbor::bounded::*;
use dcbor_test_support as support;
mod maps;
mod schema;
pub use schema::exercise_schema_schedule;

/// The fuzzing policy: 2M values and 32M bytes of work, 4M live bytes, and a
/// scheduled refusal of attempted call `refuse_at`.
fn policy(refuse_at: Option<usize>) -> Limits {
    Limits::new(2_000_000, 32_000_000, 4_000_000).refusing(refuse_at)
}

/// Panic unless one step, run under a cumulative allowance, admitted at most
/// one quantum of work by itself.
fn within_turn(before: WriteWork, after: WriteWork) {
    assert!(after.values >= before.values && after.bytes >= before.bytes);
    assert!(after.values - before.values <= TURN.values);
    assert!(after.bytes - before.bytes <= TURN.bytes);
}

/// A refusal is either the scheduled one, at exactly the scheduled call, or a
/// work or storage limit. Anything else is an encoder invariant failure.
fn expected_failure(error: BoundedError<LimitRefusal>, policy: &Limits, scheduled: Option<usize>) {
    match error {
        BoundedError::Refused(LimitRefusal::Scheduled(at)) => {
            assert_eq!(Some(at), scheduled);
            assert_eq!(at, policy.attempts() - 1);
        }
        BoundedError::Refused(LimitRefusal::Work | LimitRefusal::Storage) => {}
        other => panic!("encoding invariant failed: {other:?}"),
    }
}

/// Prepare `value`, write its plan into caller-owned output
/// ([`Prepared::encode_owned`]), possibly refused and then retried, and
/// publish the plan in place ([`Prepared::publish`]): every output is
/// `expected`, within the write bound, and published only once complete;
/// every reservation is released with its owner.
pub fn exercise<T: Schema + ?Sized>(value: &T, expected: &[u8], refusal: Option<usize>) {
    // Select the phase independently. Reusing one refusal index in both
    // passes can stop preparation before the write refusal is ever reached.
    let preparation_refusal = refusal
        .filter(|index| index % 2 == 0)
        .map(|index| index / 2);
    let write_refusal = refusal
        .filter(|index| index % 2 != 0)
        .map(|index| index / 2);
    let mut allocator = policy(preparation_refusal);
    let result = prepare(value, &mut allocator);
    match result {
        Err(error) => expected_failure(error, &allocator, preparation_refusal),
        Ok(prepared) => {
            assert_eq!(prepared.len(), expected.len());
            let len = u64::try_from(prepared.len()).unwrap();
            let write = prepared.write_work::<()>().unwrap();
            // The output reservation is admitted under its own policy, apart
            // from the injected schedules, before its storage is allocated.
            let mut output_policy = policy(None);
            let permit = output_policy.allocate(len).unwrap();
            let mut budget = policy(write_refusal);
            match prepared.encode_owned(permit, &mut budget) {
                Ok(encoded) => {
                    assert_eq!(encoded.as_ref(), expected);
                    assert!(write.covers(&budget.used()));
                    assert_eq!(
                        dcbor::CBOR::try_from_data(encoded.as_ref())
                            .unwrap()
                            .to_cbor_data(),
                        expected
                    );
                }
                Err(error) => expected_failure(error, &budget, write_refusal),
            }
            assert_eq!(output_policy.live_bytes(), 0);
            // Each write starts with a fresh writer, including after a
            // refusal. Retry must be canonical and within the write bound.
            let permit = output_policy.allocate(len).unwrap();
            let mut retry = policy(None);
            let encoded = prepared.encode_owned(permit, &mut retry).unwrap();
            assert_eq!(encoded.as_ref(), expected);
            assert!(write.covers(&retry.used()));
            drop(encoded);
            assert_eq!(output_policy.live_bytes(), 0);
            // The plan's own arena published in place as the encoding.
            let mut publishing = policy(None);
            let published = prepared.publish(&mut publishing).unwrap();
            assert_eq!(published.as_ref(), expected);
            assert!(write.covers(&publishing.used()));
            assert!(allocator.live_bytes() >= len);
            drop(published);
        }
    }
    assert_eq!(allocator.live_bytes(), 0);
}

pub fn exercise_decode(input: &[u8], refusal: Option<usize>) {
    use dcbor::bounded::decode::{DecodeError, decode};
    let mut policy = policy(refusal);
    match decode(input, 32, &mut policy) {
        Ok(document) => {
            assert_eq!(document.root().encoded(), input);
            // Only successful bounded validation reaches the recursive oracle:
            // its depth is now known and its text is canonical.
            let symbolic = dcbor::CBOR::try_from_data(input).unwrap();
            assert_eq!(symbolic.to_cbor_data(), input);
            assert!(document.node_count() <= input.len());
        }
        Err(DecodeError::Resource(error)) => expected_failure(error, &policy, refusal),
        Err(DecodeError::Invalid(_) | DecodeError::DepthLimit { .. }) => {}
        Err(DecodeError::UnprovenText) => panic!("normalizing policy returned QuickOnly refusal"),
    }
    assert_eq!(policy.live_bytes(), 0);
}

/// Arbitrary malformed inputs, every proper prefix of a bounded sample, and a
/// selected actual refusal. The recursive oracle only sees validated depth.
pub fn exercise_decode_schedule(data: &[u8]) {
    let Some((&schedule, input)) = data.split_first() else {
        return;
    };
    let input = &input[..input.len().min(4096)];
    retained_schedule(input, schedule as usize);
    for end in 0..input.len().min(64) {
        retained_schedule(&input[..end], schedule as usize + end);
    }
    if !input.is_empty() {
        let mut mutation = input.to_vec();
        let at = schedule as usize % mutation.len();
        mutation[at] ^= 1 << (schedule % 8);
        retained_schedule(&mutation, schedule as usize);
    }
}

fn retained_schedule(input: &[u8], schedule: usize) {
    use dcbor::bounded::decode::{DecodeError, Options, cursor::Decoder};
    /// The terminal outcome of one retained decode: published, invalid,
    /// beyond the depth limit, refused by a policy limit, or cancelled.
    #[derive(Debug, PartialEq, Eq)]
    enum Terminal {
        Published,
        Invalid,
        Depth,
        Limit,
        Cancelled,
    }
    fn run(input: &[u8], stop: Option<usize>, cancel: bool) -> (usize, WriteWork, Terminal) {
        let mut policy = policy(stop);
        let mut operation = Decoder::new(input, Options::normalizing(32));
        let mut observed = false;
        let mut terminal = None;
        for _ in 0..support::decode_turns(input.len()) {
            let before = policy.used();
            let outcome = support::contracted(&mut policy, &mut operation);
            within_turn(before, policy.used());
            match outcome {
                Ok(Step::Progress) => {}
                Ok(Step::Complete(document)) => {
                    support::exhausted(&mut policy, &mut operation);
                    assert_eq!(document.root().encoded(), input);
                    let expected = dcbor::CBOR::try_from_data(input).unwrap();
                    assert_eq!(expected.to_cbor_data(), input);
                    let held = policy.live_bytes();
                    drop(operation);
                    assert_eq!(policy.live_bytes(), held);
                    drop(document);
                    assert_eq!(policy.live_bytes(), 0);
                    assert_eq!(observed, stop.is_some());
                    return (policy.attempts(), policy.used(), Terminal::Published);
                }
                Err(DecodeError::Resource(BoundedError::Refused(LimitRefusal::Scheduled(at)))) => {
                    assert_eq!(Some(at), stop);
                    assert_eq!(at, policy.attempts() - 1);
                    assert!(!observed);
                    observed = true;
                    policy.fail_call(None);
                    if cancel {
                        terminal = Some(Terminal::Cancelled);
                        break;
                    }
                }
                Err(DecodeError::Invalid(_)) => {
                    terminal = Some(Terminal::Invalid);
                    break;
                }
                Err(DecodeError::DepthLimit { .. }) => {
                    terminal = Some(Terminal::Depth);
                    break;
                }
                Err(DecodeError::Resource(BoundedError::Refused(
                    LimitRefusal::Work | LimitRefusal::Storage,
                ))) => {
                    terminal = Some(Terminal::Limit);
                    break;
                }
                other => panic!(
                    "unexpected retained decode outcome {} at {:?}",
                    support::label(&other),
                    operation.position()
                ),
            }
        }
        let terminal = terminal.expect("bounded retained decode failed to terminate");
        assert_eq!(observed, stop.is_some());
        drop(operation);
        assert_eq!(policy.live_bytes(), 0);
        (policy.attempts(), policy.used(), terminal)
    }
    let baseline = run(input, None, false);
    assert!(baseline.0 > 0);
    let stop = schedule % baseline.0;
    let resumed = run(input, Some(stop), false);
    assert_eq!(resumed.0, baseline.0 + 1);
    assert_eq!(
        resumed.1, baseline.1,
        "completed work replayed after refusal"
    );
    assert_eq!(resumed.2, baseline.2);
    run(input, Some(stop), true);
}
