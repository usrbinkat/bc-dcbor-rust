use dcbor::bounded::resumable::{
    Budget, Decode, Event, Fault, Limits, Outcome, Policy, Pool, Snapshot, Value,
};

pub const QUANTUM: u64 = 64;

pub fn policy() -> Policy {
    Policy::canonical().max_depth(64)
}

pub fn budget() -> Budget {
    Budget::new(Limits {
        values: 3,
        bytes: QUANTUM,
        allocated: 4096,
    })
}

pub fn pool() -> Pool {
    Pool::new(32 * 1024 * 1024)
}

pub fn decoder(bytes: &[u8], pool: &Pool) -> Decode {
    Decode::new(bytes.to_vec().into_boxed_slice(), policy(), pool.clone())
        .expect("fixture input ownership")
}

pub fn finish(decoder: &mut Decode) -> Value {
    // Finite watchdog based on fixture extent, not a wall clock or retries
    // after an error. Each Progress outcome must certify useful advancement.
    let max = decoder.input_len().checked_mul(128).unwrap() + 4096;
    for _ in 0..max {
        let before = decoder.snapshot();
        let mut allowance = budget();
        let bound = decoder.next_unit().unwrap();
        let outcome = decoder.step(&mut allowance);
        assert!(allowance.consumed().within(allowance.limits()));
        assert!(bound.work.covers(allowance.consumed()));
        match outcome {
            Outcome::Progress => {
                assert!(decoder.snapshot().completed_units > before.completed_units);
            }
            Outcome::Complete(value) => {
                assert_no_replay(decoder.events());
                assert_eq!(decoder.completion_count(), 1);
                return value;
            }
            other => panic!("unexpected outcome {other:?}; {before:?}"),
        }
    }
    panic!("no completion: {:?}", decoder.snapshot());
}

pub fn assert_no_replay(events: &[Event]) {
    let mut completed = std::collections::BTreeSet::new();
    let mut ranges = 0;
    for event in events {
        if let Event::Completed {
            operation,
            start,
            end,
        } = event
        {
            ranges += 1;
            assert!(end > start, "empty completed operation");
            for position in *start..*end {
                assert!(
                    completed.insert((*operation, position)),
                    "replayed completed operation: {event:?}"
                );
            }
        }
    }
    assert!(
        ranges > 0,
        "empty instrumentation cannot prove useful progress"
    );
}

pub fn unchanged(before: &Snapshot, after: &Snapshot) {
    assert_eq!(before, after, "refused unit changed semantic state");
}

pub fn byte_string(length: usize) -> Vec<u8> {
    assert!(length <= u32::MAX as usize);
    let mut bytes = vec![0x5a];
    bytes.extend_from_slice(&(length as u32).to_be_bytes());
    bytes.extend((0..length).map(|i| (i % 251) as u8));
    bytes
}

pub fn text_wire(text: &str) -> Vec<u8> {
    let n = text.len();
    let mut out = if n < 24 {
        vec![0x60 | n as u8]
    } else if n <= 255 {
        vec![0x78, n as u8]
    } else if n <= 65535 {
        vec![0x79, (n >> 8) as u8, n as u8]
    } else {
        let mut head = vec![0x7a];
        head.extend_from_slice(&u32::try_from(n).unwrap().to_be_bytes());
        head
    };
    out.extend_from_slice(text.as_bytes());
    out
}

pub fn assert_invalid(bytes: &[u8]) {
    let pool = pool();
    let mut decode = decoder(bytes, &pool);
    for _ in 0..bytes.len() * 128 + 4096 {
        let before = decode.snapshot();
        let mut allowance = budget();
        let outcome = decode.step(&mut allowance);
        assert!(allowance.consumed().within(allowance.limits()));
        match outcome {
            Outcome::Progress => {
                assert!(decode.snapshot().completed_units > before.completed_units);
                continue;
            }
            Outcome::Invalid(_) => {
                assert_eq!(decode.completion_count(), 0);
                let before = decode.snapshot();
                assert!(matches!(decode.step(&mut budget()), Outcome::Invalid(_)));
                unchanged(&before, &decode.snapshot());
                drop(decode);
                assert_eq!(pool.live(), 0);
                return;
            }
            other => panic!("invalid input accepted or deferred: {bytes:x?}: {other:?}"),
        }
    }
    panic!("invalid input failed to terminate");
}

pub fn refuse_each(bytes: &[u8], fault: Fault) {
    let baseline_pool = pool();
    let mut baseline = decoder(bytes, &baseline_pool);
    let expected = finish(&mut baseline);
    let boundaries = baseline.snapshot().admission_points;
    assert!(boundaries > 0);
    for index in 0..boundaries {
        let pool = pool();
        let mut decode = decoder(bytes, &pool);
        decode.inject_once(index, fault);
        let mut fired = false;
        for _ in 0..bytes.len() * 128 + 4096 {
            let before = decode.snapshot();
            let bound = decode.next_unit().unwrap();
            let mut allowance = budget();
            let outcome = decode.step(&mut allowance);
            assert!(allowance.consumed().within(allowance.limits()));
            assert!(bound.work.covers(allowance.consumed()));
            assert!(pool.live() <= pool.capacity());
            match outcome {
                Outcome::Progress => {
                    assert!(decode.snapshot().completed_units > before.completed_units);
                }
                Outcome::Refused(reason) => {
                    assert_eq!(reason, fault);
                    assert!(!fired);
                    fired = true;
                    unchanged(&before, &decode.snapshot());
                }
                Outcome::Complete(value) => {
                    assert!(fired, "injection {index} never fired");
                    assert_eq!(value, expected);
                    assert_no_replay(decode.events());
                    drop(value);
                    break;
                }
                other => panic!("boundary {index}: {other:?}"),
            }
        }
        assert!(decode.is_complete(), "boundary {index} stalled");
        drop(decode);
        assert_eq!(pool.live(), 0);
    }
    drop(baseline);
    assert!(baseline_pool.live() > 0, "completed fixture owns storage");
    drop(expected);
    assert_eq!(baseline_pool.live(), 0);
}
