use super::*;
use dcbor::bounded::encoding::Preparation;

#[derive(dcbor::CBORBoundedEncodable)]
struct Record {
    #[cbor(n = 24)]
    text: Option<String>,
    #[cbor(n = 0)]
    children: Vec<Vec<u8>>,
    #[cbor(n = 256)]
    number: u64,
}

pub fn exercise_schema_schedule(data: &[u8]) {
    let data = &data[..data.len().min(1024)];
    let seed = data.first().copied().unwrap_or(0) as usize;
    let source = Record {
        text: (seed % 2 == 0).then(|| String::from_utf8_lossy(data).into_owned()),
        children: data.chunks(17).map(|chunk| chunk.to_vec()).collect(),
        number: data
            .iter()
            .take(8)
            .fold(0u64, |n, byte| (n << 8) | u64::from(*byte)),
    };
    let expected = encode(&source, &mut policy(None)).unwrap();
    let bound = support::prepare_turns(support::shape(&source));
    scheduled(&source, expected.as_ref(), seed, bound);
    super::maps::exercise(data);
}

/// Prepare `source` within `bound` turns, unrefused, refused at one call
/// selected by `seed` and resumed, and refused there and cancelled; emit each
/// published plan within its own bound. Resumption repeats only the refused
/// call.
pub(super) fn scheduled(
    source: &dyn dcbor::bounded::encoding::Schema,
    expected: &[u8],
    seed: usize,
    bound: usize,
) {
    let run = |stop, cancel| {
        let mut policy = policy(stop);
        let mut cursor = Preparation::new(source);
        let mut observed = false;
        for _ in 0..bound {
            let before = policy.used();
            let result = support::contracted(&mut policy, &mut cursor);
            within_turn(before, policy.used());
            match result {
                Ok(Step::Progress) => {}
                Ok(Step::Complete(plan)) => {
                    support::exhausted(&mut policy, &mut cursor);
                    drop(cursor);
                    let mut bytes = vec![0xee; plan.len()];
                    let mut writer = plan.writer(&mut bytes);
                    let mut budget = super::policy(None);
                    let mut done = false;
                    for _ in 0..support::emit_turns(plan.len()) {
                        let before = budget.used();
                        let step = support::contracted(&mut budget, &mut writer).unwrap();
                        within_turn(before, budget.used());
                        if step == Step::Complete(()) {
                            support::exhausted(&mut budget, &mut writer);
                            done = true;
                            break;
                        }
                    }
                    assert!(done);
                    assert_eq!(bytes, expected);
                    drop(plan);
                    assert_eq!(policy.live_bytes(), 0);
                    assert_eq!(observed, stop.is_some());
                    return (policy.attempts(), policy.used());
                }
                Err(BoundedError::Refused(LimitRefusal::Scheduled(at))) => {
                    assert_eq!(Some(at), stop);
                    assert_eq!(at, policy.attempts() - 1);
                    assert!(!observed);
                    observed = true;
                    policy.fail_call(None);
                    if cancel {
                        drop(cursor);
                        assert_eq!(policy.live_bytes(), 0);
                        return (policy.attempts(), policy.used());
                    }
                }
                _ => panic!("unexpected schema outcome at {:?}", cursor.position()),
            }
        }
        panic!("schema preparation failed to terminate");
    };
    let baseline = run(None, false);
    let stop = Some(seed % baseline.0);
    let resumed = run(stop, false);
    assert_eq!(resumed.0, baseline.0 + 1);
    assert_eq!(resumed.1, baseline.1);
    run(stop, true);
}
