use super::*;
use dcbor::bounded::encoding::{Preparation, PrepareStep};
use dcbor::bounded::text_cursor::pipeline::EmitStep;

#[derive(dcbor::CBORBoundedEncodable, dcbor::CBORResumableEncodable)]
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
    let expected = encode(&source, &mut Limits::new(2_000_000, 32_000_000, 4_000_000)).unwrap();
    scheduled(&source, expected.as_ref(), seed, data.len() * 1024 + 8192);
    super::maps::exercise(data);
}

pub(super) fn scheduled(
    source: &dyn dcbor::bounded::encoding::Schema,
    expected: &[u8],
    seed: usize,
    bound: usize,
) {
    let run = |stop, cancel| {
        let mut policy = Policy::new(stop);
        let mut cursor = Preparation::new(source);
        let mut observed = false;
        for _ in 0..bound {
            let before = policy.work;
            let result = cursor.step(&mut policy);
            assert!(policy.work.values - before.values <= 3);
            assert!(policy.work.bytes - before.bytes <= 64);
            match result {
                Ok(PrepareStep::Progress) => {}
                Ok(PrepareStep::Complete(plan)) => {
                    drop(cursor);
                    let mut bytes = vec![0xee; plan.len()];
                    let mut writer = plan.writer(&mut bytes);
                    let mut budget = Policy::new(None);
                    let mut done = false;
                    for _ in 0..plan.len() * 2 + 64 {
                        let before = budget.work;
                        let step = writer.step(&mut budget).unwrap();
                        assert!(budget.work.values - before.values <= 3);
                        assert!(budget.work.bytes - before.bytes <= 64);
                        if step == EmitStep::Complete {
                            done = true;
                            break;
                        }
                    }
                    assert!(done);
                    assert_eq!(bytes, expected);
                    drop(plan);
                    assert_eq!(policy.live.get(), 0);
                    assert_eq!(observed, stop.is_some());
                    return (policy.calls, policy.work);
                }
                Err(BoundedError::Refused(Refusal::Scheduled)) => {
                    assert_eq!(Some(policy.calls - 1), stop);
                    assert!(!observed);
                    observed = true;
                    policy.refuse_at = None;
                    if cancel {
                        drop(cursor);
                        assert_eq!(policy.live.get(), 0);
                        return (policy.calls, policy.work);
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
