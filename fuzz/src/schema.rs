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
        text: seed.is_multiple_of(2).then(|| String::from_utf8_lossy(data).into_owned()),
        children: data.chunks(17).map(|chunk| chunk.to_vec()).collect(),
        number: data
            .iter()
            .take(8)
            .fold(0u64, |n, byte| (n << 8) | u64::from(*byte)),
    };
    let expected = support::recorded_run(|run| {
        let policy = run.policy(4_000_000);
        let encoded = run.with_policy(policy, |m| encode(&source, m).unwrap());
        Ok(run.holding(
            encoded,
            support::Retirement::Released,
            &support::pipeline::Unwitnessed,
            |encoded| encoded.value().as_ref().to_vec(),
        ))
    });
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
    let run = |stop: Option<usize>, cancel| {
        support::recorded_run(|run| {
            let policy = run.policy(4_000_000);
            let writing = run.policy(4_000_000);
            run.holding(
                Preparation::new(source),
                support::Retirement::Released,
                &support::pipeline::Unwitnessed,
                |cursor| {
                    cursor
                        .drive_faulted(
                            policy,
                            bound,
                            support::Retirement::Released,
                            support::Fault {
                                refusal: stop.map_or(
                                    support::pipeline::Refusal::None,
                                    support::pipeline::Refusal::At,
                                ),
                                cancel,
                            },
                            |_, _| {},
                            |plan| {
                                let len = plan.value().len();
                                let mut bytes = vec![0xee; len];
                                plan.lending(
                                    support::Retirement::Released,
                                    |plan| plan.writer(&mut bytes),
                                    |writer| {
                                        writer.drive(
                                            writing,
                                            support::emit_turns(len),
                                            support::Retirement::Released,
                                            |_| (),
                                        )
                                    },
                                )?;
                                assert_eq!(bytes, expected);
                                Ok::<_, support::Finding>(())
                            },
                        )?
                        .transpose()
                },
            )?;
            Ok(run.with_policy(policy, |m| {
                assert_eq!(m.injected_refusals(), usize::from(stop.is_some()));
                assert_eq!(m.live_bytes(), 0);
                (m.attempts(), m.used())
            }))
        })
    };
    let baseline = run(None, false);
    let stop = Some(seed % baseline.0);
    let resumed = run(stop, false);
    assert_eq!(resumed.0, baseline.0 + 1);
    assert_eq!(resumed.1, baseline.1);
    run(stop, true);
}
