use super::harness::*;
use dcbor::bounded::{
    BoundedError,
    encoding::{Preparation, PrepareStep, Schema},
    text_cursor::pipeline::EmitStep,
};
use dcbor_derive::CBORResumableEncodable;

#[derive(CBORResumableEncodable)]
struct Record {
    #[cbor(n = 24)]
    omitted: Option<String>,
    #[cbor(n = 1)]
    nested: Vec<Vec<String>>,
    #[cbor(n = 0)]
    enabled: bool,
}

fn prepare(source: &dyn Schema, stop: Option<usize>, cancel: bool) -> Meter {
    let expected = [0xa2, 0, 0xf5, 1, 0x81, 0x81, 0x62, 0xc3, 0xa9];
    let mut m = meter();
    m.fail_at = stop.map(|i| (i, Refusal::Work));
    let pool = m.pool.clone();
    let mut cursor = Preparation::new(source);
    let mut observed = false;
    let mut completed = false;
    let mut plan = None;
    for _ in 0..8192 {
        let before = (m.values, m.bytes);
        m.limit_values = before.0 + 3;
        m.limit_bytes = before.1 + 64;
        m.refused = None;
        let result = cursor.step(&mut m);
        assert!(m.values - before.0 <= 3 && m.bytes - before.1 <= 64);
        match result {
            Ok(PrepareStep::Progress) => {}
            Ok(PrepareStep::Complete(value)) => {
                plan = Some(value);
                completed = true;
                break;
            }
            Err(BoundedError::Refused(Refusal::Work)) => {
                assert_eq!(m.refused, stop.map(|i| (i, Refusal::Work)));
                assert!(!observed);
                observed = true;
                m.fail_at = None;
                if cancel {
                    completed = true;
                    break;
                }
            }
            _ => panic!("unexpected outcome at {:?}", cursor.position()),
        }
    }
    assert!(completed);
    assert_eq!(observed, stop.is_some());
    drop(cursor);
    if let Some(plan) = plan {
        assert!(pool.live() > 0);
        assert_eq!(plan.len(), expected.len());
        let mut bytes = [0xee; 11];
        let mut writer = plan.writer(&mut bytes[1..10]);
        let mut b = meter();
        let mut done = false;
        for _ in 0..32 {
            if writer.step(&mut b).unwrap() == EmitStep::Complete {
                done = true;
                break;
            }
        }
        assert!(done);
        assert_eq!(writer.emitted_prefix(), expected);
        assert!(b.calls.iter().all(|c| !matches!(c, Call::Allocate(_))));
        assert_eq!(writer.step(&mut b).unwrap(), EmitStep::Finished);
        assert_eq!(bytes[0], 0xee);
        assert_eq!(bytes[10], 0xee);
        drop(plan);
    }
    assert_eq!(pool.live(), 0);
    m
}

#[test]
fn derived_schema_every_admission_resumes_without_replay_and_cancels() {
    let source = Record {
        omitted: None,
        enabled: true,
        nested: vec![vec!["e\u{301}".into()]],
    };
    let baseline = prepare(&source, None, false);
    every_case(baseline.calls.len(), |stop| {
        let resumed = prepare(&source, Some(stop), false);
        let mut expected = baseline.calls.clone();
        expected.insert(stop, expected[stop]);
        assert_eq!(resumed.calls, expected);
        assert_eq!(
            (resumed.values, resumed.bytes),
            (baseline.values, baseline.bytes)
        );
        let cancelled = prepare(&source, Some(stop), true);
        assert_eq!(cancelled.calls, baseline.calls[..=stop]);
    });
}

#[derive(CBORResumableEncodable)]
enum Shape<T> {
    #[cbor(n = 7)]
    Unit,
    #[cbor(n = 24)]
    Tuple(T, Option<u64>),
    #[cbor(n = 2)]
    Named {
        #[cbor(n = 256)]
        absent: Option<T>,
        #[cbor(n = 24)]
        present: Option<T>,
        #[cbor(n = 0)]
        count: u64,
    },
}

fn plan(source: &dyn Schema) -> (dcbor::bounded::encoding::Prepared<Permit>, Pool) {
    let mut m = meter();
    let mut preparation = Preparation::new(source);
    for _ in 0..65536 {
        m.limit_values = m.values + 3;
        m.limit_bytes = m.bytes + 64;
        if let PrepareStep::Complete(plan) = preparation.step(&mut m).unwrap() {
            drop(preparation);
            return (plan, m.pool);
        }
    }
    panic!(
        "preparation exceeded finite bound at {:?}",
        preparation.position()
    );
}

fn emission_matrix(source: &dyn Schema, expected: &[u8]) {
    let (plan, pool) = plan(source);
    assert_eq!(plan.len(), expected.len());
    let live = pool.live();
    let run = |stop: Option<usize>, cancel: bool| {
        let mut bytes = vec![0xee; expected.len() + 2];
        let mut writer = plan.writer(&mut bytes[1..expected.len() + 1]);
        let mut m = meter();
        m.fail_at = stop.map(|i| (i, Refusal::Work));
        let mut observed = false;
        let mut done = false;
        for _ in 0..expected.len() * 2 + 64 {
            m.limit_values = m.values + 3;
            m.limit_bytes = m.bytes + 64;
            let prefix = writer.emitted_prefix().to_vec();
            match writer.step(&mut m) {
                Ok(EmitStep::Progress) => {}
                Ok(EmitStep::Complete) => {
                    assert_eq!(writer.emitted_prefix(), expected);
                    done = true;
                    break;
                }
                Err(BoundedError::Refused(Refusal::Work)) => {
                    assert_eq!(m.refused, stop.map(|i| (i, Refusal::Work)));
                    assert_eq!(writer.emitted_prefix(), prefix);
                    assert!(!observed);
                    observed = true;
                    m.fail_at = None;
                    m.refused = None;
                    if cancel {
                        done = true;
                        break;
                    }
                }
                other => panic!("unexpected emission {other:?}"),
            }
            assert_eq!(pool.live(), live);
        }
        assert!(done);
        assert_eq!(observed, stop.is_some());
        assert!(
            m.calls
                .iter()
                .all(|call| !matches!(call, Call::Allocate(_)))
        );
        assert_eq!(bytes[0], 0xee);
        assert_eq!(*bytes.last().unwrap(), 0xee);
        m
    };
    let baseline = run(None, false);
    every_case(baseline.calls.len(), |stop| {
        let resumed = run(Some(stop), false);
        let mut trace = baseline.calls.clone();
        trace.insert(stop, trace[stop]);
        assert_eq!(resumed.calls, trace);
        let cancelled = run(Some(stop), true);
        assert_eq!(cancelled.calls, baseline.calls[..=stop]);
    });
    drop(plan);
    assert_eq!(pool.live(), 0);
}

#[test]
fn enum_generic_optional_tagged_and_numeric_literals_survive_emission_refusals() {
    emission_matrix(&Shape::<String>::Unit, &[7]);
    emission_matrix(
        &Shape::Tuple("a".to_string(), None),
        &[0x83, 0x18, 24, 0x61, b'a', 0xf6],
    );
    let named = Shape::Named {
        absent: None,
        present: Some("a".to_string()),
        count: 1,
    };
    emission_matrix(&named, &[0x82, 2, 0xa2, 0, 1, 0x18, 24, 0x61, b'a']);
    emission_matrix(
        &dcbor::bounded::Tagged {
            tag: 42,
            value: named,
        },
        &[0xd8, 42, 0x82, 2, 0xa2, 0, 1, 0x18, 24, 0x61, b'a'],
    );
    emission_matrix(
        &vec![1.0f64, 1.5, f64::NAN],
        &[0x83, 1, 0xf9, 0x3e, 0, 0xf9, 0x7e, 0],
    );
    emission_matrix(&vec![-1i64, -25], &[0x82, 0x20, 0x38, 24]);
}

#[test]
fn many_map_headers_and_multibyte_payloads_preserve_gap_order_and_prefixes() {
    #[derive(CBORResumableEncodable)]
    struct Empty {}
    let source: Vec<_> = (0..32).map(|_| Empty {}).collect();
    let mut expected = vec![0x98, 32];
    expected.extend([0xa0; 32]);
    emission_matrix(&source, &expected);
    let source = dcbor::ByteString::from(vec![0xaa; 256]);
    let mut expected = vec![0x59, 1, 0];
    expected.extend([0xaa; 256]);
    emission_matrix(&source, &expected);
}

#[test]
fn every_schema_preparation_allocation_failure_preserves_physical_ownership() {
    use super::heap::Observation;
    let source = Record {
        omitted: None,
        enabled: true,
        nested: vec![vec!["e\u{301}".repeat(32)]; 8],
    };
    let run = |failure| {
        let mut m = meter();
        m.calls.reserve(65536);
        let observation = Observation::begin(failure);
        let mut preparation = Preparation::new(&source);
        let mut result = None;
        let mut failed = false;
        for _ in 0..65536 {
            m.limit_values = m.values + 3;
            m.limit_bytes = m.bytes + 64;
            match preparation.step(&mut m) {
                Ok(PrepareStep::Progress) => {}
                Ok(PrepareStep::Complete(plan)) => {
                    result = Some(plan);
                    break;
                }
                Err(BoundedError::Allocation { .. }) => {
                    failed = true;
                    break;
                }
                _ => panic!("unexpected preparation outcome"),
            }
            assert!(observation.snapshot().live <= m.pool.live() as usize);
        }
        observation.stop();
        assert!(failed || result.is_some());
        let stats = observation.snapshot();
        assert_eq!(stats.denied, failure.is_some());
        assert_eq!(failed, failure.is_some());
        assert!(!stats.overflow);
        assert_eq!(stats.unadmitted, 0);
        assert!(stats.peak <= m.pool.peak() as usize);
        drop(preparation);
        if result.is_some() {
            assert!(m.pool.live() > 0);
        }
        drop(result);
        assert_eq!(observation.snapshot().live, 0);
        assert_eq!(m.pool.live(), 0);
        stats.calls
    };
    let calls = run(None);
    every_case(calls, |index| {
        run(Some(index));
    });
}

#[test]
fn wide_schema_finalizes_multibyte_map_head_without_payload_relocation() {
    macro_rules! wide {
        ($($name:ident = $key:literal),* $(,)?) => {{
            #[derive(CBORResumableEncodable)]
            struct Wide { $(#[cbor(n = $key)] $name: u64,)* }
            Wide { $($name: 0,)* }
        }};
    }
    let source = wide!(
        a0 = 0,
        a1 = 1,
        a2 = 2,
        a3 = 3,
        a4 = 4,
        a5 = 5,
        a6 = 6,
        a7 = 7,
        a8 = 8,
        a9 = 9,
        a10 = 10,
        a11 = 11,
        a12 = 12,
        a13 = 13,
        a14 = 14,
        a15 = 15,
        a16 = 16,
        a17 = 17,
        a18 = 18,
        a19 = 19,
        a20 = 20,
        a21 = 21,
        a22 = 22,
        a23 = 23,
        a24 = 24,
        a25 = 25,
        a26 = 26,
        a27 = 27,
        a28 = 28,
        a29 = 29,
        a30 = 30,
        a31 = 31,
    );
    let expected = [
        0xb8, 32, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 0, 9, 0, 10, 0, 11, 0, 12, 0,
        13, 0, 14, 0, 15, 0, 16, 0, 17, 0, 18, 0, 19, 0, 20, 0, 21, 0, 22, 0, 23, 0, 0x18, 24, 0,
        0x18, 25, 0, 0x18, 26, 0, 0x18, 27, 0, 0x18, 28, 0, 0x18, 29, 0, 0x18, 30, 0, 0x18, 31, 0,
    ];
    emission_matrix(&source, &expected);
}
