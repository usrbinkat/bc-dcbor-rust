use super::bindings::{string_driver, text_driver};
use super::driver::{Driver, Event, Operation, Step, finish, resume};
use super::harness::*;
use dcbor::bounded::BoundedError;
use dcbor::bounded::text_cursor::pipeline::{
    EmitStep, PrepareStep, PreparedText, TextPreparation, TextWriter,
};

impl Operation<PreparedText<Permit>> for TextPreparation<'_, Permit> {
    fn advance(&mut self, meter: &mut Meter) -> Result<Event<PreparedText<Permit>>, &'static str> {
        Ok(match self.step(meter) {
            Ok(PrepareStep::Progress) => Event::Progress,
            Ok(PrepareStep::Complete(plan)) => Event::Complete(plan),
            Ok(PrepareStep::Finished) => Event::Finished,
            Err(BoundedError::Refused(reason)) => Event::Refused(reason),
            Err(_) => return Err("text preparation failed"),
        })
    }
}

impl Operation<()> for TextWriter<'_, '_, Permit> {
    fn advance(&mut self, meter: &mut Meter) -> Result<Event<()>, &'static str> {
        Ok(match self.step(meter) {
            Ok(EmitStep::Progress) => Event::Progress,
            Ok(EmitStep::Complete) => Event::Complete(()),
            Ok(EmitStep::Finished) => Event::Finished,
            Err(BoundedError::Refused(reason)) => Event::Refused(reason),
            Err(_) => return Err("text emission failed"),
        })
    }
}

fn preparation(meter: Meter) -> Driver<TextPreparation<'static, Permit>, PreparedText<Permit>> {
    Driver::from_operation(TextPreparation::new(SOURCE), meter)
}

fn prepared() -> (PreparedText<Permit>, Meter) {
    let mut operation = preparation(meter());
    finish(&mut operation, 4096);
    (operation.output.take().unwrap(), operation.meter)
}

fn suspend<O: Operation<T>, T>(operation: &mut Driver<O, T>, reason: Refusal) {
    let target = operation.meter.fail_at.expect("injection configured");
    let mut observed = false;
    for _ in 0..4096 {
        match operation.step().unwrap() {
            Step::Progress => assert!(operation.output.is_none()),
            Step::Refused(actual) => {
                assert_eq!(actual, reason);
                observed = true;
                break;
            }
            other => panic!("missing pipeline refusal {target:?}: {other:?}"),
        }
    }
    assert!(observed);
    assert_eq!(operation.meter.refused, Some(target));
}

const SOURCE: &str = "a\u{301}";
const EXPECTED: &[u8] = &[0x62, 0xc3, 0xa1];

#[test]
fn preparation_cancellation_at_every_admission_releases_scratch() {
    let (plan, baseline) = prepared();
    assert_eq!(plan.len(), EXPECTED.len() as u64);
    drop(plan);
    assert_eq!(baseline.pool.live(), 0);
    every_case(baseline.calls.len(), |stop| {
        let reason = match baseline.calls[stop] {
            Call::Allocate(_) => Refusal::Capacity,
            Call::Work { .. } => Refusal::Work,
        };
        let mut m = meter();
        m.fail_at = Some((stop, reason));
        let pool = m.pool.clone();
        let mut operation = preparation(m);
        suspend(&mut operation, reason);
        assert_eq!(operation.meter.refused, Some((stop, reason)));
        assert_eq!(operation.meter.calls, baseline.calls[..=stop]);
        assert!(operation.output.is_none());
        drop(operation);
        assert_eq!(pool.live(), 0);
    });
}

#[test]
fn preparation_resumption_preserves_literal_result_and_plan_ownership() {
    let (plan, baseline) = prepared();
    drop(plan);
    every_case(baseline.calls.len(), |stop| {
        let mut m = meter();
        m.fail_at = Some((stop, Refusal::Work));
        let pool = m.pool.clone();
        let mut operation = preparation(m);
        resume(&mut operation, Refusal::Work);
        operation.meter.assert_units(3, 64);
        let mut expected_trace = baseline.calls.clone();
        expected_trace.insert(stop, baseline.calls[stop]);
        assert_eq!(operation.meter.calls, expected_trace);
        let plan = operation.output.take().unwrap();
        let retained = pool.live();
        assert!(retained > 0);
        drop(operation);
        assert_eq!(pool.live(), retained);
        let mut bytes = [0xee; 3];
        let mut writer = Driver::from_operation(plan.writer(&mut bytes), meter());
        finish(&mut writer, 4096);
        writer.meter.assert_units(3, 64);
        drop(writer);
        assert_eq!(bytes, EXPECTED);
        assert_eq!(pool.live(), retained);
        drop(plan);
        assert_eq!(pool.live(), 0);
    });
}

#[test]
fn emission_resumes_same_destination_without_prefix_replay() {
    let (plan, allocator) = prepared();
    let retained = allocator.pool.live();
    let mut destination = [0; 3];
    let mut reference = Driver::from_operation(plan.writer(&mut destination), meter());
    finish(&mut reference, 4096);
    let baseline = reference.meter;
    every_case(baseline.calls.len(), |stop| {
        let mut guarded = [0xee; 5];
        let mut m = meter();
        m.fail_at = Some((stop, Refusal::Work));
        let mut operation = Driver::from_operation(plan.writer(&mut guarded[1..4]), m);
        resume(&mut operation, Refusal::Work);
        operation.meter.assert_units(3, 64);
        let mut trace = baseline.calls.clone();
        trace.insert(stop, baseline.calls[stop]);
        assert_eq!(operation.meter.calls, trace, "emitted prefix replayed");
        assert_eq!(operation.step().unwrap(), Step::Finished);
        assert_eq!(allocator.pool.live(), retained);
        drop(operation);
        assert_eq!(guarded, [0xee, 0x62, 0xc3, 0xa1, 0xee]);
    });
    drop(plan);
    assert_eq!(allocator.pool.live(), 0);
}

#[test]
fn every_encoding_refusal_cancels_without_releasing_an_independent_output() {
    let mut reference = text_driver(SOURCE, meter());
    finish(&mut reference, 4096);
    drop(reference.output.take());
    let baseline = reference.meter;
    every_case(baseline.calls.len(), |stop| {
        let pool = Pool::new(32 * 1024 * 1024);
        let mut first = text_driver(SOURCE, Meter::new(pool.clone()));
        finish(&mut first, 4096);
        let output = first.output.take().unwrap();
        let retained = pool.live();
        assert!(retained >= EXPECTED.len() as u64);
        let mut m = Meter::new(pool.clone());
        m.fail_at = Some((stop, Refusal::Work));
        let mut operation = text_driver(SOURCE, m);
        suspend(&mut operation, Refusal::Work);
        assert_eq!(operation.meter.refused, Some((stop, Refusal::Work)));
        assert!(operation.output.is_none());
        assert!(pool.live() >= retained);
        drop(operation);
        assert_eq!(pool.live(), retained);
        assert_eq!(output.as_ref(), EXPECTED);
        drop(first);
        assert_eq!(pool.live(), retained);
        drop(output);
        assert_eq!(pool.live(), 0);
    });
}

// Ownership transitions and exact final reacquisition follow merge/split and
// stress_test in tokio/tests/sync_semaphore_owned.rs. Workers use real dCBOR
// calls and independently observed suspension; no worker simulates a result.
#[test]
fn concurrent_suspended_constructors_recover_exact_shared_capacity() {
    let capacity = 32 * 1024 * 1024;
    let pool = Pool::new(capacity);
    let mut reference = string_driver(EXPECTED, meter());
    finish(&mut reference, 4096);
    drop(reference.output.take());
    let baseline = reference.meter;
    let boundaries = baseline.calls.len();
    let outcomes = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for worker in 0..8 {
            let pool = pool.clone();
            let baseline = &baseline;
            handles.push(scope.spawn(move || {
                every_case(125, |iteration| {
                    let stop = (worker * 125 + iteration) % boundaries;
                    let mut m = Meter::new(pool.clone());
                    m.fail_at = Some((stop, Refusal::Work));
                    let mut operation = string_driver(EXPECTED, m);
                    resume(&mut operation, Refusal::Work);
                    let mut expected_trace = baseline.calls.clone();
                    expected_trace.insert(stop, baseline.calls[stop]);
                    assert_eq!(operation.meter.calls, expected_trace);
                    assert_eq!(
                        (operation.meter.values, operation.meter.bytes),
                        (baseline.values, baseline.bytes),
                    );
                    operation.meter.assert_units(3, 64);
                    assert_eq!(operation.output.as_ref().unwrap().value(), "á");
                    let output = operation.output.take().unwrap();
                    assert_eq!(operation.step().unwrap(), Step::Finished);
                    drop(operation);
                    assert_eq!(output.value(), "á");
                    drop(output);
                });
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join())
            .collect::<Vec<_>>()
    });
    assert_eq!(pool.live(), 0);
    let all = pool.reserve(capacity).unwrap();
    assert!(pool.reserve(1).is_err());
    drop(all);
    assert_eq!(pool.live(), 0);
    assert!(
        outcomes.iter().all(Result::is_ok),
        "one or more continuation workers failed"
    );
}

#[test]
fn cancelled_emission_preserves_plan_and_exact_literal_prefix() {
    let (plan, allocator) = prepared();
    let retained = allocator.pool.live();
    let mut destination = [0; 3];
    let mut reference = Driver::from_operation(plan.writer(&mut destination), meter());
    finish(&mut reference, 4096);
    let baseline = reference.meter;
    every_case(baseline.calls.len(), |stop| {
        let mut guarded = [0xee; 5];
        let mut m = meter();
        m.fail_at = Some((stop, Refusal::Work));
        let mut operation = Driver::from_operation(plan.writer(&mut guarded[1..4]), m);
        suspend(&mut operation, Refusal::Work);
        assert_eq!(operation.meter.refused, Some((stop, Refusal::Work)));
        assert_eq!(operation.meter.calls, baseline.calls[..=stop]);
        assert!(operation.output.is_none());
        assert_eq!(allocator.pool.live(), retained);
        drop(operation);
        assert_eq!(allocator.pool.live(), retained);
        assert_eq!((guarded[0], guarded[4]), (0xee, 0xee));
        let written = guarded[1..4]
            .iter()
            .take_while(|byte| **byte != 0xee)
            .count();
        assert_eq!(&guarded[1..1 + written], &EXPECTED[..written]);
        assert!(guarded[1 + written..4].iter().all(|byte| *byte == 0xee));
    });
    drop(plan);
    assert_eq!(allocator.pool.live(), 0);
}
