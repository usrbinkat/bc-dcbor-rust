//! Standalone bounded decoding with cooperative retirement pressure.
//! Each batch is fully drained; busy-period age is an upper bound on record
//! retirement age, not a per-record completion timestamp or open-loop latency.
use dcbor::bounded::decode::Options;
use dcbor::bounded::decode::construction::reclamation::Reclaimed;
use dcbor::bounded::decode::construction::{Borrowed, DecodeOwner, TypedDecoder};
use dcbor::bounded::{Failure, Limits, ResourceBound, Resumable, Step};
use std::time::{Duration, Instant};

#[global_allocator]
static ALLOCATOR: std::alloc::System = std::alloc::System;

fn turns(bound: ResourceBound) -> usize {
    usize::try_from(bound.values.checked_add(bound.allocated).unwrap()).unwrap()
}

// Benchmark scheduling calls production steps directly. This measures actual
// step invocations, including ordinary quantum exhaustion, without test tracing.
fn drive<O: Resumable<Limits>>(
    operation: &mut O,
    m: &mut Limits,
    bound: usize,
    steps: &mut usize,
) -> O::Output {
    for _ in 0..bound {
        m.turn();
        *steps += 1;
        match operation.step(m) {
            Ok(Step::Complete(value)) => return value,
            Ok(Step::Progress) => {}
            Err(error) if error.refused() => {}
            _ => panic!("decoding failed or finished without output"),
        }
    }
    panic!("production bound exceeded");
}

fn main() {
    if cfg!(debug_assertions) {
        eprintln!("run this measurement with --release");
        std::process::exit(2);
    }
    let mut args = std::env::args().skip(1);
    let mut number = |default| args.next().map_or(default, |v| v.parse::<usize>().unwrap());
    let operations = number(1000);
    let batch = number(16);
    let service = number(1);
    let length = number(1024);
    assert!(
        args.next().is_none(),
        "usage: reclamation_profile [operations batch cleanup_turns_per_operation text_bytes]"
    );
    assert!(operations > 0 && batch > 0);
    let text = "x".repeat(length);
    let wire = dcbor::CBOR::from(text.clone()).to_cbor_data();
    let options = Options::normalizing(8);
    let borrow_bound =
        turns(dcbor::bounded::decode::construction::borrow_bound::<Limits, ()>().unwrap());
    let decode_bound =
        turns(
            dcbor::bounded::decode::construction::typed_decode_bound::<
                Borrowed<'_>,
                String,
                Limits,
                (),
            >(wire.len() as u64, options)
            .unwrap(),
        );
    let scope_bound =
        turns(dcbor::bounded::decode::construction::scope_bound::<Limits, ()>().unwrap());
    let cleanup_bound = decode_bound
        .checked_add(borrow_bound)
        .unwrap()
        .checked_mul(batch)
        .unwrap()
        .checked_add(scope_bound)
        .unwrap();
    let pool = Limits::new(0, 0, 64 * 1024 * 1024).requesting_at_most(0);
    // share() grants independent work/request authority but one storage ceiling.
    let mut foreground = pool.share();
    let mut cleanup = pool.share();
    let mut owner = DecodeOwner::new();
    let mut initialized = false;
    for _ in 0..scope_bound {
        foreground.turn();
        match owner.initialize_step(&mut foreground) {
            Ok(()) => {
                initialized = true;
                break;
            }
            Err(error) if error.refused() => {}
            Err(error) => panic!("scope initialization: {error:?}"),
        }
    }
    assert!(initialized);
    let mut samples = Vec::with_capacity(operations);
    let mut foreground_steps = 0;
    let mut cleanup_steps = 0;
    let mut cleanup_wall = Duration::ZERO;
    let mut busy_since = None;
    let mut max_busy = Duration::ZERO;
    let mut peak_records = 0;
    let started = Instant::now();
    for index in 0..operations {
        let begun = Instant::now();
        let input = drive(
            &mut owner.borrow_input(&wire),
            &mut foreground,
            borrow_bound,
            &mut foreground_steps,
        );
        let value = drive(
            &mut TypedDecoder::<_, String, Limits>::new(input, options),
            &mut foreground,
            decode_bound,
            &mut foreground_steps,
        );
        assert_eq!(value.value(), &text);
        busy_since.get_or_insert_with(Instant::now);
        drop(value);
        peak_records = peak_records.max(owner.outstanding());
        let draining = (index + 1) % batch == 0 || index + 1 == operations;
        let cleanup_started = Instant::now();
        for _ in 0..if draining { cleanup_bound } else { service } {
            if owner.outstanding() == 0 {
                break;
            }
            cleanup.turn();
            cleanup_steps += 1;
            match owner.step(&mut cleanup) {
                Ok(Reclaimed::Progress | Reclaimed::Done) => {}
                Ok(Reclaimed::Waiting) => panic!("retired records cannot wait for live handles"),
                Err(error) if error.refused() => {}
                Err(error) => panic!("cleanup: {error:?}"),
            }
        }
        cleanup_wall += cleanup_started.elapsed();
        if draining {
            assert_eq!(owner.outstanding(), 0, "batch cleanup exceeded bound");
        }
        if owner.outstanding() == 0
            && let Some(since) = busy_since.take()
        {
            max_busy = max_busy.max(since.elapsed());
        }
        samples.push(begun.elapsed().as_nanos());
    }
    let elapsed = started.elapsed();
    cleanup.turn();
    assert_eq!(owner.shutdown_step(&mut cleanup).unwrap(), Reclaimed::Done);
    assert_eq!(pool.live_bytes(), 0);
    assert_eq!(pool.used().values, 0);
    assert_eq!(pool.requested_bytes(), 0);
    samples.sort_unstable();
    println!(
        "# reclamation-profile-v1 load=closed-loop scheduler=cooperative allocator=System storage_ceiling=67108864 work_authority=per_handle requests_authority=per_handle latency=checked_decode_plus_cleanup busy_age=queue_busy_period_upper_bound"
    );
    println!(
        "operations\tbatch\tservice_turns\ttext_bytes\twall_ns\tp99_foreground_ns\tmax_foreground_ns\tcleanup_wall_ns\tforeground_steps\tcleanup_steps\tpeak_records\tpeak_pool_bytes\tmax_busy_ns\tforeground_values\tcleanup_values\tforeground_requests_bytes\tcleanup_requests_bytes\tforeground_refusals\tcleanup_refusals"
    );
    println!(
        "{operations}\t{batch}\t{service}\t{length}\t{}\t{}\t{}\t{}\t{foreground_steps}\t{cleanup_steps}\t{peak_records}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        elapsed.as_nanos(),
        samples[(operations * 99).div_ceil(100) - 1],
        samples.last().unwrap(),
        cleanup_wall.as_nanos(),
        pool.peak_bytes(),
        max_busy.as_nanos(),
        foreground.used().values,
        cleanup.used().values,
        foreground.requested_bytes(),
        cleanup.requested_bytes(),
        foreground.refusals(),
        cleanup.refusals()
    );
}
