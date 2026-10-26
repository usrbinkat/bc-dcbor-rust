//! Standalone, closed-loop synchronous codec measurements.
//! Run in release mode; see docs/bounded-consumers.md for interpretation.
use dcbor::CBOR;
use dcbor::bounded::decode::{Options, decode_with};
use dcbor::bounded::{Limits, prepare};
use std::hint::black_box;
use std::sync::Barrier;
use std::time::{Duration, Instant};

#[global_allocator]
static ALLOCATOR: std::alloc::System = std::alloc::System;

#[derive(Clone, Copy, Default)]
struct Phase {
    wall: Duration,
    cpu: Duration,
    attempts: usize,
    refusals: usize,
    values: u64,
    bytes: u64,
    requested: u64,
}

impl Phase {
    fn add(&mut self, other: Self) {
        self.wall += other.wall;
        self.cpu += other.cpu;
        self.attempts += other.attempts;
        self.refusals += other.refusals;
        self.values += other.values;
        self.bytes += other.bytes;
        self.requested += other.requested;
    }
}

/// Linux per-thread CPU time excludes descheduling and other workers' CPU.
/// Clock reads are instrumentation overhead, not isolated codec dispatch cost.
#[cfg(target_os = "linux")]
fn thread_cpu() -> Duration {
    #[repr(C)]
    struct Timespec {
        seconds: std::os::raw::c_long,
        nanoseconds: std::os::raw::c_long,
    }
    unsafe extern "C" {
        fn clock_gettime(clock: std::os::raw::c_int, value: *mut Timespec) -> std::os::raw::c_int;
    }
    let mut time = Timespec {
        seconds: 0,
        nanoseconds: 0,
    };
    // SAFETY: Linux CLOCK_THREAD_CPUTIME_ID is 3; time is a writable timespec
    // with the native C ABI, and no pointer is retained by clock_gettime.
    let result = unsafe { clock_gettime(3, &mut time) };
    assert_eq!(
        result,
        0,
        "thread CPU clock: {}",
        std::io::Error::last_os_error()
    );
    Duration::new(
        time.seconds.try_into().unwrap(),
        time.nanoseconds.try_into().unwrap(),
    )
}

#[cfg(not(target_os = "linux"))]
fn thread_cpu() -> Duration {
    panic!("codec CPU attribution requires Linux CLOCK_THREAD_CPUTIME_ID")
}

fn measured<T>(m: &mut Limits, phase: &mut Phase, body: impl FnOnce(&mut Limits) -> T) -> T {
    let before = (m.attempts(), m.refusals(), m.used(), m.requested_bytes());
    let started = Instant::now();
    let cpu = thread_cpu();
    let output = body(m);
    let cpu = thread_cpu()
        .checked_sub(cpu)
        .expect("monotonic thread CPU clock");
    let elapsed = started.elapsed();
    phase.add(Phase {
        wall: elapsed,
        cpu,
        attempts: m.attempts() - before.0,
        refusals: m.refusals() - before.1,
        values: m.used().values - before.2.values,
        bytes: m.used().bytes - before.2.bytes,
        requested: m.requested_bytes() - before.3,
    });
    output
}

/// Timed regions call the production synchronous entry points directly.
/// There is no benchmark-owned continuation scheduler or refusal oracle.
fn roundtrip(
    source: &str,
    wire: &[u8],
    output: &mut [u8],
    m: &mut Limits,
    phases: &mut [Phase; 4],
) {
    let plan = measured(m, &mut phases[0], |m| {
        prepare(black_box(source), m).unwrap()
    });
    assert_eq!(plan.len(), wire.len());
    measured(m, &mut phases[1], |m| {
        plan.encode_into(black_box(&mut *output), m).unwrap()
    });
    assert_eq!(output, wire, "encoding differs from the symbolic oracle");
    let document = measured(m, &mut phases[2], |m| {
        decode_with(black_box(&*output), Options::normalizing(128), m).unwrap()
    });
    assert_eq!(document.root().encoded(), wire);
    measured(m, &mut phases[3], |_| {
        drop(document);
        drop(plan);
    });
}

fn number(text: Option<String>, default: usize) -> usize {
    let value = text.map_or(default, |text| text.parse().expect("positive integer"));
    assert!(value > 0, "arguments must be positive");
    value
}

fn percentile(sorted: &[u128], numerator: usize, denominator: usize) -> u128 {
    let rank = sorted
        .len()
        .checked_mul(numerator)
        .unwrap()
        .div_ceil(denominator);
    sorted[rank.saturating_sub(1)]
}

fn main() {
    if cfg!(debug_assertions) {
        eprintln!("run this measurement with --release");
        std::process::exit(2);
    }
    let mut arguments = std::env::args().skip(1);
    let workers = number(arguments.next(), 1);
    let operations = number(arguments.next(), 10_000);
    let repetitions = number(arguments.next(), 1024);
    let fixture = arguments.next().unwrap_or_else(|| "ascii".into());
    let storage = arguments.next().unwrap_or_else(|| "private".into());
    assert!(
        arguments.next().is_none(),
        "usage: codec_profile [workers operations repetitions ascii|combining private|shared]"
    );
    assert!(
        operations >= workers,
        "each worker needs at least one operation"
    );
    assert!(matches!(storage.as_str(), "private" | "shared"));
    let source = match fixture.as_str() {
        "ascii" => "x".repeat(repetitions),
        "combining" => "e\u{301}".repeat(repetitions),
        _ => panic!("fixture must be ascii or combining"),
    };
    // Oracle generation, worker setup, buffers and warmup are outside the
    // measured interval. Source and canonical wire sizes are reported separately.
    let wire = CBOR::from(source.clone()).to_cbor_data();
    let pool = Limits::unlimited();
    let ready = Barrier::new(workers + 1);
    let start = Barrier::new(workers + 1);
    let (elapsed, mut samples, totals) = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for worker in 0..workers {
            let mut m = if storage == "shared" {
                pool.share()
            } else {
                Limits::unlimited()
            };
            let count = operations / workers + usize::from(worker < operations % workers);
            let (source, wire, ready, start) = (&source, &wire, &ready, &start);
            handles.push(scope.spawn(move || {
                // A failed warmup must still release both barriers; otherwise
                // one worker's assertion could strand the controller forever.
                let setup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut output = vec![0; wire.len()];
                    let samples = Vec::with_capacity(count);
                    for _ in 0..8 {
                        roundtrip(
                            source,
                            wire,
                            &mut output,
                            &mut m,
                            &mut [Phase::default(); 4],
                        );
                    }
                    m.measure();
                    m.open();
                    (output, samples)
                }));
                let mut phases = [Phase::default(); 4];
                ready.wait();
                start.wait();
                let (mut output, mut samples) = match setup {
                    Ok(setup) => setup,
                    Err(error) => std::panic::resume_unwind(error),
                };
                for _ in 0..count {
                    let begun = Instant::now();
                    roundtrip(source, wire, &mut output, &mut m, &mut phases);
                    samples.push(begun.elapsed().as_nanos());
                }
                (Instant::now(), samples, phases, m)
            }));
        }
        ready.wait();
        let begun = Instant::now();
        start.wait();
        let mut ended = begun;
        let mut samples = Vec::with_capacity(operations);
        let mut totals = [Phase::default(); 4];
        for handle in handles {
            let (finished, worker_samples, phases, m) = handle.join().expect("codec worker failed");
            ended = ended.max(finished);
            samples.extend(worker_samples);
            for (total, phase) in totals.iter_mut().zip(phases) {
                total.add(phase);
            }
            if storage == "private" {
                assert_eq!(m.live_bytes(), 0, "worker retained reservations");
            }
        }
        (ended.duration_since(begun), samples, totals)
    });
    assert_eq!(pool.live_bytes(), 0, "shared pool retained reservations");
    assert_eq!(samples.len(), operations);
    samples.sort_unstable();
    println!(
        "# codec-profile-v2 execution=synchronous load=closed-loop allocator=System policy=Limits logging=off trace=recent32 steps=unmeasured cpu_time=thread_clock instrumentation=two_cpu_clock_reads_per_phase"
    );
    println!(
        "# fixture={fixture} workers={workers} operations={operations} storage={storage} source_bytes={} wire_bytes={}",
        source.len(),
        wire.len()
    );
    println!(
        "wall_ns\toperations_per_second\tp50_checked_roundtrip_ns\tp99_checked_roundtrip_ns\tp999_checked_roundtrip_ns\tmax_checked_roundtrip_ns"
    );
    println!(
        "{}\t{:.3}\t{}\t{}\t{}\t{}",
        elapsed.as_nanos(),
        operations as f64 / elapsed.as_secs_f64(),
        percentile(&samples, 50, 100),
        percentile(&samples, 99, 100),
        percentile(&samples, 999, 1000),
        samples.last().unwrap()
    );
    println!(
        "phase\tsummed_wall_ns\tsummed_thread_cpu_ns\tadmission_attempts\trefusals\tadmitted_values\tadmitted_bytes\trequested_bytes"
    );
    for (name, phase) in [
        "prepare_with_shape_walk",
        "emit",
        "parse_validate",
        "drop_document_and_plan",
    ]
    .into_iter()
    .zip(totals)
    {
        assert_eq!(
            phase.refusals, 0,
            "unlimited synchronous workload refused resources"
        );
        println!(
            "{name}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            phase.wall.as_nanos(),
            phase.cpu.as_nanos(),
            phase.attempts,
            phase.refusals,
            phase.values,
            phase.bytes,
            phase.requested
        );
    }
}
