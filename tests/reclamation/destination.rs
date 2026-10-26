use super::*;

/// Construct `["a", "b"]` from `wire`, cancelling the construction after
/// `stop` turns: cancellation releases nothing synchronously, and its own
/// cleanup takes every unit refused once, releasing nothing, before it is
/// admitted, within the decode's bound. The turns construction took to
/// publish, when it published within `stop`.
fn cancelled(wire: &[u8], stop: usize) -> Option<usize> {
    let bound = support::typed_turns::<Vec<String>>(wire.len());
    let mut m = meter();
    let (mut owner, document) = document(&mut m, wire, Options::normalizing(8));
    let mut construction = Construction::<_, Vec<String>, Limits>::construct(document);
    let mut output = None;
    let mut published = None;
    for turn in 0..stop.min(bound) {
        match support::checked(&mut m, |m| support::contracted(m, &mut construction)) {
            Ok(Step::Progress) | Err(DecodeError::Resource(BoundedError::Refused(_))) => {}
            Ok(Step::Complete(value)) => {
                assert_eq!(value.value(), &["a", "b"]);
                output = Some(value);
                published = Some(turn + 1);
                break;
            }
            _ => panic!("construction skipped publication"),
        }
    }
    let held = m.live_bytes();
    construction.cancel();
    assert_eq!(m.live_bytes(), held, "cancellation released synchronously");
    // Every cleanup unit is refused once, without release, before it runs.
    let mut finished = false;
    for _ in 0..bound {
        m.clear_refusal();
        m.exhaust();
        let held = m.live_bytes();
        match support::contracted(&mut m, &mut construction) {
            Err(DecodeError::Resource(BoundedError::Refused(_))) => {
                assert_eq!(m.live_bytes(), held);
            }
            Ok(Step::Finished) => {
                finished = true;
                break;
            }
            Ok(Step::Progress) => {
                assert!(m.live_bytes() < held, "unpaid cleanup progress");
                continue;
            }
            _ => panic!("cleanup advanced without admission"),
        }
        if matches!(
            support::checked(&mut m, |m| support::contracted(m, &mut construction)).unwrap(),
            Step::Finished
        ) {
            finished = true;
            break;
        }
    }
    assert!(finished, "cleanup exceeded its bound of {bound} turns");
    support::exhausted(&mut m, &mut construction);
    drop(construction);
    drop(output);
    drain(&mut owner, &mut m);
    assert_eq!(owner.outstanding(), 0);
    assert_eq!(m.live_bytes(), 0);
    published
}

/// The construction cancelled after every number of turns through its
/// publication ([`support::stop_matrix`]): publication is reached within the
/// decode's bound, and exactly the stop at it publishes.
#[test]
fn cancelled_construction_reclaims_at_every_boundary() {
    let wire = [0x82, 0x61, b'a', 0x61, b'b'];
    let boundaries = cancelled(&wire, usize::MAX).expect("construction never reached publication");
    support::stop_matrix("cancelled construction of two texts", boundaries, |stop| {
        assert_eq!(
            cancelled(&wire, stop).is_some(),
            stop == boundaries,
            "a stop after {stop} turns"
        );
    });
}

#[test]
fn terminal_allocation_error_is_not_replayed() {
    let mut m = meter();
    let (mut owner, document) = document(&mut m, &[7], Options::normalizing(8));
    // Close the scope: the live document keeps it from completing.
    assert_eq!(owner.shutdown_step(&mut m).unwrap(), Reclaimed::Waiting);
    let mut construction = Construction::<_, u64, Limits>::construct(document);
    assert!(matches!(
        support::checked(&mut m, |m| support::contracted(m, &mut construction)),
        Err(DecodeError::Resource(BoundedError::PlanMismatch))
    ));
    support::finish_within(&mut m, &mut construction, support::typed_turns::<u64>(1));
    drop(construction);
    drain(&mut owner, &mut m);
    assert_eq!(m.live_bytes(), 0);
}
