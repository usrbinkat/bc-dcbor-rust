use super::*;
use dcbor::bounded::decode::cursor::Decoder;
use dcbor::bounded::{Family, Reservation};

/// The parser these gates step: its arenas' permits and the origin of their
/// held credit are those of the policy stepping it, [`Limits`].
type Parser<'a> = Decoder<'a, Reservation, Family>;

/// Parse `wire`, cancelling the parser after `stop` turns: its explicit
/// cleanup takes every unit refused once, releasing nothing, before it is
/// admitted, and releases what the parser retained; dropping it then
/// releases nothing more, and the document, outside the parser's custody
/// once published, releases the rest. Within the retained parse's bound,
/// which covers its cleanup. The turns the parse took to publish, when it
/// published within `stop`, and the boundary valuations the run reached.
/// One recorded run, its finalizer refining the stream.
fn cancelled(wire: &[u8], stop: usize) -> (Option<usize>, dcbor::bounded::boundary::Reached) {
    support::recorded_run(|run| {
        let policy = run.policy(u64::MAX);
        Ok(run.with_policy(policy, |m| cancelled_under(m, wire, stop)))
    })
}

/// [`cancelled`]'s body under the run's policy `m`.
fn cancelled_under(
    m: &mut Limits,
    wire: &[u8],
    stop: usize,
) -> (Option<usize>, dcbor::bounded::boundary::Reached) {
    use dcbor::bounded::decode::Kind;
    let bound = support::decode_turns(wire.len());
    let mut parser = Parser::new(wire, Options::normalizing(8));
    let mut document = None;
    let mut published = None;
    for turn in 0..stop.min(bound) {
        match support::checked(m, |m| support::contracted(m, &mut parser)) {
            Ok(Step::Progress) | Err(DecodeError::Resource(BoundedError::Refused(_))) => {}
            Ok(Step::Complete(value)) => {
                support::exhausted(m, &mut parser);
                assert_eq!(value.root().encoded(), wire);
                assert_eq!(
                    value.root().children().next().unwrap().kind(),
                    Kind::Text("\u{301}")
                );
                document = Some(value);
                published = Some(turn + 1);
                break;
            }
            _ => panic!("canonical text did not produce its literal document"),
        }
    }
    // This matrix covers explicit parser cancellation. Document release is
    // outside the parser's custody once Complete transfers it to the caller.
    let mut cleaned = false;
    for _ in 0..bound {
        let held = m.live_bytes();
        m.clear_refusal();
        m.exhaust();
        match parser.reclaim_step(m) {
            Err(BoundedError::Refused(_)) => assert_eq!(m.live_bytes(), held),
            Ok(true) => {
                cleaned = true;
                break;
            }
            Ok(false) => assert!(m.live_bytes() < held, "unpaid cleanup progress"),
            _ => panic!("parser cancellation failed"),
        }
        m.clear_refusal();
        m.fresh();
        if parser.reclaim_step(m).unwrap() {
            cleaned = true;
            break;
        }
    }
    assert!(
        cleaned,
        "parser cancellation exceeded its bound of {bound} turns"
    );
    let held = m.live_bytes();
    drop(parser);
    assert_eq!(
        m.live_bytes(),
        held,
        "parser drop released retained resources"
    );
    drop(document);
    assert_eq!(m.live_bytes(), 0);
    (published, m.reached())
}

/// A leading combining acute accent is already NFC but needs the Maybe
/// normalization path; the surrounding array also acquires parser stack
/// space. The parser cancelled after every number of turns through its
/// publication ([`support::stop_matrix`]).
#[test]
fn normalization_cancellation_at_every_parser_boundary() {
    let wire = [0x81, 0x62, 0xcc, 0x81];
    let boundaries = cancelled(&wire, usize::MAX)
        .0
        .expect("normalization never reached publication");
    support::stop_matrix("cancelled normalizing parse", boundaries, |stop| {
        let (published, reached) = cancelled(&wire, stop);
        assert_eq!(
            published.is_some(),
            stop == boundaries,
            "a stop after {stop} turns"
        );
        reached
    });
}

#[test]
fn parser_error_retains_reservations_until_admitted_cleanup() {
    support::recorded_run(|run| {
        let policy = run.policy(u64::MAX);
        run.with_policy(policy, parser_error_under);
        Ok(())
    });
}

/// [`parser_error_retains_reservations_until_admitted_cleanup`]'s body under
/// the run's policy `m`.
fn parser_error_under(m: &mut Limits) {
    // The third array child is truncated after prior arena and stack allocation.
    let wire = [0x83, 1, 2, 0x19, 0x01];
    // The retained parse's bound covers its cleanup after a failure.
    let bound = support::decode_turns(wire.len());
    let mut parser = Parser::new(&wire, Options::normalizing(8));
    let mut failed = false;
    for _ in 0..bound {
        let held = m.live_bytes();
        match support::checked(m, |m| support::contracted(m, &mut parser)) {
            Ok(Step::Progress) => {}
            Err(DecodeError::Invalid(dcbor::Error::Underrun)) => {
                assert!(held > 0);
                assert_eq!(m.live_bytes(), held);
                failed = true;
                break;
            }
            Err(DecodeError::Resource(BoundedError::Refused(_))) => {}
            _ => panic!("malformed parser fixture produced an unexpected result"),
        }
    }
    assert!(failed, "fixture did not reach its terminal error");
    let refusals = m.refusals();
    let mut finished = false;
    for _ in 0..bound {
        m.clear_refusal();
        m.exhaust();
        let held = m.live_bytes();
        let position = parser.position();
        // Raw step: a resource-free phase transition can precede the refused
        // unit, so only input consumption and retained arena sizes are fixed.
        match parser.step(m) {
            Err(DecodeError::Resource(BoundedError::Refused(_))) => {
                assert_eq!(m.live_bytes(), held);
                assert_eq!(parser.position().input, position.input);
                assert_eq!(parser.position().nodes, position.nodes);
            }
            Ok(Step::Finished) => {
                assert_eq!(held, 0);
                finished = true;
                break;
            }
            Ok(Step::Progress) => assert!(m.live_bytes() < held, "unpaid cleanup progress"),
            _ => panic!("terminal error replayed during parser cleanup"),
        }
        match support::checked(m, |m| support::contracted(m, &mut parser)).unwrap() {
            Step::Progress => {}
            Step::Finished => {
                support::exhausted(m, &mut parser);
                assert_eq!(m.live_bytes(), 0);
                finished = true;
                break;
            }
            Step::Complete(_) => panic!("failed parser published a document"),
        }
    }
    assert!(finished);
    assert!(m.refusals() > refusals);
    drop(parser);
    assert_eq!(m.live_bytes(), 0);
}
