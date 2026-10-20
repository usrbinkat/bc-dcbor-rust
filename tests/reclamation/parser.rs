use super::*;
use dcbor::bounded::decode::cursor::{DecodeStep, Decoder};
use dcbor::bounded::decode::{DecodeError, Options};

#[test]
fn normalization_cancellation_at_every_parser_boundary() {
    use dcbor::bounded::decode::Kind;
    // A leading combining acute accent is already NFC but needs the Maybe
    // normalization path. The surrounding array also acquires parser stack space.
    let wire = [0x81, 0x62, 0xcc, 0x81];
    let mut published = false;
    for stop in 0..512 {
        let mut a = Turn::new();
        let mut parser = Decoder::new(&wire, Options::normalizing(8));
        let mut document = None;
        for _ in 0..stop {
            a.fresh();
            match parser.step(&mut a) {
                Ok(DecodeStep::Progress)
                | Err(DecodeError::Resource(BoundedError::Refused(()))) => {}
                Ok(DecodeStep::Complete(value)) => {
                    assert_eq!(value.root().encoded(), &wire);
                    assert_eq!(
                        value.root().children().next().unwrap().kind(),
                        Kind::Text("\u{301}")
                    );
                    document = Some(value);
                    published = true;
                    break;
                }
                _ => panic!("canonical text did not produce its literal document"),
            }
        }
        // This matrix covers explicit parser cancellation. Document release is
        // outside the parser's custody once Complete transfers it to the caller.
        let mut cleaned = false;
        for _ in 0..512 {
            let held = a.live.load(Ordering::SeqCst);
            a.values = 0;
            a.bytes = 0;
            match parser.reclaim_step(&mut a) {
                Err(BoundedError::Refused(())) => {
                    assert_eq!(a.live.load(Ordering::SeqCst), held);
                }
                Ok(true) => {
                    cleaned = true;
                    break;
                }
                Ok(false) => assert_eq!(a.live.load(Ordering::SeqCst), held),
                _ => panic!("parser cancellation failed"),
            }
            a.fresh();
            if parser.reclaim_step(&mut a).unwrap() {
                cleaned = true;
                break;
            }
        }
        assert!(cleaned, "parser cancellation exceeded its finite bound");
        let held = a.live.load(Ordering::SeqCst);
        drop(parser);
        assert_eq!(
            a.live.load(Ordering::SeqCst),
            held,
            "parser drop released retained resources"
        );
        drop(document);
        assert_eq!(a.live.load(Ordering::SeqCst), 0);
        if published {
            break;
        }
    }
    assert!(published, "normalization never reached publication");
}

#[test]
fn parser_error_retains_reservations_until_admitted_cleanup() {
    // The third array child is truncated after prior arena and stack allocation.
    let wire = [0x83, 1, 2, 0x19, 0x01];
    let mut a = Turn::new();
    let mut parser = Decoder::new(&wire, Options::normalizing(8));
    let mut failed = false;
    for _ in 0..256 {
        a.fresh();
        let held = a.live.load(Ordering::SeqCst);
        match parser.step(&mut a) {
            Ok(DecodeStep::Progress) => {}
            Err(DecodeError::Invalid(dcbor::Error::Underrun)) => {
                assert!(held > 0);
                assert_eq!(a.live.load(Ordering::SeqCst), held);
                failed = true;
                break;
            }
            Err(DecodeError::Resource(BoundedError::Refused(()))) => {}
            _ => panic!("malformed parser fixture produced an unexpected result"),
        }
    }
    assert!(failed, "fixture did not reach its terminal error");
    let mut finished = false;
    for _ in 0..256 {
        a.values = 0;
        a.bytes = 0;
        let held = a.live.load(Ordering::SeqCst);
        let position = parser.position();
        match parser.step(&mut a) {
            Err(DecodeError::Resource(BoundedError::Refused(()))) => {
                assert_eq!(a.live.load(Ordering::SeqCst), held);
                // A resource-free transition can precede the refused unit;
                // input consumption and retained arena sizes cannot change.
                assert_eq!(parser.position().input, position.input);
                assert_eq!(parser.position().nodes, position.nodes);
            }
            Ok(DecodeStep::Finished) => {
                assert_eq!(held, 0);
                finished = true;
                break;
            }
            Ok(DecodeStep::Progress) => assert_eq!(held, 0),
            _ => panic!("terminal error replayed during parser cleanup"),
        }
        a.fresh();
        match parser.step(&mut a).unwrap() {
            DecodeStep::Progress => {}
            DecodeStep::Finished => {
                assert_eq!(a.live.load(Ordering::SeqCst), 0);
                finished = true;
                break;
            }
            DecodeStep::Complete(_) => panic!("failed parser published a document"),
        }
    }
    assert!(finished);
    assert!(a.refused > 0);
    drop(parser);
    assert_eq!(a.live.load(Ordering::SeqCst), 0);
}
