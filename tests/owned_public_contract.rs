//! The safe consumer path through the production owned pipeline: acquire,
//! inspect, construct across threads, prepare, emit, retire and shut down.
//! There is no test-local implementation, unsafe fallback, cfg gate on the
//! interfaces, or ignored test.
#![cfg(feature = "std")]
#![forbid(unsafe_code)]
use dcbor::bounded::decode::Options;
use dcbor::bounded::decode::construction::TypedDecoder;
use dcbor::bounded::encoding::OwnedPreparation;
use dcbor::bounded::{Limits, Step};
use dcbor_test_support as support;

#[test]
fn safe_acquire_inspect_construct_encode_transfer_and_retire() {
    let mut m = Limits::unlimited().logged().strict();
    let mut owner = support::scope(&mut m);
    let wire = [0x62, b'o', b'k'];
    // Copying is explicit; acquisition retains progress and custody.
    let input = support::copy(&owner, &mut m, &wire);
    let document =
        support::parse(&mut m, input, Options::quick_only(8)).expect("document inspection failed");
    assert_eq!(document.root().encoded(), wire);
    assert_eq!(document.bytes(), wire);
    // The input moves out of the document without copying.
    let input = document.into_input();
    let mut decoder = TypedDecoder::<_, String, Limits>::new(input, Options::quick_only(8));
    let mut output = None;
    for _ in 0..support::typed_turns::<String>(wire.len()) {
        // Consecutive turns run on different threads with exclusive custody.
        (decoder, m, output) = std::thread::spawn(move || {
            let output = match support::checked(&mut m, |m| support::contracted(m, &mut decoder)) {
                Ok(Step::Progress) => None,
                Ok(Step::Complete(value)) => {
                    support::exhausted(&mut m, &mut decoder);
                    Some(value)
                }
                Err(error) if support::ordinary_exhaustion(&m, &error) => None,
                other => panic!("typed decode failed: {}", support::label(&other)),
            };
            (decoder, m, output)
        })
        .join()
        .expect("decode turn panicked");
        if output.is_some() {
            break;
        }
    }
    drop(decoder);
    let output = output.expect("typed construction exceeded its bound");
    assert_eq!(output.value(), "ok");
    assert_eq!(output.bytes(), wire);
    let bound = support::turns(
        dcbor::bounded::encoding::owned_prepare_bound::<dcbor::ByteString, String, Limits, ()>(
            support::shape(output.value()),
        )
        .expect("the owned preparation bound fits in u64"),
    );
    let plan = support::drive_within(&mut m, &mut OwnedPreparation::prepare(output), bound)
        .expect("preparation failed");
    assert_eq!(plan.value(), "ok");
    assert_eq!(plan.len(), wire.len());
    let mut writer = plan.into_writer();
    let held = m.live_bytes();
    let used = m.used();
    let calls = m.calls().len();
    let before = writer.position();
    assert_eq!(
        writer.position(),
        before,
        "writer observation is not deterministic"
    );
    assert_eq!(m.live_bytes(), held, "observation changed custody");
    assert_eq!(m.used(), used, "observation charged work");
    assert_eq!(m.calls().len(), calls, "observation changed the trace");
    assert!(before.plan.source);
    let prepared = before
        .plan
        .preparation
        .expect("published plan omitted its arenas");
    assert!(prepared.bytes.has_current_permit);
    assert_eq!(prepared.bytes.initialized, wire.len());
    assert!(!before.emission.finished);
    let bytes = support::emit(&mut m, &mut writer, wire.len());
    assert_eq!(bytes, wire);
    let after = writer.position();
    assert!(after.emission.finished);
    assert_eq!(after.emission.written, wire.len());
    assert_eq!(
        after.plan, before.plan,
        "emission changed retained plan custody"
    );
    assert_eq!(m.live_bytes(), held, "emission released its source or plan");
    drop(writer);
    support::drain(&mut owner, &mut m);
    assert_eq!(m.live_bytes(), 0);
}
