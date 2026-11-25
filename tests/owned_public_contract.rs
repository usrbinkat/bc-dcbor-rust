//! The safe consumer path through the production owned pipeline: acquire,
//! inspect, construct across threads, prepare, emit, retire and shut down.
#![cfg(feature = "std")]
#![forbid(unsafe_code)]
use dcbor::ByteString;
use dcbor::bounded::Limits;
use dcbor::bounded::decode::Options;
use dcbor::bounded::decode::construction::{TypedDecoder, TypedValue};
use dcbor_test_support::{
    self as support, Finding, Holding, PolicyId, Retirement, pipeline::Unwitnessed,
};

/// Prepare and emit the held value while preserving the plan's custody and
/// proving that writer observation neither charges work nor changes state.
fn encode(
    value: &mut Holding<'_, '_, TypedValue<'_, ByteString, String, Limits>, Unwitnessed>,
    policy: PolicyId,
    wire: &[u8],
) -> Result<(), Finding> {
    assert_eq!(value.value().value(), "ok");
    assert_eq!(value.value().bytes(), wire);
    value.prepare(policy, |plan| {
        assert_eq!(plan.value().value(), "ok");
        assert_eq!(plan.value().len(), wire.len());
        plan.transfer(
            dcbor::bounded::encoding::OwnedPrepared::into_writer,
            Retirement::Published,
            |writer| {
                let (before, held) = writer.with_policy(policy, |writer, m| {
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
                    (before, held)
                });
                assert_eq!(
                    before.plan.source.and_then(|source| source.phase),
                    Some(dcbor::bounded::decode::construction::ConstructPhase::Published),
                    "a published plan's source is its published value's record"
                );
                let prepared = before
                    .plan
                    .preparation
                    .expect("published plan omitted its arenas");
                assert!(prepared.bytes.arena.has_current_permit);
                assert_eq!(prepared.bytes.arena.initialized, wire.len());
                assert!(!before.emission.finished);
                let mut bytes = Vec::with_capacity(wire.len());
                assert!(writer.emit(policy, &mut bytes, wire.len(), |_, _, _| false)?);
                assert_eq!(bytes, wire);
                let after = writer.value().position();
                assert!(after.emission.finished);
                assert_eq!(after.emission.written, wire.len());
                assert_eq!(
                    after.plan, before.plan,
                    "emission changed retained plan custody"
                );
                writer.with_policy(policy, |_, m| {
                    assert_eq!(m.live_bytes(), held, "emission released its source or plan");
                });
                Ok::<_, Finding>(())
            },
        )
    })?
}

/// Each decode turn executes on a fresh joined worker borrowing parent-held
/// custody. A separate observed handle transfer proves the constructed value
/// remains at its original address; publication outlives its decoder.
#[test]
fn safe_acquire_inspect_construct_encode_transfer_and_retire() {
    const WIRE: &[u8] = &[0x62, b'o', b'k'];
    const OPTIONS: Options = Options::quick_only(8);
    support::recorded_run(|run| {
        let policy = run.policy(u64::MAX);
        run.scoped(policy, &Unwitnessed, |owner| {
            owner.copied(policy, WIRE, |input| {
                input.parse(policy, OPTIONS, |document| {
                    assert_eq!(document.value().root().encoded(), WIRE);
                    assert_eq!(document.value().bytes(), WIRE);
                    document.transfer(
                        |document| {
                            TypedDecoder::<_, String, Limits>::new(document.into_input(), OPTIONS)
                        },
                        Retirement::Stopped,
                        |decoder| {
                            decoder.drive_threaded(
                                policy,
                                support::typed_turns::<String>(WIRE.len()),
                                Retirement::Published,
                                |_, _| {},
                                |value| {
                                    let address = std::ptr::from_ref(value.value().value());
                                    value.checkpoint();
                                    value.transfer(
                                        core::convert::identity,
                                        Retirement::Published,
                                        |value| {
                                            value.checkpoint();
                                            assert_eq!(
                                                std::ptr::from_ref(value.value().value()),
                                                address,
                                                "moving the handle moved the value"
                                            );
                                            encode(value, policy, WIRE)
                                        },
                                    )
                                },
                            )?
                        },
                    )
                })?
            })?
        })?;
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok::<_, Finding>(())
    });
}
