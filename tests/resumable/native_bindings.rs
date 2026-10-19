use super::driver::{Driver, Event, Operation, Step, finish, resume};
use super::harness::*;
use core::cmp::Ordering;
use dcbor::bounded::BoundedError;
use dcbor::bounded::decode::{
    DecodeError,
    comparison::{ComparisonStep, KeyComparison},
    header::{Header, HeaderCursor, HeaderStep},
};
use dcbor::bounded::{
    Encoded,
    text_cursor::{TextEncoder, TextStep},
};

use dcbor::bounded::decode::{
    Document, Options,
    cursor::{DecodeStep, Decoder},
    string_cursor::{OwnedString, StringDecoder, StringStep},
};

pub fn string_driver(
    input: &[u8],
    meter: Meter,
) -> Driver<StringDecoder<'_, Permit>, OwnedString<Permit>> {
    Driver::from_operation(StringDecoder::new(input, Options::normalizing(16)), meter)
}

impl Operation<OwnedString<Permit>> for StringDecoder<'_, Permit> {
    fn advance(&mut self, meter: &mut Meter) -> Result<Event<OwnedString<Permit>>, &'static str> {
        Ok(match self.step(meter) {
            Ok(StringStep::Progress) => Event::Progress,
            Ok(StringStep::Complete(value)) => Event::Complete(value),
            Ok(StringStep::Finished) => Event::Finished,
            Err(DecodeError::Resource(BoundedError::Refused(reason))) => Event::Refused(reason),
            Err(DecodeError::Invalid(_)) => Event::Invalid,
            Err(_) => return Err("production string construction resource or policy failure"),
        })
    }
}

pub fn decode_driver(
    input: &[u8],
    meter: Meter,
) -> Driver<Decoder<'_, Permit>, Document<'_, Permit>> {
    Driver::from_operation(Decoder::new(input, Options::normalizing(16)), meter)
}

impl<'a> Operation<Document<'a, Permit>> for Decoder<'a, Permit> {
    fn advance(&mut self, meter: &mut Meter) -> Result<Event<Document<'a, Permit>>, &'static str> {
        Ok(match self.step(meter) {
            Ok(DecodeStep::Progress) => Event::Progress,
            Ok(DecodeStep::Complete(document)) => Event::Complete(document),
            Ok(DecodeStep::Finished) => Event::Finished,
            Err(DecodeError::Resource(BoundedError::Refused(reason))) => Event::Refused(reason),
            Err(DecodeError::Invalid(_)) => Event::Invalid,
            Err(_) => return Err("production decoder resource or policy failure"),
        })
    }
}

pub fn text_driver(source: &str, meter: Meter) -> Driver<TextEncoder<'_, Permit>, Encoded<Permit>> {
    Driver::from_operation(TextEncoder::new(source), meter)
}

impl Operation<Encoded<Permit>> for TextEncoder<'_, Permit> {
    fn advance(&mut self, meter: &mut Meter) -> Result<Event<Encoded<Permit>>, &'static str> {
        Ok(match self.step(meter) {
            Ok(TextStep::Progress) => Event::Progress,
            Ok(TextStep::Complete(output)) => Event::Complete(output),
            Ok(TextStep::Finished) => Event::Finished,
            Err(BoundedError::Refused(reason)) => Event::Refused(reason),
            Err(_) => return Err("production text encoder resource or invariant failure"),
        })
    }
}

impl Operation<Header> for HeaderCursor<'_> {
    fn advance(&mut self, meter: &mut Meter) -> Result<Event<Header>, &'static str> {
        Ok(match self.step(meter) {
            Ok(HeaderStep::Progress) => Event::Progress,
            Ok(HeaderStep::Complete(header)) => Event::Complete(header),
            Ok(HeaderStep::Finished) => Event::Finished,
            Err(DecodeError::Resource(BoundedError::Refused(reason))) => Event::Refused(reason),
            Err(DecodeError::Invalid(_)) => Event::Invalid,
            Err(_) => return Err("unexpected header resource or policy error"),
        })
    }
}

impl Operation<Ordering> for KeyComparison<'_> {
    fn advance(&mut self, meter: &mut Meter) -> Result<Event<Ordering>, &'static str> {
        Ok(match self.step(meter) {
            Ok(ComparisonStep::Progress) => Event::Progress,
            Ok(ComparisonStep::Complete(ordering)) => Event::Complete(ordering),
            Ok(ComparisonStep::Finished) => Event::Finished,
            Err(BoundedError::Refused(reason)) => Event::Refused(reason),
            Err(_) => return Err("unexpected comparison resource error"),
        })
    }
}

#[test]
fn common_driver_resumes_a_real_header_cursor_with_production_offsets() {
    let wire = [0x19, 0x01, 0x00];
    let mut m = meter();
    m.fail_at = Some((0, Refusal::Work));
    let pool = m.pool.clone();
    let mut operation = Driver::from_operation(HeaderCursor::new(&wire), m);
    assert_eq!(operation.operation().acquired(), 0);
    resume(&mut operation, Refusal::Work);
    assert_eq!(operation.output.as_ref().unwrap().argument, 256);
    assert_eq!(operation.output.as_ref().unwrap().length, 3);
    assert_eq!(operation.operation().acquired(), 3);
    assert_eq!((operation.meter.values, operation.meter.bytes), (4, 6));
    assert_eq!(operation.meter.calls.len(), 5);
    assert_eq!(operation.invocations, 1);
    operation.meter.assert_units(3, 64);
    assert_eq!(operation.step(), Ok(Step::Finished));
    drop(operation);
    assert_eq!(pool.live(), 0);
}

#[test]
fn common_driver_resumes_comparison_without_reexamining_its_prefix() {
    let left = [b'a'; 257];
    let mut right = left;
    right[256] = b'b';
    let m = meter();
    let pool = m.pool.clone();
    let mut operation = Driver::from_operation(KeyComparison::new(&left, &right), m);
    assert_eq!(operation.step(), Ok(Step::Progress));
    assert_eq!(operation.operation().position(), 64);
    operation.meter.fail_at = Some((1, Refusal::Work));
    assert_eq!(operation.step(), Ok(Step::Refused(Refusal::Work)));
    assert_eq!(operation.meter.refused, Some((1, Refusal::Work)));
    assert_eq!(operation.operation().position(), 64);
    assert!(operation.output.is_none());
    operation.meter.fail_at = None;
    finish(&mut operation, 4);
    assert_eq!(operation.output, Some(Ordering::Less));
    assert_eq!(operation.operation().position(), 257);
    assert_eq!((operation.meter.values, operation.meter.bytes), (5, 257));
    assert_eq!(operation.meter.calls.len(), 6);
    assert_eq!(operation.invocations, 1);
    operation.meter.assert_units(3, 64);
    assert_eq!(operation.step(), Ok(Step::Finished));
    drop(operation);
    assert_eq!(pool.live(), 0);
}
