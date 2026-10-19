use super::harness::*;
use dcbor::bounded::{
    Allocator, BoundedEncodable, BoundedError, BoundedResult, Budget, Cursor, Measure, Output,
    Plan, WriteWork, prepare,
};

struct Underreported {
    predicted: WriteWork,
    second: WriteWork,
}

impl BoundedEncodable for Underreported {
    fn measure<A: Allocator>(
        &self,
        _: &mut Plan<A::Permit>,
        _: &mut A,
    ) -> BoundedResult<Measure, A> {
        Ok(Measure {
            len: 2,
            write: self.predicted,
        })
    }

    fn write<P, B: Budget>(
        &self,
        _: &mut Cursor<'_, P>,
        output: &mut Output<'_>,
        budget: &mut B,
    ) -> BoundedResult<(), B> {
        budget.traverse(1, 1).map_err(BoundedError::Refused)?;
        output.byte(0x81)?;
        budget
            .traverse(self.second.values, self.second.bytes)
            .map_err(BoundedError::Refused)?;
        output.byte(0x01)
    }
}

#[test]
fn underestimated_work_is_a_bound_defect_before_the_offending_write() {
    for second in [WriteWork::new(1, 0), WriteWork::new(0, 1)] {
        let value = Underreported {
            predicted: WriteWork::new(1, 1),
            second,
        };
        let mut allocator = meter();
        let prepared = prepare(&value, &mut allocator).unwrap();
        let mut output = [0xee; 2];
        let mut budget = meter();
        let error = prepared.encode_into(&mut output, &mut budget).unwrap_err();
        assert!(
            matches!(error, BoundedError::WorkExceeded { predicted, attempted }
            if predicted == value.predicted && attempted == WriteWork::new(1 + second.values, 1 + second.bytes))
        );
        assert_eq!(output, [0x81, 0xee]);
        assert_eq!(
            budget.calls,
            [Call::Work {
                values: 1,
                bytes: 1
            }]
        );
        assert!(
            budget.refused.is_none(),
            "bound defect was misclassified as caller refusal"
        );
        assert_eq!((budget.values, budget.bytes), (1, 1));
        drop(prepared);
        assert_eq!(allocator.pool.live(), 0);
    }
}

#[test]
fn caller_refusal_within_valid_bound_keeps_its_class_and_paid_prefix() {
    let value = Underreported {
        predicted: WriteWork::new(2, 2),
        second: WriteWork::new(1, 1),
    };
    let mut allocator = meter();
    let prepared = prepare(&value, &mut allocator).unwrap();
    for reason in [Refusal::Work, Refusal::Capacity, Refusal::Deadline] {
        let mut output = [0xee; 2];
        let mut budget = meter();
        budget.fail_at = Some((1, reason));
        assert!(matches!(prepared.encode_into(&mut output, &mut budget),
            Err(BoundedError::Refused(actual)) if actual == reason));
        assert_eq!(budget.refused, Some((1, reason)));
        assert_eq!((budget.values, budget.bytes), (1, 1));
        assert_eq!(output, [0x81, 0xee]);
    }
    let mut output = [0; 2];
    let mut budget = meter();
    prepared.encode_into(&mut output, &mut budget).unwrap();
    assert_eq!(output, [0x81, 0x01]);
    assert_eq!((budget.values, budget.bytes), (2, 2));
    drop(prepared);
    assert_eq!(allocator.pool.live(), 0);
}
