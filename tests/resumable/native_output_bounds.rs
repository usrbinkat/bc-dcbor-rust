use dcbor::bounded::{BoundedError, Output, WriteWork};

#[test]
fn output_capacity_refusal_preserves_exact_position_and_written_bytes() {
    let mut guarded = [0xee; 7];
    {
        let mut output = Output::new(&mut guarded[1..6]);
        assert_eq!(output.written(), 0);
        output.slice::<()>(&[0x44, 1, 2]).unwrap();
        assert_eq!(output.written(), 3);
        assert!(matches!(
            output.slice::<()>(&[3, 4, 5]),
            Err(BoundedError::Capacity {
                needed: 3,
                remaining: 2
            })
        ));
        assert_eq!(
            output.written(),
            3,
            "failed write advanced the production offset"
        );
        output.slice::<()>(&[3, 4]).unwrap();
        assert_eq!(output.written(), 5);
        output.finish::<()>(5).unwrap();
    }
    assert_eq!(guarded, [0xee, 0x44, 1, 2, 3, 4, 0xee]);
}

#[test]
fn output_empty_writes_and_refused_tail_do_not_rewind_or_overwrite() {
    let mut bytes = [0xee; 2];
    let mut output = Output::new(&mut bytes);
    output.byte::<()>(0x81).unwrap();
    output.slice::<()>(&[]).unwrap();
    assert_eq!(output.written(), 1);
    output.byte::<()>(0x01).unwrap();
    assert!(matches!(
        output.byte::<()>(0),
        Err(BoundedError::Capacity {
            needed: 1,
            remaining: 0
        })
    ));
    assert_eq!(output.written(), 2);
    output.finish::<()>(2).unwrap();
    assert_eq!(bytes, [0x81, 0x01]);
}

#[test]
fn work_composition_checks_each_dimension_and_never_saturates() {
    let header = WriteWork::new(1, 9);
    let payload = WriteWork::new(0, 55);
    assert_eq!(header.then::<()>(payload).unwrap(), WriteWork::new(1, 64));
    assert_eq!(header.times::<()>(3).unwrap(), WriteWork::new(3, 27));
    let quantum = WriteWork::new(3, 64);
    assert!(quantum.covers(&WriteWork::new(3, 64)));
    assert!(!quantum.covers(&WriteWork::new(4, 0)));
    assert!(!quantum.covers(&WriteWork::new(0, 65)));
    for value in [WriteWork::new(u64::MAX, 0), WriteWork::new(0, u64::MAX)] {
        assert!(matches!(
            value.then::<()>(WriteWork::new(1, 1)),
            Err(BoundedError::Overflow)
        ));
        assert!(matches!(value.times::<()>(2), Err(BoundedError::Overflow)));
        assert_eq!(value.times::<()>(0).unwrap(), WriteWork::default());
        assert_eq!(value.then::<()>(WriteWork::default()).unwrap(), value);
    }
}
