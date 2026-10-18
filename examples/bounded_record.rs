//! Before/after adapter for a hypothetical record publisher. The writer belongs
//! to the application; the encoded bytes retain their permit during write_all.
use dcbor::{CBOR, CBORBoundedEncodable, CBOREncodable, bounded::*};
use std::io::Write;

#[derive(Clone, CBOREncodable, CBORBoundedEncodable)]
struct Record {
    #[cbor(n = 0)]
    sequence: u64,
    #[cbor(n = 1)]
    name: String,
    #[cbor(n = 2)]
    note: Option<String>,
}

fn before(record: &Record, writer: &mut impl Write) -> std::io::Result<()> {
    let bytes = CBOR::from(record.clone()).to_cbor_data();
    writer.write_all(&bytes)
}

#[derive(Debug)]
enum PublishError {
    Encoding(BoundedError<LimitRefusal>),
    Transport(std::io::Error),
}

fn after(
    record: &Record,
    writer: &mut impl Write,
    limits: &mut Limits,
) -> Result<(), PublishError> {
    let bytes = encode(record, limits).map_err(PublishError::Encoding)?;
    // An encoding failure cannot expose partial CBOR to the writer. Transport
    // writes can still fail partially; framing/transactionality is its contract.
    writer
        .write_all(bytes.as_ref())
        .map_err(PublishError::Transport)
}

pub fn main() {
    let record = Record {
        sequence: 24,
        name: "e\u{301}".into(),
        note: None,
    };
    let mut old_wire = Vec::new();
    before(&record, &mut old_wire).unwrap();
    let mut new_wire = Vec::new();
    let mut limits = Limits::new(10_000, 100_000, 64_000);
    after(&record, &mut new_wire, &mut limits).unwrap();
    assert_eq!(old_wire, new_wire);
    assert_eq!(new_wire, [0xa2, 0, 0x18, 24, 1, 0x62, 0xc3, 0xa9]);
    assert_eq!(limits.live_bytes(), 0);

    let mut untouched = Vec::new();
    let mut exhausted = Limits::new(0, 0, 0);
    assert!(matches!(
        after(&record, &mut untouched, &mut exhausted),
        Err(PublishError::Encoding(BoundedError::Refused(
            LimitRefusal::Work
        )))
    ));
    assert!(untouched.is_empty());

    struct Disconnected;
    impl Write for Disconnected {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    match after(&record, &mut Disconnected, &mut limits) {
        Err(PublishError::Transport(error)) => {
            assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe)
        }
        other => panic!("unexpected publication result: {other:?}"),
    }
    assert_eq!(limits.live_bytes(), 0);
}
