//! One-request canonical-CBOR validator. Run under run-bounded-worker.sh for
//! process-level resource controls, including work that a callback conceals.
use dcbor::bounded::{Budget, Limits, Owned, decode::decode};
use std::io::{Read, Write};

#[expect(
    clippy::disallowed_methods,
    reason = "an application admits its own input and output work to its policy"
)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    const MAX_INPUT: usize = 1_048_576;
    let mut limits = Limits::new(10_000_000, 128_000_000, 64_000_000);
    let mut input = Owned::new();
    limits.traverse(0, 4096)?;
    let mut block = [0u8; 4096];
    let mut stdin = std::io::stdin().lock();
    loop {
        // Read at most one byte beyond the limit, to distinguish exact-size
        // input from oversized input without allocating an unbounded buffer.
        let allowed = (MAX_INPUT - input.len() + 1).min(block.len());
        limits.traverse(1, allowed as u64)?;
        let read = stdin.read(&mut block[..allowed])?;
        if read == 0 {
            break;
        }
        if read > MAX_INPUT - input.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "input exceeds 1 MiB",
            )
            .into());
        }
        limits.traverse(0, read as u64)?;
        input.extend_from_slice(&block[..read], &mut limits)?;
    }
    let document = decode(input.as_slice(), 128, &mut limits)?;
    let bytes = document.root().encoded();
    // Publish directly from the already-owned input; no second output buffer
    // is needed. Its storage permit remains live through this write.
    limits.traverse(0, bytes.len() as u64)?;
    std::io::stdout().lock().write_all(bytes)?;
    Ok(())
}
