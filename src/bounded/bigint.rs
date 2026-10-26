//! Bignum emission over borrowed limbs, never `to_bytes_be` or a cloned
//! integer: the encoding `num_bigint.rs` converts to, tag 2 or 3 around the
//! byte string of the magnitude's big-endian bytes, less one when negative
//! (`-1 - n` is encoded as `n`), its leading zero bytes dropped and `-1`
//! encoded as `[0]`. A scan from the least significant digit finds the
//! length and the lowest nonzero digit, from which the borrow of `n - 1`
//! propagates; a pass from the most significant digit emits the bytes. Each
//! admitted unit reads a quantum of digit bytes, so a bignum is prepared in
//! retained steps like every other value.
use super::encoding::{Instruction, PreparationPlace, Schema, Staged};
use super::*;
use num_bigint::{BigInt, BigUint, Sign, U64Digits};

/// The 64-bit digits one unit reads: a quantum of their bytes.
const DIGITS_PER_UNIT: usize = decode::construction::stable::QUANTUM / 8;

/// Reading at most [`DIGITS_PER_UNIT`] digits, in the scan or for emission:
/// one value and their bytes, at most a quantum.
pub(crate) const DIGITS: Capped<PreparationPlace> = Capped::new(
    PreparationPlace::Digits,
    1,
    decode::construction::stable::QUANTUM as u64,
);

/// The work of one pass over `digits` 64-bit digits of `bignums` bignums:
/// units of at most a quantum of their bytes, each bignum's last partial.
pub(crate) fn digits_work<R>(digits: u64, bignums: u64) -> Result<WriteWork, BoundedError<R>> {
    DIGITS.covering(mul(digits, 8)?, bignums)
}

impl Schema for BigUint {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        match index {
            0 => Instruction::Bignum {
                magnitude: self,
                negative: false,
            },
            _ => Instruction::End,
        }
    }
}

impl Schema for BigInt {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        match index {
            0 => Instruction::Bignum {
                magnitude: self.magnitude(),
                negative: self.sign() == Sign::Minus,
            },
            _ => Instruction::End,
        }
    }
}

/// Where a bignum is: scanning its digits, or emitting its bytes.
enum Phase {
    Scan,
    Emit,
}

/// A bignum being prepared: its tag staged when it begins, then its digits
/// scanned, then its byte string's head staged, then its bytes staged a
/// quantum at a time.
pub(crate) struct Bignum<'a> {
    magnitude: &'a BigUint,
    negative: bool,
    phase: Phase,
    /// The current pass over the digits: the scan from the least
    /// significant, the emission from the most. The digits it has left give
    /// those read ([`Self::read`]), so the record stays within the quantum
    /// its initialization writes at once.
    digits: U64Digits<'a>,
    /// The lowest nonzero digit's index, once the scan sees it.
    lowest: Option<usize>,
    /// The most significant digit, once the scan reads it.
    top: u64,
    /// Leading bytes of the most significant digits the emission drops.
    skip: usize,
}

impl<'a> Bignum<'a> {
    /// A bignum of `magnitude`, negative when `negative`, its tag staged.
    pub(crate) fn new(magnitude: &'a BigUint, negative: bool, staged: &mut Staged) -> Self {
        staged.head(
            MajorType::Tagged,
            Argument::Shortest(if negative {
                crate::TAG_NEGATIVE_BIGNUM
            } else {
                crate::TAG_POSITIVE_BIGNUM
            }),
        );
        Self {
            magnitude,
            negative,
            phase: Phase::Scan,
            digits: magnitude.iter_u64_digits(),
            lowest: None,
            top: 0,
            skip: 0,
        }
    }

    /// The digits read in the current pass, and whether its bytes are
    /// being emitted.
    pub(crate) fn position(&self) -> (usize, bool) {
        (self.read(), matches!(self.phase, Phase::Emit))
    }

    /// The number of 64-bit digits.
    fn count(&self) -> usize {
        self.magnitude.iter_u64_digits().len()
    }

    /// The digits the current pass has read: every digit but those it has
    /// left, from either end.
    fn read(&self) -> usize {
        self.count() - self.digits.len()
    }

    /// The encoded byte string's length: the magnitude's bytes, or the
    /// bytes of the magnitude less one when negative, at least one then.
    fn encoded_bytes(&self) -> Option<usize> {
        let digits = self.count();
        if digits == 0 {
            return (!self.negative).then_some(0);
        }
        let (index, value) = if !self.negative {
            (digits - 1, self.top)
        } else {
            // A negative magnitude is nonzero: its lowest nonzero digit
            // loses one, every digit below it borrows to all ones.
            let lowest = self.lowest?;
            if digits - 1 > lowest {
                (digits - 1, self.top)
            } else if self.top > 1 {
                (digits - 1, self.top - 1)
            } else if lowest > 0 {
                (lowest - 1, u64::MAX)
            } else {
                return Some(1);
            }
        };
        if value == 0 {
            return None;
        }
        let bits = index.checked_mul(64)? + (64 - value.leading_zeros() as usize);
        let bytes = bits.div_ceil(8);
        Some(if self.negative { bytes.max(1) } else { bytes })
    }

    /// The digit at `index`, adjusted for the sign: less one at the lowest
    /// nonzero digit and all ones below it when negative.
    fn adjusted(&self, digit: u64, index: usize) -> u64 {
        let lowest = self.lowest.unwrap_or(0);
        if !self.negative || index > lowest {
            digit
        } else if index == lowest {
            digit - 1
        } else {
            u64::MAX
        }
    }

    /// One admitted unit, once every staged byte was appended: a quantum
    /// of digits scanned, its last staging the byte string's head; or a
    /// quantum of digits read into staged bytes. True once every byte is
    /// staged.
    pub(crate) fn step<A: Allocator>(
        &mut self,
        staged: &mut Staged,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        let digits = self.count();
        let count = self.digits.len().min(DIGITS_PER_UNIT);
        DIGITS.admit(a, widen(count * 8)?)?;
        match self.phase {
            Phase::Scan => {
                for _ in 0..count {
                    let index = self.read();
                    let digit = self.digits.next().ok_or(BoundedError::PlanMismatch)?;
                    if digit != 0 && self.lowest.is_none() {
                        self.lowest = Some(index);
                    }
                    self.top = digit;
                }
                if self.digits.len() > 0 {
                    return Ok(false);
                }
                let bytes = self.encoded_bytes().ok_or(BoundedError::PlanMismatch)?;
                self.skip = digits
                    .checked_mul(8)
                    .and_then(|all| all.checked_sub(bytes))
                    .ok_or(BoundedError::PlanMismatch)?;
                staged.head(MajorType::ByteString, Argument::Shortest(widen(bytes)?));
                self.digits = self.magnitude.iter_u64_digits();
                self.phase = Phase::Emit;
                // A magnitude of no bytes is its head alone.
                Ok(bytes == 0)
            }
            Phase::Emit => {
                let mut chunk = [0u8; decode::construction::stable::QUANTUM];
                let mut filled = 0;
                for _ in 0..count {
                    let digit = self.digits.next_back().ok_or(BoundedError::PlanMismatch)?;
                    // The digit just taken from the top: those left lie
                    // below it.
                    let index = self.digits.len();
                    for byte in self.adjusted(digit, index).to_be_bytes() {
                        if self.skip > 0 {
                            self.skip -= 1;
                        } else {
                            chunk[filled] = byte;
                            filled += 1;
                        }
                    }
                }
                staged.fill(&chunk[..filled])?;
                Ok(self.digits.len() == 0)
            }
        }
    }
}
