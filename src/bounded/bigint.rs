//! Bignum emission uses borrowed limbs, never to_bytes_be or a cloned integer.
//! A borrow boundary applies |n|-1 to negative magnitudes without subtraction
//! storage. Wire semantics match this crate's existing tag-2/tag-3 conversions.
use super::*;
use num_bigint::{BigInt, BigUint, Sign};

struct Layout {
    bytes: u64,
    digits: u64,
    first_nonzero: usize,
}

fn layout<B: Budget>(value: &BigUint, negative: bool, budget: &mut B) -> BoundedResult<Layout, B> {
    budget.traverse(1, 0).map_err(BoundedError::Refused)?;
    let digits = widen(value.iter_u32_digits().len())?;
    budget
        .traverse(digits, mul(digits, 4)?)
        .map_err(BoundedError::Refused)?;
    let mut borrow = negative;
    let mut bits = 0;
    let mut first_nonzero = None;
    for (index, digit) in value.iter_u32_digits().enumerate() {
        if digit != 0 && first_nonzero.is_none() {
            first_nonzero = Some(index);
        }
        let (adjusted, underflow) = digit.overflowing_sub(u32::from(borrow));
        borrow = underflow;
        if adjusted != 0 {
            bits = add(
                mul(widen(index)?, 32)?,
                u64::from(32 - adjusted.leading_zeros()),
            )?;
        }
    }
    let bytes = add(bits, 7)? / 8;
    Ok(Layout {
        bytes: if negative { bytes.max(1) } else { bytes },
        digits,
        first_nonzero: first_nonzero.unwrap_or(0),
    })
}

fn measure<A: Allocator>(
    value: &BigUint,
    negative: bool,
    allocator: &mut A,
) -> BoundedResult<Measure, A> {
    let layout = layout(value, negative, allocator)?;
    Ok(Measure {
        len: add(1, item_len(layout.bytes, layout.bytes)?)?,
        write: WriteWork::new(
            add(1, mul(layout.digits, 2)?)?,
            add(mul(layout.digits, 8)?, layout.bytes)?,
        ),
    })
}

fn write<B: Budget>(
    value: &BigUint,
    negative: bool,
    output: &mut Output<'_>,
    budget: &mut B,
) -> BoundedResult<(), B> {
    let layout = layout(value, negative, budget)?;
    budget
        .traverse(layout.digits, add(mul(layout.digits, 4)?, layout.bytes)?)
        .map_err(BoundedError::Refused)?;
    output.head(
        MajorType::Tagged,
        if negative {
            crate::TAG_NEGATIVE_BIGNUM
        } else {
            crate::TAG_POSITIVE_BIGNUM
        },
    )?;
    output.head(MajorType::ByteString, layout.bytes)?;
    let mut skip = mul(layout.digits, 4)?
        .checked_sub(layout.bytes)
        .ok_or(BoundedError::Overflow)?;
    for (index, digit) in value.iter_u32_digits().enumerate().rev() {
        let adjusted = if !negative || index > layout.first_nonzero {
            digit
        } else if index == layout.first_nonzero {
            digit - 1
        } else {
            u32::MAX
        };
        for byte in adjusted.to_be_bytes() {
            if skip != 0 {
                skip -= 1;
            } else {
                output.byte(byte)?;
            }
        }
    }
    Ok(())
}

impl BoundedEncodable for BigUint {
    fn measure<A: Allocator>(
        &self,
        _: &mut Plan<A::Permit>,
        allocator: &mut A,
    ) -> BoundedResult<Measure, A> {
        measure(self, false, allocator)
    }
    fn write<P, B: Budget>(
        &self,
        _: &mut Cursor<'_, P>,
        output: &mut Output<'_>,
        budget: &mut B,
    ) -> BoundedResult<(), B> {
        write(self, false, output, budget)
    }
}
impl BoundedEncodable for BigInt {
    fn measure<A: Allocator>(
        &self,
        _: &mut Plan<A::Permit>,
        allocator: &mut A,
    ) -> BoundedResult<Measure, A> {
        allocator.traverse(1, 0).map_err(BoundedError::Refused)?;
        let measured = measure(self.magnitude(), self.sign() == Sign::Minus, allocator)?;
        Ok(Measure {
            len: measured.len,
            write: WriteWork::new(1, 0).then(measured.write)?,
        })
    }
    fn write<P, B: Budget>(
        &self,
        _: &mut Cursor<'_, P>,
        output: &mut Output<'_>,
        budget: &mut B,
    ) -> BoundedResult<(), B> {
        budget.traverse(1, 0).map_err(BoundedError::Refused)?;
        write(self.magnitude(), self.sign() == Sign::Minus, output, budget)
    }
}
