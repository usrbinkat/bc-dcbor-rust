//! The reference semantics of dCBOR numeric reduction, stated from an
//! `f64`'s bits alone, independently of the implementation it checks
//! ([`super::prepare_f64`]): no float arithmetic, no conversion between
//! precisions, no cast between a float and an integer. A value is decomposed
//! into its sign, odd significand and binary exponent; each rule of the
//! profile is a condition on those three integers:
//!
//! - NaN, whatever its payload and sign, is the one canonical NaN, half
//!   precision `7e00`.
//! - Zero of either sign, and every integral value in `[-2^63, 2^64 - 1]`,
//!   is that integer: unsigned, or negative with argument `-1 - v`.
//! - Every other value, the infinities included, takes the narrowest of
//!   binary16, binary32 and binary64 that represents it exactly, written as
//!   that format's bits.
//!
//! A format represents a finite value exactly when its odd significand has
//! at most the format's precision in bits, its least significant bit is at
//! or above the format's least subnormal exponent, and its leading bit is
//! at or below the format's greatest exponent.
//!
//! The one definition both the native exhaustive tests (binary16 and
//! binary32, every bit pattern) and the Kani harnesses (binary64, every bit
//! pattern, `float/proofs.rs`) check the implementation against.

use super::Numeric;

/// The one NaN dCBOR admits, as the specification states it, not as the
/// implementation names it: "the quiet NaN value having the half-width CBOR
/// representation `0xf97e00`" (draft-mcnally-deterministic-cbor-18, section
/// 2.5, Numeric Reduction, rule 1; draft source `ec77ab6`, line 202). The
/// implementation's constant is checked equal to it (`float/proofs.rs`,
/// `the_implementation_names_the_specified_nan`).
pub(crate) const SPECIFIED_NAN: u16 = 0x7e00;

/// A finite nonzero value: `(-1)^negative * significand * 2^exponent`, the
/// significand odd.
#[derive(Clone, Copy)]
struct Finite {
    negative: bool,
    significand: u64,
    exponent: i32,
}

impl Finite {
    /// The significand's bits.
    const fn width(self) -> i32 {
        (u64::BITS - self.significand.leading_zeros()) as i32
    }

    /// The binary exponent of the leading bit.
    const fn top(self) -> i32 {
        self.width() - 1 + self.exponent
    }
}

/// What an `f64`'s bits denote.
#[derive(Clone, Copy)]
enum Value {
    Nan,
    Infinite { negative: bool },
    Zero,
    Finite(Finite),
}

/// The bits of `x` decomposed (IEEE 754 binary64: one sign bit, eleven
/// exponent bits of bias 1023, fifty-two fraction bits).
fn decompose(x: f64) -> Value {
    let bits = x.to_bits();
    let negative = bits >> 63 == 1;
    let field = ((bits >> 52) & 0x7ff) as i32;
    let fraction = bits & ((1 << 52) - 1);
    if field == 0x7ff {
        return if fraction == 0 {
            Value::Infinite { negative }
        } else {
            Value::Nan
        };
    }
    // A subnormal's significand is its fraction at the least exponent; a
    // normal's carries its leading bit.
    let (significand, exponent) = if field == 0 {
        (fraction, -1074)
    } else {
        (fraction | 1 << 52, field - 1075)
    };
    if significand == 0 {
        return Value::Zero;
    }
    let shift = significand.trailing_zeros();
    Value::Finite(Finite {
        negative,
        significand: significand >> shift,
        exponent: exponent + shift as i32,
    })
}

/// A binary interchange format narrower than binary64.
struct Format {
    /// Significand bits, the leading one included.
    precision: i32,
    /// The least normal exponent.
    least: i32,
    /// The greatest exponent.
    greatest: i32,
    /// Exponent field bits.
    field: u32,
}

const BINARY16: Format = Format {
    precision: 11,
    least: -14,
    greatest: 15,
    field: 5,
};

const BINARY32: Format = Format {
    precision: 24,
    least: -126,
    greatest: 127,
    field: 8,
};

impl Format {
    /// Fraction bits.
    const fn fraction(&self) -> i32 {
        self.precision - 1
    }

    /// The exponent of a subnormal's least significant bit.
    const fn least_bit(&self) -> i32 {
        self.least - self.fraction()
    }

    /// The bits of `value` in this format, when it holds it exactly.
    fn exact(&self, value: Finite) -> Option<u64> {
        if value.width() > self.precision
            || value.exponent < self.least_bit()
            || value.top() > self.greatest
        {
            return None;
        }
        let fraction = self.fraction();
        let (field, bits) = if value.top() >= self.least {
            // A normal value: the leading bit implicit, at the fraction's
            // top, the exponent biased.
            let bias = (1 << (self.field - 1)) - 1;
            let aligned = value.significand << (fraction - (value.width() - 1));
            ((value.top() + bias) as u64, aligned & ((1 << fraction) - 1))
        } else {
            // A subnormal: the significand in units of the least bit.
            (0, value.significand << (value.exponent - self.least_bit()))
        };
        Some(self.signed(value.negative, field, bits))
    }

    /// An infinity in this format.
    fn infinite(&self, negative: bool) -> u64 {
        self.signed(negative, (1 << self.field) - 1, 0)
    }

    fn signed(&self, negative: bool, field: u64, fraction: u64) -> u64 {
        let width = self.field + self.fraction() as u32;
        (u64::from(negative) << width) | (field << self.fraction()) | fraction
    }
}

/// The integer `value` is, when it is integral and in `[-2^63, 2^64 - 1]`.
fn integer(value: Finite) -> Option<Numeric> {
    if value.exponent < 0 {
        return None;
    }
    // The magnitude has `top + 1` bits.
    let bits = value.top() + 1;
    if !value.negative {
        return (bits <= 64).then(|| Numeric::Unsigned(value.significand << value.exponent));
    }
    // A magnitude of at most 2^63: fewer than 64 bits, or 2^63 itself.
    let magnitude_fits = bits <= 63 || (value.significand == 1 && value.exponent == 63);
    magnitude_fits.then(|| Numeric::Negative((value.significand << value.exponent) - 1))
}

/// The binary64 value of binary16 `bits`, built from the bits alone (a
/// NaN's payload kept in its fraction's top bits, its quiet bit set): the
/// reference's own widening, independent of the `half` crate's, which the
/// implementation uses.
pub(crate) fn binary16(bits: u16) -> f64 {
    let negative = u64::from(bits >> 15);
    let field = u64::from((bits >> 10) & 0x1f);
    let fraction = u64::from(bits & 0x3ff);
    let magnitude = if field == 0x1f {
        if fraction == 0 {
            0x7ff0_0000_0000_0000
        } else {
            0x7ff8_0000_0000_0000 | (fraction << 42)
        }
    } else if field != 0 {
        ((field + 1023 - 15) << 52) | (fraction << 42)
    } else if fraction == 0 {
        0
    } else {
        // A subnormal, `fraction * 2^-24`: its leading bit at `top`.
        let top = 63 - u64::from(fraction.leading_zeros());
        ((top + 1023 - 24) << 52) | ((fraction << (52 - top)) & ((1 << 52) - 1))
    };
    f64::from_bits((negative << 63) | magnitude)
}

/// The binary16 bits of `x` when binary16 holds it exactly, its sign kept
/// (both zeros, both infinities); none for a NaN or a value binary16 does not
/// hold. The contract the `half` conversion is held to (`float/proofs.rs`).
pub(crate) fn binary16_bits(x: f64) -> Option<u16> {
    let sign = ((x.to_bits() >> 63) as u16) << 15;
    match decompose(x) {
        Value::Nan => None,
        Value::Zero => Some(sign),
        Value::Infinite { negative } => Some(BINARY16.infinite(negative) as u16),
        Value::Finite(value) => BINARY16.exact(value).map(|bits| bits as u16),
    }
}

/// The canonical encoding dCBOR gives `x`: the reference [`super::prepare_f64`]
/// is checked against. A float written at a width is canonical, what the
/// decoders accept (`validate_canonical_f16`, `_f32`, `_f64`), exactly when
/// this is that float at that width.
pub(crate) fn reduce(x: f64) -> Numeric {
    match decompose(x) {
        Value::Nan => Numeric::Float16(SPECIFIED_NAN),
        Value::Zero => Numeric::Unsigned(0),
        Value::Infinite { negative } => Numeric::Float16(BINARY16.infinite(negative) as u16),
        Value::Finite(value) => integer(value)
            .or_else(|| {
                BINARY16
                    .exact(value)
                    .map(|bits| Numeric::Float16(bits as u16))
            })
            .or_else(|| {
                BINARY32
                    .exact(value)
                    .map(|bits| Numeric::Float32(bits as u32))
            })
            .unwrap_or(Numeric::Float64(x.to_bits())),
    }
}
