<!-- draft-mcnally-deterministic-cbor-18, WIPs-IETF-draft-deterministic-cbor ec77ab6, lines 324-390 -->
# Appendix A: dCBOR Numeric Test Vectors

The following tables provide common and edge-case numeric test vectors for dCBOR encoders and decoders, and are intended to exercise the requirements of this specification.

## dCBOR Numeric Encodings

| Value                                     | dCBOR Encoding       | Note                                                                                 |
| :---------------------------------------- | :------------------- | :----------------------------------------------------------------------------------- |
| 0                                         | `00`                 |                                                                                      |
| 1                                         | `01`                 |                                                                                      |
| 23                                        | `17`                 |                                                                                      |
| 24                                        | `1818`               |                                                                                      |
| 255 (2<sup>8</sup> – 1)                   | `18ff`               |                                                                                      |
| 65535 (2<sup>16</sup> – 1)                | `19ffff`             |                                                                                      |
| 65536 (2<sup>16</sup>)                    | `1a00010000`         |                                                                                      |
| 4294967295 (2<sup>32</sup> – 1)           | `1affffffff`         |                                                                                      |
| 4294967296 (2<sup>32</sup>)               | `1b0000000100000000` |                                                                                      |
| 18446744073709551615 (2<sup>64</sup> – 1) | `1bffffffffffffffff` |                                                                                      |
| -1                                        | `20`                 |                                                                                      |
| -2                                        | `21`                 |                                                                                      |
| -127 (–2<sup>8</sup> – 1)                 | `387e`               |                                                                                      |
| -128 (–2<sup>7</sup>)                     | `387f`               |                                                                                      |
| -32768 (–2<sup>16</sup>)                  | `397fff`             |                                                                                      |
| -2147483648 (–2<sup>31</sup>)             | `3a7fffffff`         |                                                                                      |
| -9223372036854775808  (–2<sup>63</sup>)   | `3b7fffffffffffffff` |                                                                                      |
| 1.5                                       | `f93e00`             |                                                                                      |
| 2345678.25                                | `fa4a0f2b39`         |                                                                                      |
| 1.2                                       | `fb3ff3333333333333` |                                                                                      |
| 42.0                                      | `182a`               | Reduced.                                                                             |
| 2345678.0                                 | `1a0023cace`         | Reduced.                                                                             |
| -2345678.0                                | `3a0023cacd`         | Reduced.                                                                             |
| -0.0                                      | `00`                 | Reduced.                                                                             |
| 5.960464477539063e-08                     | `f90001`             | Smallest half-precision subnormal.                                                   |
| 1.401298464324817e-45                     | `fa00000001`         | Smallest single subnormal.                                                           |
| 5e-324                                    | `fb0000000000000001` | Smallest double subnormal.                                                           |
| 2.2250738585072014e-308                   | `fb0010000000000000` | Smallest double normal.                                                              |
| 6.103515625e-05                           | `f90400`             | Smallest half-precision normal.                                                      |
| 65504.0                                   | `19ffe0`             | Reduced. Largest possible half-precision.                                            |
| 33554430.0                                | `1a01fffffe`         | Reduced. Exponent 24 to test single exponent boundary.                               |
| -9223372036854774784.0                    | `3b7ffffffffffffbff` | Reduced. Most negative double that converts to int64.                                |
| 18446744073709550000.0                    | `1bfffffffffffff800` | Reduced. Largest double that can convert to uint64, almost UINT64_MAX.               |
| 18446744073709552000.0                    | `fa5f800000`         | Just too large to convert to uint64, but converts to a single, just over UINT64_MAX. |
| -18446742974197924000.0                   | `fadf7fffff`         | Large negative that converts to float, but too large for int64.                      |
| 3.4028234663852886e+38                    | `fa7f7fffff`         | Largest possible single.                                                             |
| 3.402823466385289e+38                     | `fb47efffffe0000001` | Slightly larger than largest possible single.                                        |
| 1.7976931348623157e+308                   | `fb7fefffffffffffff` | Largest double.                                                                      |
| Infinity (any size)                       | `f97c00`             | Canonicalized.                                                                       |
| -Infinity (any size)                      | `f9fc00`             | Canonicalized.                                                                       |
| NaN (any size, any payload)               | `f97e00`             | Canonicalized.                                                                       |

## Invalid dCBOR Encodings

These are valid CBOR encodings that MUST be rejected as invalid by a dCBOR-compliant decoder.

| Value                                      | CBOR Encoding        | Reason for Rejection           |
| :----------------------------------------- | :------------------- | :----------------------------- |
| 12.0                                       | `f94a00`             | Can be reduced to 12.          |
| 1.5                                        | `fb3ff8000000000000` | Not preferred encoding.        |
| -9223372036854775809 (-2<sup>63</sup> – 1) | `3b8000000000000000` | 65-bit negative integer value. |
| -18446744073709551616 (-2<sup>64</sup>)    | `3bffffffffffffffff` | 65-bit negative integer value. |
| Infinity                                   | `fb7ff0000000000000` | Not preferred encoding.        |
| Infinity                                   | `fa7f800000`         | Not preferred encoding.        |
| -Infinity                                  | `fbfff0000000000000` | Not preferred encoding.        |
| -Infinity                                  | `faff800000`         | Not preferred encoding.        |
| NaN                                        | `fb7ff9100000000001` | Not canonical NaN.             |
| NaN                                        | `faffc00001`         | Not canonical NaN.             |
| NaN                                        | `f97e01`             | Not canonical NaN.             |
