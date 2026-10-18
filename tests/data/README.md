# Normalization conformance data

`normalization_tests.rs` is the generated Rust test corpus from
[`unicode-rs/unicode-normalization`](https://github.com/unicode-rs/unicode-normalization),
version **0.1.25**, `tests/data/normalization_tests.rs`.
Its generator, `scripts/unicode.py`, selects **Unicode 17.0.0** and reads
<https://www.unicode.org/Public/17.0.0/ucd/NormalizationTest.txt>.

The generated source retains its upstream copyright and dual-license notice.
This copy is distributed under the MIT option; the upstream MIT license is
included as `LICENSE-MIT`. The corpus has 20,034 rows.

`tests/normalization.rs` checks the five NFC identities for every row:

- NFC(source) = NFC(nfc) = NFC(nfd) = nfc
- NFC(nfkc) = NFC(nfkd) = nfkc

That is 100,170 checks of the bounded encoder against supplied expected
strings, not expectations computed by the normalization implementation.
When upgrading Unicode data, update the dependency pin, corpus, provenance,
and review the bounded normalization algorithm against the new dependency.
