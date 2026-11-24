//! The one canonical decomposition every bounded path reads: strict
//! validation's normalization (`text.rs`), a text shape's measurement and the
//! text continuation's source step (`text_cursor.rs`).
//!
//! Each part is handed to a sink taken as `&mut dyn FnMut(char)`, so
//! unicode-normalization's `decompose` is instantiated once, over that one
//! sink type, whose name carries no closure and so no source location: the
//! loop-bound policy (`tests/data/proofs/loop-bounds.json`) selects that one
//! monomorph, and no edit to a caller moves it.
use unicode_normalization::char::decompose_canonical;

/// `ch`'s canonical full decomposition, each part to `part` in order.
pub(crate) fn parts(ch: char, part: &mut dyn FnMut(char)) {
    decompose_canonical(ch, part);
}
