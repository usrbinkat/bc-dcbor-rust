//! Stable typed construction with explicit lifecycle custody.
use super::{Document, Node, wrong_type};

pub mod in_place;
pub mod reclamation;
mod typed;
pub use typed::{DecodeOwner, TypedDecoder, TypedPosition, TypedStep, TypedValue};

pub fn node_at<'d, 'a, P>(document: &'d Document<'a, P>, index: usize) -> Option<Node<'d, 'a>> {
    (index < document.entries.len()).then(|| Node {
        input: document.input,
        entries: document.entries.as_slice(),
        index,
    })
}

pub fn next_index(node: Node<'_, '_>) -> usize {
    node.entries[node.index].next
}
