// Two contexts a binding may legitimately hold, its own and any other in
// scope, cannot be taken apart and recombined: no public API hands out a
// document, or a pending acquisition, apart from its slot, or takes them and
// a slot together. The planted control
// `tests/data/controls/context-recombination.patch` restores such a route,
// and this fixture then compiles.
use dcbor::bounded::decode::construction::Context;
use dcbor::bounded::decode::construction::reclamation::Written;
use dcbor::bounded::{Allocator, Limits};

// Another document's handle paired with this binding's own slot and node.
fn substituted<'b, 'c, 's, 'a, A: Allocator>(
    own: Context<'b, 'c, 's, 'a, u64, Written, A>,
    foreign: Context<'b, 'c, 's, 'a, u64, Written, A>,
) -> Context<'b, 'c, 's, 'a, u64, Written, A> {
    let index = own.index();
    foreign.origin().context(index, own.into_slot())
}

// Another document's node, read as data, made the node of this binding's
// own slot.
fn renoded<'b, 'c, 's, 'a, A: Allocator>(
    own: Context<'b, 'c, 's, 'a, u64, Written, A>,
    foreign: Context<'b, 'c, 's, 'a, u64, Written, A>,
) -> Option<Context<'b, 'c, 's, 'a, u64, Written, A>> {
    let index = own.index();
    foreign
        .node_at(index)
        .map(|_| foreign.origin().context(index, own.into_slot()))
}

fn main() {
    let _ = substituted::<Limits>;
    let _ = renoded::<Limits>;
}
