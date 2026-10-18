#![deny(warnings)]
use dcbor::{bounded::BoundedEncodable, CBORBoundedEncodable};

#[derive(CBORBoundedEncodable)]
struct Generic<A, B, P, const N: usize> {
    #[cbor(n = 0)]
    count: [A; N],
    #[cbor(n = 1)]
    plan: B,
    #[cbor(n = 2)]
    output: Option<P>,
}

#[derive(CBORBoundedEncodable)]
struct Newtype<__DcborAllocator, __DcborBudget, __DcborPermit>(
    Generic<__DcborAllocator, __DcborBudget, __DcborPermit, 2>,
);

#[derive(CBORBoundedEncodable)]
enum Named {
    #[cbor(n = 0)]
    Item {
        #[cbor(n = 0)]
        count: u64,
        #[cbor(n = 1)]
        payload: String,
        #[cbor(n = 2)]
        write: bool,
        #[cbor(n = 3)]
        measured: u64,
        #[cbor(n = 4)]
        map: u64,
        #[cbor(n = 5)]
        plan: Option<String>,
        #[cbor(n = 6)]
        output: u64,
        #[cbor(n = 7)]
        budget: u64,
        #[cbor(n = 8)]
        allocator: u64,
        #[cbor(n = 9)]
        f0: u64,
        #[cbor(n = 10)]
        v: u64,
    },
}

#[derive(CBORBoundedEncodable)]
enum Empty {}

#[derive(CBORBoundedEncodable)]
struct Borrowed<'a, T: ?Sized>
where
    T: BoundedEncodable,
{
    #[cbor(n = 0)]
    value: &'a T,
}

fn assert_bounded<T: BoundedEncodable>() {}
fn main() {
    assert_bounded::<Generic<bool, u64, String, 3>>();
    assert_bounded::<Newtype<bool, u64, String>>();
    assert_bounded::<Empty>();
    assert_bounded::<Borrowed<'_, str>>();
    let _ = Named::Item {
        count: 0,
        payload: String::new(),
        write: false,
        measured: 0,
        map: 0,
        plan: None,
        output: 0,
        budget: 0,
        allocator: 0,
        f0: 0,
        v: 0,
    };
}
