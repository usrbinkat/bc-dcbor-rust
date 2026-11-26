// `closed` refuses map keys no field names: a type that decodes no map of
// its own has none to refuse, and declaring it is a compile error.
use dcbor::CBORDecodable;

#[derive(CBORDecodable)]
#[cbor(closed)]
struct Newtype(u64);

#[derive(CBORDecodable)]
#[cbor(closed)]
struct Unit;

#[derive(CBORDecodable)]
#[cbor(closed)]
enum Positional {
    #[cbor(n = 0)]
    Bare,
    #[cbor(n = 1)]
    One(u64),
}

fn main() {}
