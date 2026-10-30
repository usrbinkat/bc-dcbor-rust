# Blockchain Commons Deterministic CBOR ("dCBOR") for Rust

<!--Guidelines: https://github.com/BlockchainCommons/secure-template/wiki -->

### _by Wolf McNally_

---

`dcbor` implements the dCBOR application profile defined in the IETF Internet Draft [draft-mcnally-deterministic-cbor](https://datatracker.ietf.org/doc/draft-mcnally-deterministic-cbor/). The dCBOR application profile first requires conformance to CBOR Common Deterministic Encoding (CDE) rules, which include:

- Integers must use their shortest possible representation
- Floating-point numbers must use their shortest possible representation
- Map keys must be sorted in bytewise lexicographic order
- Indefinite-length items are not allowed

On top of CDE, dCBOR adds these additional rules:

- Maps must not contain duplicate keys
- Numeric reduction: floating-point values that can be represented as integers in the range [-2^63, 2^64-1] must be encoded as integers
- All NaN values must be reduced to a single canonical representation (quiet NaN with half-width representation 0xf97e00)
- Only certain "simple values" are allowed: false (0xf4), true (0xf5), null (0xf6), and floating-point values
- Text strings must be in Unicode Normalization Form C (NFC)

dCBOR encoders must only emit CBOR conforming to these rules, and dCBOR decoders must validate that encoded CBOR conforms to these requirements.

This deterministic approach ensures that semantically equivalent data items are encoded into identical byte streams, which is essential for applications requiring cryptographic verification, content-based addressing, and consistent hashing.

## Getting Started

```toml
[dependencies]
dcbor = "0.25.2"
```

## Retained schema encoding

The default `std` build does not implement bounded encoding for
`std::collections::HashMap`: its public API exposes neither indexed buckets nor
an allocation-based scan bound. With `hashbrown` enabled, use the pinned
hashbrown `HashMap` or `HashTable` directly. No conversion is performed implicitly.

The `dcbor::hashbrown` re-export names the exact pinned dependency that supplies
these implementations. Consumers can use
`dcbor::hashbrown::HashMap<K, V, std::hash::RandomState>` for untrusted keys,
constructing it with `HashMap::with_hasher(RandomState::new())`.

The opt-in `custom-std-collections` feature enables the std `HashMap`
implementations and requires a rebuilt standard library exposing
`hashmap_bucket_access`. An unmodified nightly compiler is insufficient, and
`--all-features` also requires this custom toolchain. That API exposes physical
bucket count, indexed shared bucket access, and allocation size from the owning
hash table. A Cargo dependency override does not replace compiled std. The
custom standard-library development shell supplies that library; qualification
results must identify the fork revision and patch used.

Every bounded encoding runs on one engine, `bounded::encoding::Preparation`,
over a value's `bounded::Schema`. `bounded::encode` walks the value's shape
(`encoding::Shape::of`), prepares its plan in an arena capped at the walked
extent and a widest head per map, and publishes that arena in place as the
encoding (`Prepared::publish`): nothing is allocated or copied for the output.
`bounded::prepare` stops at the plan; `Prepared::encode_into` writes it into a
caller's exactly sized slice and `Prepared::encode_owned` into storage the
caller admits separately. `bounded::encode_bound` bounds the whole of `encode`
from the walked shape.

With the `derive` feature, `CBORBoundedEncodable` generates the `Schema`. Named
structs use canonical integer-key maps; absent optional fields are omitted. A
derived map's head carries its count at once: the presence checks of its
optional fields are announced and admitted first (`Instruction::Inspect`), then
the counted head is written (`Instruction::CountedMap`), and the engine refuses
a source that visits another number of fields. Newtypes, unit structs, and unit,
tuple, and named enum variants follow the symbolic schema representation.
Type-level tags remain untagged during encoding; use `bounded::Tagged` for
explicit tag emission.

Preparation retains an explicit traversal stack, normalization state, byte
relocation, and map-header positions. Call `step` on the same preparation after a
budget refusal. `Step::Complete` returns an independently owned plan;
`plan.writer(destination)` emits into an exactly sized destination without
allocation. Writer steps copy at most 64 bytes and preserve the emitted prefix
on refusal. Preparation supports nesting up to 128 traversal frames.

Built-in schema instructions cover integers, floats, booleans, strings, byte
strings, arrays, vectors, nullable options, references, boxes, shared pointers,
`BTreeMap`, `dcbor::Map`, symbolic `CBOR`, `Date`, and, with `num-bigint`,
`BigInt` and `BigUint`. Text the NFC quick check proves normal is copied as it
is; any other text is normalized by the retained normalizer. Bignum magnitudes
are read a quantum of digits at a time, scanned once for their length and once
for their bytes.
Custom `encoding::Schema` implementations must produce each instruction in
bounded work without allocating or recursively traversing children. Dynamic-map
entry instructions may inspect at most 64 indexed bucket controls and yield at
most one entry. The engine rejects index advances outside 1 through 64; custom
implementations must also bound the actual work preceding the returned instruction.
The preparation borrow must preserve the representation throughout traversal:
a source answering differently when prepared than when its shape was walked is
refused at the arena's cap. A counted unordered map
(`Instruction::CountedUnorderedMap`) must declare the number of entries its
source holds: the map ends once that many are yielded, and one ending before
its count is refused.

Prepared plans retain canonical bytes with map-header gap metadata; only a map
whose count is unknown at its start holds a gap. Finalizing a gap's header does
not shift the payload. Dynamic-map children compact their header gaps
incrementally before their canonical bytes participate in ordering.
Preparation retains storage proportional to the encoded output in addition to
normalization scratch and traversal metadata.

Trees are walked without searching or comparing keys. On a stable toolchain a
`BTreeMap` or `dcbor::Map` is read through its standard iterator over its whole
range, each step's node moves (at most twice the tree's height) admitted before
it in units of at most a turn's three values. Under `custom-std-collections` it
is read through the forked standard
library's stepped cursor, one admitted transition per step. A `dcbor::Map` is
keyed by its keys' encodings and yields them in canonical order, so its entries
are checked in one pass over adjacent keys instead of sorted; a `BTreeMap`'s
entries are ordered by their prepared key bytes.

With `hashbrown` enabled, `Preparation` accepts a borrowed
`hashbrown::HashTable<(K, V)>` from hashbrown 0.17 whose keys and values implement
`Schema`. `bounded::encoding::maps::MapPreparation` is an alias for that same
engine. Each admitted scan inspects at most 64 buckets, including vacant buckets,
and stops at the first entry, found a control group at a time
(`next_full_bucket` in the pinned hashbrown and the forked standard library);
the charge is the 64-control window on every target. A map ends once its
declared entries are yielded, so no bucket after its last entry is scanned.
Keys and values are prepared through retained schema operations, then flat entry
descriptors are merge-ordered by canonical key bytes. Key comparisons use the
decoder's retained comparison primitive, examining at most 64 byte pairs per
turn. Equal keys are rejected during merging. Merge scratch holds only the
shorter run, and descriptor moves are admitted separately from comparisons.
Every dynamic map, the root's included, is permuted into canonical order in the
plan's own bytes, so the plan is the encoding but for its header gaps.
Descriptors stay with the preparation; the `Prepared` plan holds only its
bytes and gap records. Emission takes `O(B / 64 + g)` steps for `B` bytes and
`g` header gaps, including partial chunks, without allocation; publication in
place takes the same steps and releases the gap records.

The table interface is bucket-indexed: this path does not use `HashMap::iter`
or estimate sparse scans from insertion capacity. Table construction is a
separate caller operation. `HashTable<(K, V)>` also implements `Schema`, so tables
compose as keys and values, in vectors, and in derived records and enum variants.
Nested preparation uses one explicit frame stack and flat entry descriptors.
Completed child maps are ordered before their parent compares their canonical
bytes. Gap compaction, merge comparisons, descriptor removal, and reordered-byte
assembly each retain their positions across refusal. `Preparation::position()`
exposes these positions through its `dynamic` field. Instruction variants and
position fields have the same shape with and without the `hashbrown` feature.
Compaction uses chunks of at most 64 bytes. Reordered payloads use byte-position
permutation cycles with a retained saved byte and a visited bitmap, initialized
incrementally. No second full-payload byte buffer is allocated. Removing
plain-data suffixes is constant work; the backing allocation stays charged.
Nested already ordered payloads bypass reassembly. The permutation bitmap and offset
storage are released before returning to the parent map. Descriptor merge scratch
is retained for reuse across maps, so peak memory includes the largest shorter-run
scratch allocation encountered during preparation, until preparation is dropped.

For `B` prepared payload bytes and dynamic nesting depth `D`, compaction and
reassembly move `O(B * D)` bytes in total. Each moved byte also requires a retained
binary descriptor lookup. With at most `n` entries per dynamic map, permutation
lookup work is `O(B * D * log(n + 1))`, in addition to arena growth and key
comparison work. With `n` entries, merge ordering uses `O(n log n)` comparisons;
each comparison examines at most the shorter key's length. These are cumulative
work bounds, separate from the three-value/64-byte per-turn limit.

## Owner-backed typed decoding

`bounded::decode::construction::TypedDecoder` consumes an initialized input
handle acquired through `DecodeOwner`. Its type parameters are the input,
decoded value and allocator.
The controller starts without allocating or constructing schema fields. Stepping
it allocates one stable lifecycle record and initializes parser metadata in that
record before parsing. `Step::Complete` publishes a `TypedValue` handle;
`value()` borrows the initialized value at its construction address.

```rust
use dcbor::bounded::{Limits, Resumable, Step, decode::{Options, construction::{
    DecodeOwner, TypedDecoder, reclamation::Reclaimed,
}}};

let input = [0x62, b'o', b'k'];
let mut owner = DecodeOwner::<Limits>::new();
let mut budget = Limits::new(1_000_000, 1_000_000, 1_000_000);
owner.initialize_step(&mut budget).unwrap();
let mut acquisition = owner.borrow_input(&input);
let input = loop {
    match acquisition.step(&mut budget).unwrap() {
        Step::Progress => {}
        Step::Complete(input) => break input,
        Step::Finished => panic!("missing input"),
    }
};
drop(acquisition);
let mut decoder = TypedDecoder::<_, String, Limits>::new(input, Options::normalizing(8));
loop {
    match decoder.step(&mut budget).unwrap() {
        Step::Progress => {}
        Step::Complete(value) => {
            assert_eq!(value.value(), "ok");
            drop(value);
            break;
        }
        Step::Finished => panic!("missing output"),
    }
}
drop(decoder);
while owner.shutdown_step(&mut budget).unwrap() != Reclaimed::Done {}
assert_eq!(budget.live_bytes(), 0);
```

Dropping a controller or published handle queues its existing custody record.
The owner must be stepped to reclaim queued resources. `shutdown_step` also
closes admission; retain the input and owner until cleanup finishes. A terminal
decode error retains custody: further decoder steps perform cleanup before
returning `Finished`. A budget refusal preserves the operation for resumption
with a fresh allowance. `cancel()` selects this same explicit cleanup path.

Custom bindings implement `in_place::InPlace<A>` and mandatory
`reclamation::Reclaim<A>`. Their retained state implements `Custody`, projecting
its initialized parts, held allocations, admissions and active child obligations
under exclusive access. Observation admits and allocates nothing. `Reduction`
is optional and requires a documented cleanup simulation; containers without
one retain every stop schedule. Both construction and cleanup receive the
value as a `reclamation::Slot`: its `Place` and its retained state, the
custody paired with it, together. A slot is minted only where the value's
provenance is rooted (a record's block, a metadata block, a container's
buffer, a tree node), under `Slot::new`'s one obligation, that pairing; every
other slot is a child projected from one (`Slot::child`). So the trait
methods take slots through safe signatures: a caller holding a slot has
nothing to promise, and the `unsafe trait` contracts require each
implementation to be sound for every call its holder can make, in any order,
a cleanup step after `Done` and a build after cleanup began included. Inside
an implementation a binding reaches its parts by raw projection
(`Place::project`, `cast`, `add`), writes through `write` and
`drop_in_place`, and borrows a header exclusively only within `with_mut`,
never over bytes in which a place lies, so a place one step derives stays
valid in every later step; each of these is `unsafe`, under the state's
record of what is initialized. Every access through a place borrows the
slot's custody: a shared read (`get`) holds it shared while the read is live,
and every write, exclusive borrow or custody access (`write`,
`drop_in_place`, `with_mut`, `reach`, `as_ptr`) holds it exclusively, so the
borrow checker refuses a write under a live read or two exclusive accesses at
once. Internal metadata initialized field by field is written the same way:
a `Slot` of the destination and its units initialized, one field per
admitted unit. Completion returns a status rather than moving a schema value. The former
`ResumableDecodable::start`, schema-sized associated state, and
`BuildStep::Complete(T)` protocol have been removed. `CBORBoundedDecodable`
generates in-place bindings and a guard against user-defined synchronous `Drop`.
Enum construction requires an explicit supported representation: `repr(C)`,
`repr(u8)`, or `repr(C, u8)`.

Native `Option<T>` requires `in_place::Placeholder`: a resource-free value whose
initialization and native option representation fit 64 bytes. For larger payloads,
`in_place::StableOption<T, A>` stores a pointer to separately allocated stable
payload storage. It initializes the child in place and publishes that pointer
after completion. `as_ref()` exposes the optional borrowed payload. Its child
allocation and reservation remain in the enclosing record's incremental cleanup
path. Neither representation guesses the layout of a native `Option<T>`.

Synchronous child dispatch has a separate, pre-allocation depth limit of 64.
`Reclaim::DISPATCH_DEPTH` describes the maximum construction or cleanup call
chain; containers and derives compose child bounds with saturating arithmetic.
The owner rejects an excessive bound before reserving or allocating a record.
Custom unsafe bindings must declare their actual bound, including helper and
child dispatch; the leaf default is valid only without child delegation. This
limit is independent of the parser's input nesting limit.

Every binding also declares `Reclaim::remaining`: the most successful cleanup
calls its state can still take, the one returning `Done` included, read like
an observation. The scope holds each queued record to the count it declared
when its cleanup began and refuses a call beyond it as a defect, so every
drain, stepped or terminal, is finite. Overstating is sound; understating
violates the unsafe contract. The count is read while the value may still be
borrowed, as a published value is by the preparation encoding it, so
`remaining` receives the value's slot observed, a `reclamation::PeekSlot`:
shared reads and raw place projections of the value, no write and no
exclusive reborrow of its bytes. A record's own custody (its phase, handles
and children's construction states, grouped apart from the published value),
which no reader borrows, stays reachable through `Place::custody`, for as long
as the record's progress is borrowed exclusively.

Cleanup steps must not unwind: a step unwound half done would leave its state
recording what it no longer holds. A policy's release observer
(`Limits::observe_releases`) runs inside them, held to their contract: bounded,
nonblocking work that allocates nothing. An observer that panics aborts the
process rather than unwind out of a release, as a terminal drain that cannot
complete does.

## Verification layers

In the fork-enabled development shell:

```sh
cargo test --workspace --all-features
DCBOR_RIGOR=exhaustive cargo test --workspace --all-features
DCBOR_REACH_DIR=<reach directory> bash tests/reach-map.sh
DCBOR_REACH_DIR=<reach directory> MIRI_LOG_DIR=<log directory> bash tests/miri-owned.sh
```

Fast rigor is the default: every admission is refused once and resumed,
every physical request is failed, and stops are reduced only by certified
cleanup classes. Exhaustive additionally replays each refusal and each stop
independently and checks the reductions. Both use the same oracles.
The Miri gate runs both aliasing models with strict provenance, symbolic
alignment checks and host isolation, and compares its reached class
inventory with native execution of the same selections. It requires a
passing reach map of the same source (`DCBOR_REACH_DIR`), checked before
anything runs, and `MIRI_LOG_DIR` or `TMPDIR`, its log directory; it lists
every selection line before running any, and publishes each test's outcome
per aliasing model and build domain in `results.tsv`.

`run_tests.sh` runs the stable feature matrix; its exhaustive mode also
checks the fast feature-selection assumptions. [tests/BOUNDED.md](tests/BOUNDED.md)
documents the selection and mutation-effectiveness gate.
[tests/data/README.md](tests/data/README.md) documents checked recording,
configuration identities, complete variant inventories and matrix cost ratchets.

## Related Projects

- [dCBOR Overview](https://github.com/BlockchainCommons/crypto-commons/blob/master/dcbor.md)
- [dCBOR Library for Swift](https://github.com/BlockchainCommons/BCSwiftDCBOR)
- [dCBOR-CLI Reference App](https://github.com/BlockchainCommons/dcbor-cli)

## Status - Production-Ready

`dcbor` is now considered production-ready. The specification has been implemented by multiple third parties and extensively discussed in the IETF CBOR working group. The library provides a stable API that follows the dCBOR application profile.

We still welcome your feedback about the library. Let us know if the API meets your needs, if the functionality is easy to use, if the usage of Rust feels properly standardized, and if the library solves any problems you are encountering when doing this kind of coding. Comments can be posted [to the Gordian Developer Community](https://github.com/BlockchainCommons/Gordian-Developer-Community/discussions/116).

See [Blockchain Commons' Development Phases](https://github.com/BlockchainCommons/Community/blob/master/release-path.md).

## Version History

### 0.25.2 - March 16, 2026
- Add numeric reduction example demonstrating integer/float extraction and dCBOR canonical encoding rules.

### 0.25.1 - January 31, 2026
- Add expected-text-output-rubric comments to test files.

### 0.25.0 - December 18, 2025
- Add support for bignums via num-bigint.

### 0.24.1 - December 4, 2025
- Updated third-party dependencies.

### 0.24.0 - December 2, 2025
- Add Copy trait to Date.
- Remove AsRef<Date> implementation.

### 0.23.3 - November 12, 2025
- Format.

### 0.23.2 - November 3, 2025
- Clarify documentation.

### 0.23.1 - October 19, 2025
- Format.

### 0.23.0 - September 16, 2025
- Remove dependency on anyhow library
- Migrate thiserror from v1 to v2
- Code formatting improvements
- Improve tests

### 0.22.0 - July 2, 2025
- Added comprehensive CBOR tree traversal functionality with new walk module
- Implemented visitor pattern for structured CBOR data inspection and transformation
- Added extensive examples and test suite for walk operations
- Enhanced API with walk-related exports in prelude
- Minor documentation and formatting improvements

## Financial Support

`dcbor` is a project of [Blockchain Commons](https://www.blockchaincommons.com/). We are proudly a "not-for-profit" social benefit corporation committed to open source & open development. Our work is funded entirely by donations and collaborative partnerships with people like you. Every contribution will be spent on building open tools, technologies, and techniques that sustain and advance blockchain and internet security infrastructure and promote an open web.

To financially support further development of `dcbor` and other projects, please consider becoming a Patron of Blockchain Commons through ongoing monthly patronage as a [GitHub Sponsor](https://github.com/sponsors/BlockchainCommons). You can also support Blockchain Commons with bitcoins at our [BTCPay Server](https://btcpay.blockchaincommons.com/).

## Contributing

We encourage public contributions through issues and pull requests! Please review [CONTRIBUTING.md](./CONTRIBUTING.md) for details on our development process. All contributions to this repository require a GPG signed [Contributor License Agreement](./CLA.md).

### Discussions

The best place to talk about Blockchain Commons and its projects is in our GitHub Discussions areas.

[**Gordian Developer Community**](https://github.com/BlockchainCommons/Gordian-Developer-Community/discussions). For standards and open-source developers who want to talk about interoperable wallet specifications, please use the Discussions area of the [Gordian Developer Community repo](https://github.com/BlockchainCommons/Gordian-Developer-Community/discussions). This is where you talk about Gordian specifications such as [Gordian Envelope](https://github.com/BlockchainCommons/Gordian/tree/master/Envelope#articles), [bc-shamir](https://github.com/BlockchainCommons/bc-shamir), [Sharded Secret Key Reconstruction](https://github.com/BlockchainCommons/bc-sskr), and [bc-ur](https://github.com/BlockchainCommons/bc-ur) as well as the larger [Gordian Architecture](https://github.com/BlockchainCommons/Gordian/blob/master/Docs/Overview-Architecture.md), its [Principles](https://github.com/BlockchainCommons/Gordian#gordian-principles) of independence, privacy, resilience, and openness, and its macro-architectural ideas such as functional partition (including airgapping, the original name of this community).

[**Gordian User Community**](https://github.com/BlockchainCommons/Gordian/discussions). For users of the Gordian reference apps, including [Gordian Coordinator](https://github.com/BlockchainCommons/iOS-GordianCoordinator), [Gordian Seed Tool](https://github.com/BlockchainCommons/GordianSeedTool-iOS), [Gordian Server](https://github.com/BlockchainCommons/GordianServer-macOS), [Gordian Wallet](https://github.com/BlockchainCommons/GordianWallet-iOS), and [SpotBit](https://github.com/BlockchainCommons/spotbit) as well as our whole series of [CLI apps](https://github.com/BlockchainCommons/Gordian/blob/master/Docs/Overview-Apps.md#cli-apps). This is a place to talk about bug reports and feature requests as well as to explore how our reference apps embody the [Gordian Principles](https://github.com/BlockchainCommons/Gordian#gordian-principles).

[**Blockchain Commons Discussions**](https://github.com/BlockchainCommons/Community/discussions). For developers, interns, and patrons of Blockchain Commons, please use the discussions area of the [Community repo](https://github.com/BlockchainCommons/Community) to talk about general Blockchain Commons issues, the intern program, or topics other than those covered by the [Gordian Developer Community](https://github.com/BlockchainCommons/Gordian-Developer-Community/discussions) or the
[Gordian User Community](https://github.com/BlockchainCommons/Gordian/discussions).

### Other Questions & Problems

As an open-source, open-development community, Blockchain Commons does not have the resources to provide direct support of our projects. Please consider the discussions area as a locale where you might get answers to questions. Alternatively, please use this repository's [issues](./issues) feature. Unfortunately, we can not make any promises on response time.

If your company requires support to use our projects, please feel free to contact us directly about options. We may be able to offer you a contract for support from one of our contributors, or we might be able to point you to another entity who can offer the contractual support that you need.

### Credits

The following people directly contributed to this repository. You can add your name here by getting involved. The first step is learning how to contribute from our [CONTRIBUTING.md](./CONTRIBUTING.md) documentation.

| Name              | Role                     | Github                                           | Email                                 | GPG Fingerprint                                    |
| ----------------- | ------------------------ | ------------------------------------------------ | ------------------------------------- | -------------------------------------------------- |
| Christopher Allen | Principal Architect      | [@ChristopherA](https://github.com/ChristopherA) | \<ChristopherA@LifeWithAlacrity.com\> | FDFE 14A5 4ECB 30FC 5D22 74EF F8D3 6C91 3574 05ED  |
| Wolf McNally      | Lead Researcher/Engineer | [@WolfMcNally](https://github.com/wolfmcnally)   | \<Wolf@WolfMcNally.com\>              | 9436 52EE 3844 1760 C3DC  3536 4B6C 2FCF 8947 80AE |

## Responsible Disclosure

We want to keep all of our software safe for everyone. If you have discovered a security vulnerability, we appreciate your help in disclosing it to us in a responsible manner. We are unfortunately not able to offer bug bounties at this time.

We do ask that you offer us good faith and use best efforts not to leak information or harm any user, their data, or our developer community. Please give us a reasonable amount of time to fix the issue before you publish it. Do not defraud our users or us in the process of discovery. We promise not to bring legal action against researchers who point out a problem provided they do their best to follow the these guidelines.

### Reporting a Vulnerability

Please report suspected security vulnerabilities in private via email to ChristopherA@BlockchainCommons.com (do not use this email for support). Please do NOT create publicly viewable issues for suspected security vulnerabilities.

The following keys may be used to communicate sensitive information to developers:

| Name              | Fingerprint                                       |
| ----------------- | ------------------------------------------------- |
| Christopher Allen | FDFE 14A5 4ECB 30FC 5D22 74EF F8D3 6C91 3574 05ED |

You can import a key by running the following command with that individual’s fingerprint: `gpg --recv-keys "<fingerprint>"` Ensure that you put quotes around fingerprints that contain spaces.
