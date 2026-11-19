//! Derive macros for dcbor `CBOREncodable`, `CBORDecodable`, and the
//! bounded encoding and decoding.
//!
//! Every derive parses its input once into a validated `Schema`: field
//! keys, variant discriminants, optional fields, newtype and unit shapes,
//! and the type's tag. Duplicate field keys within one map and duplicate
//! discriminants within one enum are compile errors. Each derive generates
//! from that schema, so the symbolic encoding (`dcbor::CBOREncodable`), the
//! symbolic decoding (`TryFrom<CBOR> for T`) and the bounded encoding
//! (`dcbor::bounded::encoding::Schema`) take every representation decision
//! from one definition.
//!
//! The symbolic encoding is fallible: every field is encoded through its own
//! `CBOREncodable`, and a field that does not encode (a host map whose keys
//! collide after numeric reduction or NFC, at any depth) refuses the whole
//! record with that field's error, propagated, never discarded and never a
//! panic. No field type needs `Clone`: fields are encoded by reference.
//!
//! # Struct encoding
//!
//! Structs are encoded as CBOR maps with integer keys for compactness.
//! Each field must have a `#[cbor(n = N)]` attribute specifying its key.
//! Fields of type `Option<T>` are omitted from the map when `None`.
//! Decoding refuses a required field's absence (`MissingMapKey`) and a
//! present field of another type, an optional one included (its error,
//! never `None`), and ignores keys no field names. Each field's value is
//! moved out of the decoded map into its conversion, never copied.
//!
//! ```
//! use dcbor::prelude::*;
//! use dcbor_derive::{CBOREncodable, CBORDecodable};
//!
//! #[derive(CBOREncodable, CBORDecodable)]
//! struct Person {
//!     #[cbor(n = 0)]
//!     name: String,
//!     #[cbor(n = 1)]
//!     age: u8,
//!     #[cbor(n = 2)]
//!     email: Option<String>,
//! }
//!
//! let person = Person { name: "Ada".into(), age: 37, email: None };
//! let bytes = person.encode_cbor_data().unwrap();
//! assert_eq!(bytes, [0xa2, 0x00, 0x63, b'A', b'd', b'a', 0x01, 0x18, 37]);
//! let decoded = Person::try_from(CBOR::try_from_data(bytes).unwrap()).unwrap();
//! assert_eq!(decoded.name, "Ada");
//! assert_eq!(decoded.age, 37);
//! assert_eq!(decoded.email, None);
//! ```
//!
//! A field whose value does not encode refuses the record:
//!
//! ```
//! use std::collections::BTreeMap;
//! use dcbor::prelude::*;
//! use dcbor_derive::CBOREncodable;
//!
//! #[derive(CBOREncodable)]
//! struct Labels {
//!     #[cbor(n = 0)]
//!     names: BTreeMap<String, u8>,
//! }
//!
//! // "\u{e9}" and "e\u{301}" are distinct Rust strings, one NFC key.
//! let names = BTreeMap::from([("\u{e9}".to_string(), 1), ("e\u{301}".to_string(), 2)]);
//! assert!(matches!(
//!     Labels { names }.encode_cbor(),
//!     Err(dcbor::Error::DuplicateMapKey)
//! ));
//! ```
//!
//! # Newtype structs
//!
//! Single-field tuple structs delegate to the inner type:
//!
//! ```
//! use dcbor::prelude::*;
//! use dcbor_derive::{CBOREncodable, CBORDecodable};
//! #[derive(CBOREncodable, CBORDecodable)]
//! struct Wrapper(String);
//!
//! let bytes = Wrapper("hello".into()).encode_cbor_data().unwrap();
//! assert_eq!(bytes, [0x65, b'h', b'e', b'l', b'l', b'o']);
//! let decoded = Wrapper::try_from(CBOR::try_from_data(bytes).unwrap()).unwrap();
//! assert_eq!(decoded.0, "hello");
//! ```
//!
//! # Enums
//!
//! Enums encode as CBOR arrays `[variant_index, ...fields]`.
//! Unit variants encode as a bare integer.
//! Tuple variants encode as `[variant_index, field0, field1, ...]`.
//! Struct variants encode as `[variant_index, {map of fields}]`.
//!
//! Use `#[cbor(n = N)]` on each variant to set the discriminant.
//!
//! ```
//! use dcbor::prelude::*;
//! use dcbor_derive::{CBOREncodable, CBORDecodable};
//! #[derive(CBOREncodable, CBORDecodable)]
//! enum Shape {
//!     #[cbor(n = 0)]
//!     Circle { #[cbor(n = 0)] radius: f64 },
//!     #[cbor(n = 1)]
//!     Rectangle {
//!         #[cbor(n = 0)] width: f64,
//!         #[cbor(n = 1)] height: f64,
//!     },
//!     #[cbor(n = 2)]
//!     Point,
//! }
//!
//! assert_eq!(Shape::Point.encode_cbor_data().unwrap(), [0x02]);
//! let bytes = Shape::Rectangle { width: 2.0, height: 3.0 }
//!     .encode_cbor_data()
//!     .unwrap();
//! assert_eq!(bytes, [0x82, 0x01, 0xa2, 0x00, 0x02, 0x01, 0x03]);
//! let decoded = Shape::try_from(CBOR::try_from_data(bytes).unwrap()).unwrap();
//! assert!(matches!(decoded, Shape::Rectangle { width: 2.0, height: 3.0 }));
//! ```
//!
//! # Tagged types
//!
//! Use `#[cbor(tag = N)]` on the type to generate `CBORTagged`,
//! `CBORTaggedEncodable`, and `CBORTaggedDecodable` implementations.
//! The `TryFrom<CBOR>` impl will expect and validate the tag. The
//! `CBOREncodable` encoding, and the bounded encoding (`CBORBoundedEncodable`),
//! emit the untagged value; the tagged form is
//! `CBORTaggedEncodable::tagged_cbor`, whose untagged part is the
//! `CBOREncodable` encoding, its failure propagated.
//!
//! ```
//! use dcbor::prelude::*;
//! use dcbor_derive::{CBOREncodable, CBORDecodable};
//! #[derive(CBOREncodable, CBORDecodable)]
//! #[cbor(tag = 42)]
//! struct Tagged {
//!     #[cbor(n = 0)]
//!     data: Vec<u8>,
//! }
//!
//! # fn main() -> dcbor::Result<()> {
//! let value = Tagged { data: vec![1, 2] };
//! assert_eq!(value.encode_cbor_data()?, [0xa1, 0x00, 0x82, 0x01, 0x02]);
//! let bytes = value.tagged_cbor_data()?;
//! assert_eq!(bytes, [0xd8, 42, 0xa1, 0x00, 0x82, 0x01, 0x02]);
//! let decoded = Tagged::try_from(CBOR::try_from_data(bytes)?)?;
//! assert_eq!(decoded.data, [1, 2]);
//! assert!(Tagged::try_from(value.untagged_cbor()?).is_err());
//! # Ok(())
//! # }
//! ```
//!
//! # Bounded encoding
//!
//! `CBORBoundedEncodable` generates `dcbor::bounded::encoding::Schema`: the
//! type's encoding as constant-work instructions, prepared by the bounded
//! engine into the bytes the symbolic conversion produces. A map's head
//! carries its count at once: the required fields and each optional field
//! present, its presence checks announced first so they are admitted
//! before they are made. Map fields are written in the order of their
//! encoded keys, decided here from the schema: the keys are unsigned
//! integers, whose shortest encodings order as the integers do.
//!
//! ```
//! use dcbor::bounded::{BoundedError, LimitRefusal, Limits, encode, prepare};
//! use dcbor_derive::CBORBoundedEncodable;
//!
//! #[derive(CBORBoundedEncodable)]
//! struct Record {
//!     #[cbor(n = 1)] count: u64,
//!     #[cbor(n = 0)] enabled: bool,
//!     #[cbor(n = 2)] note: Option<String>,
//! }
//! let value = Record { count: 24, enabled: true, note: None };
//! let encoded = encode(&value, &mut Limits::unlimited()).unwrap();
//! assert_eq!(encoded.as_ref(), [0xa2, 0x00, 0xf5, 0x01, 0x18, 0x18]);
//!
//! // The shape walk allocates nothing; preparation refuses at its first
//! // allocation when no storage is allowed.
//! assert!(matches!(
//!     prepare(&value, &mut Limits::new(1_000, 1_000, 0)).map(|prepared| prepared.len()),
//!     Err(BoundedError::Refused(LimitRefusal::Storage))
//! ));
//! ```

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Data, DeriveInput, Error, Fields, Ident, Result, Type, parse_macro_input};
mod cddl;
mod construction;
mod encoding;

/// Derive `dcbor::CBOREncodable`: the fallible symbolic encoding, every field
/// encoded through its own `CBOREncodable` by reference, a field's failure
/// propagated. A tagged type also gets `CBORTagged` and `CBORTaggedEncodable`.
#[proc_macro_derive(CBOREncodable, attributes(cbor))]
pub fn derive_cbor_encodable(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match Schema::parse(&input).map(|schema| schema.encodable()) {
        Ok(tokens) => tokens.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

/// Derive `TryFrom<dcbor::CBOR> for T`, making the type CBORDecodable.
#[proc_macro_derive(CBORDecodable, attributes(cbor))]
pub fn derive_cbor_decodable(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match Schema::parse(&input).map(|schema| schema.decodable()) {
        Ok(tokens) => tokens.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

/// Derive both `dcbor::CBOREncodable` and `TryFrom<CBOR> for T`.
#[proc_macro_derive(CBORCodable, attributes(cbor))]
pub fn derive_cbor_codable(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match Schema::parse(&input) {
        Ok(schema) => {
            let enc = schema.encodable();
            let dec = schema.decodable();
            quote! { #enc #dec }.into()
        }
        Err(e) => e.to_compile_error().into(),
    }
}

/// Derive `dcbor::bounded::encoding::Schema`, the bounded encoding, from the
/// same schema as the symbolic conversions.
#[proc_macro_derive(CBORBoundedEncodable, attributes(cbor))]
pub fn derive_cbor_bounded_encodable(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match Schema::parse(&input).map(|schema| encoding::expand(&schema)) {
        Ok(tokens) => tokens.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

/// Derive retained in-place construction
/// (`dcbor::bounded::decode::construction::in_place::InPlace` and
/// `reclamation::Reclaim`) from the same schema as `TryFrom<CBOR>`: the same
/// field keys, optional-field omission, unknown keys ignored, discriminants
/// and tag, read from a strictly decoded document without a symbolic tree.
/// The one typed-construction engine: `decode_typed` drives it to
/// completion.
#[proc_macro_derive(CBORBoundedDecodable, attributes(cbor))]
pub fn derive_cbor_bounded_decodable(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match Schema::parse(&input).map(|schema| construction::expand(&schema)) {
        Ok(tokens) => tokens.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

/// Derive `dcbor::cddl::Cddl`: the type's CDDL rule, generated from the
/// same schema as the symbolic and bounded decoders, so the published
/// schema and the decoders take every representation decision from one
/// definition.
#[proc_macro_derive(CBORCddl, attributes(cbor))]
pub fn derive_cbor_cddl(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match Schema::parse(&input).map(|schema| cddl::expand(&schema)) {
        Ok(tokens) => tokens.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

// ---------------------------------------------------------------------------
// Attribute parsing
// ---------------------------------------------------------------------------

/// The `n = N` of a `#[cbor(...)]` attribute among `attrs`, or `None` when
/// there is no `cbor` attribute.
fn parse_n(attrs: &[syn::Attribute]) -> Result<Option<(u64, proc_macro2::Span)>> {
    let mut key = None;
    for attr in attrs {
        if attr.path().is_ident("cbor") {
            if key.is_some() {
                return Err(Error::new_spanned(
                    attr,
                    "repeated #[cbor(n = N)] attribute",
                ));
            }
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("n") {
                    if key.is_some() {
                        return Err(meta.error("repeated `n`"));
                    }
                    let value = meta.value()?;
                    let lit: syn::LitInt = value.parse()?;
                    key = Some((lit.base10_parse::<u64>()?, lit.span()));
                    Ok(())
                } else {
                    Err(meta.error("expected `n = N`"))
                }
            })?;
            if key.is_none() {
                return Err(Error::new_spanned(attr, "missing `n = N` in #[cbor(...)]"));
            }
        }
    }
    Ok(key)
}

fn parse_tag(input: &DeriveInput) -> Result<Option<u64>> {
    let mut tag = None;
    for attr in &input.attrs {
        if attr.path().is_ident("cbor") {
            if tag.is_some() {
                return Err(Error::new_spanned(
                    attr,
                    "repeated #[cbor(tag = N)] attribute",
                ));
            }
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("tag") {
                    if tag.is_some() {
                        return Err(meta.error("repeated `tag`"));
                    }
                    let value = meta.value()?;
                    let lit: syn::LitInt = value.parse()?;
                    tag = Some(lit.base10_parse::<u64>()?);
                    Ok(())
                } else {
                    Err(meta.error("expected `tag = N`"))
                }
            })?;
            if tag.is_none() {
                return Err(Error::new_spanned(
                    attr,
                    "missing `tag = N` in #[cbor(...)]",
                ));
            }
        }
    }
    Ok(tag)
}

fn is_option(ty: &Type) -> bool {
    if let Type::Path(p) = ty
        && let Some(seg) = p.path.segments.last()
    {
        return seg.ident == "Option";
    }
    false
}

fn reject_tuple_attributes(fields: &syn::FieldsUnnamed) -> Result<()> {
    for field in &fields.unnamed {
        for attr in &field.attrs {
            if attr.path().is_ident("cbor") {
                return Err(Error::new_spanned(
                    attr,
                    "tuple fields do not have CBOR keys or tags",
                ));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

/// One field of a map: its identifier, key, and whether it is optional.
struct MapField {
    ident: Ident,
    key: u64,
    optional: bool,
}

/// The fields of one map, in declaration order, their keys validated
/// unique.
struct MapFields(Vec<MapField>);

impl MapFields {
    fn parse(fields: &syn::FieldsNamed) -> Result<Self> {
        let mut parsed: Vec<MapField> = Vec::new();
        for field in &fields.named {
            let (key, span) = parse_n(&field.attrs)?
                .ok_or_else(|| Error::new_spanned(field, "missing #[cbor(n = N)] attribute"))?;
            if let Some(earlier) = parsed.iter().find(|earlier| earlier.key == key) {
                return Err(Error::new(
                    span,
                    format!("field key {key} is already the key of `{}`", earlier.ident),
                ));
            }
            parsed.push(MapField {
                ident: field
                    .ident
                    .clone()
                    .ok_or_else(|| Error::new_spanned(field, "a map field must be named"))?,
                key,
                optional: is_option(&field.ty),
            });
        }
        Ok(Self(parsed))
    }

    /// The fields in the order of their encoded keys: unsigned integer
    /// keys' shortest encodings order as the integers do.
    fn in_key_order(&self) -> Vec<&MapField> {
        let mut ordered: Vec<&MapField> = self.0.iter().collect();
        ordered.sort_by_key(|field| field.key);
        ordered
    }

    fn idents(&self) -> Vec<&Ident> {
        self.0.iter().map(|field| &field.ident).collect()
    }
}

/// One enum variant.
struct Variant {
    ident: Ident,
    discriminant: u64,
    kind: VariantKind,
}

enum VariantKind {
    Unit,
    Tuple(usize),
    Named(MapFields),
}

/// A schema's representation. A newtype's one field is read from the input
/// itself where a generator needs its type.
enum Shape {
    Map(MapFields),
    Newtype,
    Unit,
    Enum(Vec<Variant>),
}

/// A derive input parsed and validated once; every derive generates from
/// it.
struct Schema<'a> {
    input: &'a DeriveInput,
    tag: Option<u64>,
    shape: Shape,
}

impl<'a> Schema<'a> {
    fn parse(input: &'a DeriveInput) -> Result<Self> {
        let tag = parse_tag(input)?;
        let shape = match &input.data {
            Data::Struct(data) => match &data.fields {
                Fields::Named(fields) => Shape::Map(MapFields::parse(fields)?),
                Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                    reject_tuple_attributes(fields)?;
                    Shape::Newtype
                }
                Fields::Unnamed(_) => {
                    return Err(Error::new_spanned(
                        &input.ident,
                        "tuple structs with more than one field are not supported; \
                         use a named struct with #[cbor(n = N)] attributes",
                    ));
                }
                Fields::Unit => Shape::Unit,
            },
            Data::Enum(data) => {
                let mut variants: Vec<Variant> = Vec::new();
                for variant in &data.variants {
                    if let Some((_, discriminant)) = &variant.discriminant {
                        return Err(Error::new_spanned(
                            discriminant,
                            "use #[cbor(n = N)] instead of a Rust discriminant",
                        ));
                    }
                    let (discriminant, span) = parse_n(&variant.attrs)?.ok_or_else(|| {
                        Error::new_spanned(variant, "missing #[cbor(n = N)] attribute on variant")
                    })?;
                    if let Some(earlier) = variants
                        .iter()
                        .find(|earlier| earlier.discriminant == discriminant)
                    {
                        return Err(Error::new(
                            span,
                            format!(
                                "discriminant {discriminant} is already the discriminant of `{}`",
                                earlier.ident
                            ),
                        ));
                    }
                    let kind = match &variant.fields {
                        Fields::Unit => VariantKind::Unit,
                        Fields::Unnamed(fields) => {
                            reject_tuple_attributes(fields)?;
                            VariantKind::Tuple(fields.unnamed.len())
                        }
                        Fields::Named(fields) => VariantKind::Named(MapFields::parse(fields)?),
                    };
                    variants.push(Variant {
                        ident: variant.ident.clone(),
                        discriminant,
                        kind,
                    });
                }
                Shape::Enum(variants)
            }
            Data::Union(_) => return Err(Error::new_spanned(input, "unions are not supported")),
        };
        Ok(Self { input, tag, shape })
    }

    fn name(&self) -> &Ident {
        &self.input.ident
    }

    /// A generic parameter name for a generated method, `prefix` extended
    /// with `_` until it differs from every type and const parameter of the
    /// input, at mixed-site hygiene.
    fn fresh(&self, prefix: &str) -> Ident {
        let mut candidate = prefix.to_string();
        while self.input.generics.params.iter().any(|param| match param {
            syn::GenericParam::Type(p) => p.ident == candidate,
            syn::GenericParam::Const(p) => p.ident == candidate,
            syn::GenericParam::Lifetime(_) => false,
        }) {
            candidate.push('_');
        }
        Ident::new(&candidate, proc_macro2::Span::mixed_site())
    }

    /// Bounds apply to the representation's field types, not indiscriminately
    /// to every type parameter. Optional map entries encode their inner type.
    fn field_types(&self) -> Vec<&Type> {
        let groups: Vec<&Fields> = match &self.input.data {
            Data::Struct(data) => vec![&data.fields],
            Data::Enum(data) => data.variants.iter().map(|v| &v.fields).collect(),
            Data::Union(_) => unreachable!(),
        };
        let mut types = Vec::new();
        for fields in groups {
            for field in fields {
                let mut ty = &field.ty;
                if matches!(fields, Fields::Named(_))
                    && is_option(ty)
                    && let Type::Path(path) = ty
                    && let Some(segment) = path.path.segments.last()
                    && let syn::PathArguments::AngleBracketed(args) = &segment.arguments
                    && let Some(syn::GenericArgument::Type(inner)) = args.args.first()
                {
                    ty = inner;
                }
                types.push(ty);
            }
        }
        types
    }
}

fn bindings(count: usize) -> Vec<Ident> {
    (0..count)
        .map(|i| Ident::new(&format!("f{}", i), proc_macro2::Span::call_site()))
        .collect()
}

// ---------------------------------------------------------------------------
// Encodable expansion
// ---------------------------------------------------------------------------

/// `map.insert` of every field of `fields`, each the alias `access` names
/// (owned or a reference: `Map::insert` moves an owned field into its
/// encoding and borrows a referenced one), its encoding's failure (a field
/// that does not encode, or a key
/// refused) propagated with `?`, never discarded and never a panic. The keys
/// are the field keys this derive refuses to repeat at compile time
/// (`duplicate_keys`), so a refusal comes from a field's own encoding.
fn map_inserts(
    fields: &MapFields,
    map: &Ident,
    access: impl Fn(&Ident) -> TokenStream2,
) -> Vec<TokenStream2> {
    fields
        .0
        .iter()
        .map(|field| {
            let key = field.key;
            let value = access(&field.ident);
            if field.optional {
                quote! {
                    if let ::core::option::Option::Some(v) = #value {
                        #map.insert(#key, v)?;
                    }
                }
            } else {
                quote! {
                    #map.insert(#key, #value)?;
                }
            }
        })
        .collect()
}

impl Schema<'_> {
    fn encodable(&self) -> TokenStream2 {
        let name = self.name();
        let mut generics = self.input.generics.clone();
        for ty in self.field_types() {
            generics
                .make_where_clause()
                .predicates
                .push(syn::parse_quote!(#ty: dcbor::CBOREncodable));
        }
        let (tag_generics, tag_types, tag_where) = self.input.generics.split_for_impl();
        let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

        let tagged_impls = match self.tag {
            Some(tag_value) => quote! {
                impl #tag_generics dcbor::CBORTagged for #name #tag_types #tag_where {
                    fn cbor_tags() -> dcbor::Vec<dcbor::Tag> {
                        dcbor::__derive::tags(#tag_value)
                    }
                }

                impl #impl_generics dcbor::CBORTaggedEncodable for #name #ty_generics #where_clause {
                    fn untagged_cbor(&self) -> dcbor::Result<dcbor::CBOR> {
                        <Self as dcbor::CBOREncodable>::encode_cbor(self)
                    }
                }
            },
            None => quote! {},
        };

        let borrowed = self.encode_body(false);
        let owned = self.encode_body(true);
        quote! {
            impl #impl_generics dcbor::CBOREncodable for #name #ty_generics #where_clause {
                fn encode_cbor(&self) -> dcbor::Result<dcbor::CBOR> {
                    #borrowed
                }

                fn into_encoded_cbor(self) -> dcbor::Result<dcbor::CBOR> {
                    #owned
                }
            }
            #tagged_impls
        }
    }

    /// The body of the symbolic encoding, by reference (`owned` false, the
    /// receiver `&self`) or by value (`owned` true, the receiver `self`):
    /// one definition for both. The value is destructured into
    /// expansion-owned aliases (`f0`, `f1`, ...), so a field never shadows a
    /// local of the expansion; under a reference, match ergonomics bind the
    /// aliases as references. Every field is encoded through
    /// `CBOREncodable::into_encoded_cbor` (a map insertion calls it too): an
    /// owned field moves into its encoding, and a borrowed one, a `&T`,
    /// encodes through the reference's impl, which borrows. Every path is
    /// fully qualified (`dcbor::__derive`, `dcbor`'s types, `::core`), so
    /// the expansion resolves whatever the user's crate names `Vec`, `vec!`,
    /// `From`, `Ok` or `Some`.
    ///
    /// A type that implements `Drop` cannot be destructured by value, so it
    /// cannot derive this encoding; it implements `CBOREncodable` by hand.
    fn encode_body(&self, owned: bool) -> TokenStream2 {
        let name = self.name();
        let value = if owned {
            quote! { self }
        } else {
            quote! { *self }
        };
        let ok = quote! { ::core::result::Result::Ok };
        match &self.shape {
            Shape::Map(fields) => {
                let names = fields.idents();
                let aliases = bindings(names.len());
                let map = Ident::new("map", proc_macro2::Span::call_site());
                let inserts = map_inserts(fields, &map, |field| {
                    let index = names.iter().position(|name| *name == field).unwrap();
                    let alias = &aliases[index];
                    quote! { #alias }
                });
                let pattern = if owned {
                    quote! { #name { #(#names: #aliases),* } }
                } else {
                    quote! { #name { #(#names: ref #aliases),* } }
                };
                quote! {
                    let #pattern = #value;
                    let mut map = dcbor::Map::new();
                    #(#inserts)*
                    #ok(dcbor::__derive::map(map))
                }
            }
            Shape::Newtype => {
                let pattern = if owned {
                    quote! { #name(f0) }
                } else {
                    quote! { #name(ref f0) }
                };
                quote! {
                    let #pattern = #value;
                    dcbor::CBOREncodable::into_encoded_cbor(f0)
                }
            }
            Shape::Unit => quote! { #ok(dcbor::CBOR::null()) },
            Shape::Enum(variants) if variants.is_empty() => quote! { match #value {} },
            Shape::Enum(variants) => {
                let binding = if owned {
                    quote! {}
                } else {
                    quote! { ref }
                };
                let arms = variants.iter().map(|variant| {
                    let disc = variant.discriminant;
                    let vname = &variant.ident;
                    match &variant.kind {
                        VariantKind::Unit => quote! {
                            #name::#vname => #ok(dcbor::__derive::discriminant(#disc)),
                        },
                        VariantKind::Tuple(count) => {
                            let bindings = bindings(*count);
                            quote! {
                                #name::#vname(#(#binding #bindings),*) => {
                                    #ok(dcbor::__derive::variant(#disc, [
                                        #(dcbor::CBOREncodable::into_encoded_cbor(#bindings)?),*
                                    ]))
                                }
                            }
                        }
                        VariantKind::Named(fields) => {
                            let names = fields.idents();
                            let aliases = bindings(names.len());
                            let map = Ident::new("inner_map", proc_macro2::Span::call_site());
                            let inserts = map_inserts(fields, &map, |field| {
                                let index = names.iter().position(|name| *name == field).unwrap();
                                let alias = &aliases[index];
                                quote! { #alias }
                            });
                            quote! {
                                #name::#vname { #(#names: #binding #aliases),* } => {
                                    let mut inner_map = dcbor::Map::new();
                                    #(#inserts)*
                                    #ok(dcbor::__derive::variant(#disc, [
                                        dcbor::__derive::map(inner_map),
                                    ]))
                                }
                            }
                        }
                    }
                });
                quote! {
                    match #value {
                        #(#arms)*
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Decodable expansion
// ---------------------------------------------------------------------------

/// The extraction of every field of `fields` from `map`, a `&mut dcbor::Map`
/// the decoder owns: each field's value removed and moved into its
/// conversion (`dcbor::__derive::field`, `optional`), never a clone of a
/// handle the map keeps. A required field absent is `MissingMapKey`; a
/// present field that does not convert is its conversion's error, an
/// optional one included; keys no field names are ignored.
fn map_extracts(fields: &MapFields, map: &Ident) -> Vec<TokenStream2> {
    fields
        .0
        .iter()
        .map(|field| {
            let fname = &field.ident;
            let key = field.key;
            if field.optional {
                quote! { #fname: dcbor::__derive::optional(#map, #key)? }
            } else {
                quote! { #fname: dcbor::__derive::field(#map, #key)? }
            }
        })
        .collect()
}

impl Schema<'_> {
    fn decodable(&self) -> TokenStream2 {
        let name = self.name();
        let mut generics = self.input.generics.clone();
        for ty in self.field_types() {
            generics
                .make_where_clause()
                .predicates
                .push(syn::parse_quote!(#ty: ::core::convert::TryFrom<dcbor::CBOR>));
        }
        // Every field's conversion error propagates as a dcbor::Error: a
        // required or positional field's through `?`, and an optional field
        // present in the map but not converting through `Map::get`, which
        // refuses rather than reading the field as absent.
        for ty in self.field_types() {
            generics
                .make_where_clause()
                .predicates
                .push(syn::parse_quote!(
                    dcbor::Error: ::core::convert::From<
                        <#ty as ::core::convert::TryFrom<dcbor::CBOR>>::Error,
                    >
                ));
        }
        if self.tag.is_some() {
            let (_, types, _) = self.input.generics.split_for_impl();
            generics
                .make_where_clause()
                .predicates
                .push(syn::parse_quote!(#name #types: dcbor::CBORTagged));
        }
        let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

        let ok = quote! { ::core::result::Result::Ok };
        let err = quote! { ::core::result::Result::Err };
        let core_decode = match &self.shape {
            Shape::Map(fields) => {
                let map = Ident::new("map", proc_macro2::Span::call_site());
                let extracts = map_extracts(fields, &map);
                // `ref mut`: a record of no fields never takes from the map,
                // and a `mut` binding left unmutated would warn in the
                // user's crate.
                quote! {
                    match cbor.into_case() {
                        dcbor::CBORCase::Map(ref mut map) => {
                            #ok(#name { #(#extracts),* })
                        }
                        _ => #err(dcbor::Error::WrongType),
                    }
                }
            }
            Shape::Newtype => quote! {
                #ok(#name(dcbor::__derive::convert(cbor)?))
            },
            Shape::Unit => quote! {
                if cbor.is_null() {
                    #ok(#name)
                } else {
                    #err(dcbor::Error::WrongType)
                }
            },
            Shape::Enum(variants) => decodable_enum(name, variants),
        };

        match self.tag {
            // For tagged types, TryFrom<CBOR> expects a tagged wrapper
            Some(_) => quote! {
                impl #impl_generics dcbor::CBORTaggedDecodable for #name #ty_generics #where_clause {
                    fn from_untagged_cbor(cbor: dcbor::CBOR) -> dcbor::Result<Self> {
                        #core_decode
                    }
                }

                impl #impl_generics ::core::convert::TryFrom<dcbor::CBOR> for #name #ty_generics #where_clause {
                    type Error = dcbor::Error;

                    fn try_from(cbor: dcbor::CBOR) -> dcbor::Result<Self> {
                        <Self as dcbor::CBORTaggedDecodable>::from_tagged_cbor(cbor)
                    }
                }
            },
            // For untagged types, TryFrom<CBOR> decodes directly
            None => quote! {
                impl #impl_generics ::core::convert::TryFrom<dcbor::CBOR> for #name #ty_generics #where_clause {
                    type Error = dcbor::Error;

                    fn try_from(cbor: dcbor::CBOR) -> dcbor::Result<Self> {
                        #core_decode
                    }
                }
            },
        }
    }
}

/// The decoding of an enum: a unit variant from its bare discriminant, a
/// variant with a payload from the array of its discriminant and payload,
/// whose length must be exactly the variant's. The array is moved apart
/// (`dcbor::__derive::variant_array`) and each payload value moved into its
/// conversion; a named payload's map is moved out and each field removed
/// from it into its conversion ([`map_extracts`]). No handle is cloned, so
/// a case held only by the decoded value moves rather than being copied.
/// Every path is fully qualified, as the encoding expansion's are.
fn decodable_enum(name: &Ident, variants: &[Variant]) -> TokenStream2 {
    let ok = quote! { ::core::result::Result::Ok };
    let err = quote! { ::core::result::Result::Err };
    let mut unit_arms = Vec::new();
    let mut array_arms = Vec::new();

    for variant in variants {
        let disc = variant.discriminant;
        let vname = &variant.ident;
        match &variant.kind {
            VariantKind::Unit => {
                unit_arms.push(quote! {
                    #disc => #ok(#name::#vname),
                });
            }
            VariantKind::Tuple(field_count) => {
                let field_extracts = (0..*field_count)
                    .map(|_| quote! { dcbor::__derive::convert(payload.take_value()?)? });
                array_arms.push(quote! {
                    #disc => {
                        if payload.len() != #field_count {
                            return #err(dcbor::Error::WrongType);
                        }
                        #ok(#name::#vname(#(#field_extracts),*))
                    }
                });
            }
            VariantKind::Named(fields) => {
                let map = Ident::new("inner_map", proc_macro2::Span::call_site());
                let extracts = map_extracts(fields, &map);
                array_arms.push(quote! {
                    #disc => {
                        if payload.len() != 1 {
                            return #err(dcbor::Error::WrongType);
                        }
                        match payload.take_value()?.into_case() {
                            dcbor::CBORCase::Map(ref mut inner_map) => {
                                #ok(#name::#vname { #(#extracts),* })
                            }
                            _ => #err(dcbor::Error::WrongType),
                        }
                    }
                });
            }
        }
    }

    let unit = (!unit_arms.is_empty()).then(|| {
        quote! {
            dcbor::CBORCase::Unsigned(disc) => match disc {
                #(#unit_arms)*
                _ => #err(dcbor::Error::WrongType),
            },
        }
    });
    let array = (!array_arms.is_empty()).then(|| {
        quote! {
            dcbor::CBORCase::Array(items) => {
                // `ref mut`: a variant of no payload reads only its length,
                // and a `mut` binding left unmutated would warn in the
                // user's crate.
                let (disc, ref mut payload) = dcbor::__derive::variant_array(items)?;
                match disc {
                    #(#array_arms)*
                    _ => #err(dcbor::Error::WrongType),
                }
            }
        }
    });
    quote! {
        match cbor.into_case() {
            #unit
            #array
            _ => #err(dcbor::Error::WrongType),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rejected(input: DeriveInput) -> String {
        match Schema::parse(&input) {
            Ok(_) => panic!("the schema was accepted"),
            Err(error) => error.to_string(),
        }
    }

    /// A key given twice in one map would let one field silently replace
    /// another in the symbolic map; it is refused at expansion.
    #[test]
    fn duplicate_field_keys_are_refused() {
        let message = rejected(syn::parse_quote! {
            struct Twice {
                #[cbor(n = 1)]
                first: u64,
                #[cbor(n = 1)]
                second: u64,
            }
        });
        assert_eq!(message, "field key 1 is already the key of `first`");
        let message = rejected(syn::parse_quote! {
            enum Inner {
                #[cbor(n = 0)]
                Variant {
                    #[cbor(n = 4)]
                    a: u64,
                    #[cbor(n = 4)]
                    b: u64,
                },
            }
        });
        assert_eq!(message, "field key 4 is already the key of `a`");
    }

    #[test]
    fn duplicate_discriminants_are_refused() {
        let message = rejected(syn::parse_quote! {
            enum Twice {
                #[cbor(n = 3)]
                First,
                #[cbor(n = 3)]
                Second(u64),
            }
        });
        assert_eq!(
            message,
            "discriminant 3 is already the discriminant of `First`"
        );
    }

    /// Fields are written in encoded-key order whatever their declaration
    /// order.
    #[test]
    fn map_fields_are_ordered_by_key() -> Result<()> {
        let input: DeriveInput = syn::parse_quote! {
            struct Scrambled {
                #[cbor(n = 256)]
                c: u64,
                #[cbor(n = 24)]
                b: u64,
                #[cbor(n = 0)]
                a: Option<u64>,
            }
        };
        let schema = Schema::parse(&input)?;
        let Shape::Map(fields) = &schema.shape else {
            panic!("a named struct is a map");
        };
        let keys: Vec<u64> = fields
            .in_key_order()
            .iter()
            .map(|field| field.key)
            .collect();
        assert_eq!(keys, [0, 24, 256]);
        assert!(fields.0[2].optional);
        Ok(())
    }
}
