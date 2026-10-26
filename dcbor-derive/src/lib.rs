//! Derive macros for dcbor `CBOREncodable`, `CBORDecodable`, and the
//! bounded encoding and decoding.
//!
//! Every derive parses its input once into a validated `Schema`: field
//! keys, variant discriminants, optional fields, newtype and unit shapes,
//! and the type's tag. Duplicate field keys within one map and duplicate
//! discriminants within one enum are compile errors. Each derive generates
//! from that schema, so the symbolic conversions (`From<T> for CBOR`,
//! `TryFrom<CBOR> for T`) and the bounded encoding
//! (`dcbor::bounded::encoding::Schema`) take every representation decision
//! from one definition.
//!
//! # Struct encoding
//!
//! Structs are encoded as CBOR maps with integer keys for compactness.
//! Each field must have a `#[cbor(n = N)]` attribute specifying its key.
//! Fields of type `Option<T>` are omitted from the map when `None`.
//!
//! ```
//! use dcbor::prelude::*;
//! use dcbor_derive::{CBOREncodable, CBORDecodable};
//!
//! #[derive(Clone, CBOREncodable, CBORDecodable)]
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
//! let bytes = person.to_cbor_data();
//! assert_eq!(bytes, [0xa2, 0x00, 0x63, b'A', b'd', b'a', 0x01, 0x18, 37]);
//! let decoded = Person::try_from(CBOR::try_from_data(bytes).unwrap()).unwrap();
//! assert_eq!(decoded.name, "Ada");
//! assert_eq!(decoded.age, 37);
//! assert_eq!(decoded.email, None);
//! ```
//!
//! # Newtype structs
//!
//! Single-field tuple structs delegate to the inner type:
//!
//! ```
//! use dcbor::prelude::*;
//! use dcbor_derive::{CBOREncodable, CBORDecodable};
//! #[derive(Clone, CBOREncodable, CBORDecodable)]
//! struct Wrapper(String);
//!
//! let bytes = Wrapper("hello".into()).to_cbor_data();
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
//! #[derive(Clone, CBOREncodable, CBORDecodable)]
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
//! assert_eq!(Shape::Point.to_cbor_data(), [0x02]);
//! let bytes = Shape::Rectangle { width: 2.0, height: 3.0 }.to_cbor_data();
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
//! `From<T> for CBOR` conversion, and the bounded encoding with it, emit
//! the untagged value; the tagged form is `CBORTaggedEncodable::tagged_cbor`.
//!
//! ```
//! use dcbor::prelude::*;
//! use dcbor_derive::{CBOREncodable, CBORDecodable};
//! #[derive(Clone, CBOREncodable, CBORDecodable)]
//! #[cbor(tag = 42)]
//! struct Tagged {
//!     #[cbor(n = 0)]
//!     data: Vec<u8>,
//! }
//!
//! let value = Tagged { data: vec![1, 2] };
//! assert_eq!(value.to_cbor_data(), [0xa1, 0x00, 0x82, 0x01, 0x02]);
//! let bytes = value.tagged_cbor().to_cbor_data();
//! assert_eq!(bytes, [0xd8, 42, 0xa1, 0x00, 0x82, 0x01, 0x02]);
//! let decoded = Tagged::try_from(CBOR::try_from_data(bytes).unwrap()).unwrap();
//! assert_eq!(decoded.data, [1, 2]);
//! assert!(Tagged::try_from(value.untagged_cbor()).is_err());
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
mod construction;
mod encoding;

/// Derive `From<T> for dcbor::CBOR`, making the type CBOREncodable.
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

/// Derive both `From<T> for CBOR` and `TryFrom<CBOR> for T`.
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

/// Derive `dcbor::bounded::decode::BoundedDecodable` from the same schema as
/// `TryFrom<CBOR>`: the same field keys, optional-field omission, unknown
/// keys ignored, discriminants and tag, read from a strictly decoded
/// document without a symbolic tree.
#[proc_macro_derive(CBORBoundedDecodable, attributes(cbor))]
pub fn derive_cbor_bounded_decodable(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match Schema::parse(&input).map(|schema| {
        let synchronous = schema.constructible();
        let retained = construction::expand(&schema);
        quote! { #synchronous #retained }
    }) {
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

enum Shape<'a> {
    Map(MapFields),
    Newtype(&'a Type),
    Unit,
    Enum(Vec<Variant>),
}

/// A derive input parsed and validated once; every derive generates from
/// it.
struct Schema<'a> {
    input: &'a DeriveInput,
    tag: Option<u64>,
    shape: Shape<'a>,
}

impl<'a> Schema<'a> {
    fn parse(input: &'a DeriveInput) -> Result<Self> {
        let tag = parse_tag(input)?;
        let shape = match &input.data {
            Data::Struct(data) => match &data.fields {
                Fields::Named(fields) => Shape::Map(MapFields::parse(fields)?),
                Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                    reject_tuple_attributes(fields)?;
                    Shape::Newtype(&fields.unnamed[0].ty)
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

/// `map.insert` of every field of `fields`, each read through `access`.
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
                    if let Some(ref v) = #value {
                        #map.insert(#key, v.clone());
                    }
                }
            } else {
                quote! {
                    #map.insert(#key, #value.clone());
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
                .push(syn::parse_quote!(#ty: Clone + Into<dcbor::CBOR>));
        }
        let (tag_generics, tag_types, tag_where) = self.input.generics.split_for_impl();
        if self.tag.is_some() {
            generics
                .make_where_clause()
                .predicates
                .push(syn::parse_quote!(#name #tag_types: Clone));
        }
        let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

        let core_from = match &self.shape {
            Shape::Map(fields) => {
                let map = Ident::new("map", proc_macro2::Span::call_site());
                let inserts = map_inserts(fields, &map, |field| quote! { value.#field });
                quote! {
                    let mut map = dcbor::Map::new();
                    #(#inserts)*
                    map.into()
                }
            }
            Shape::Newtype(_) => quote! { value.0.into() },
            Shape::Unit => quote! { dcbor::CBOR::null() },
            Shape::Enum(variants) => {
                let arms = variants.iter().map(|variant| {
                    let disc = variant.discriminant;
                    let vname = &variant.ident;
                    match &variant.kind {
                        VariantKind::Unit => quote! {
                            #name::#vname => dcbor::CBOR::from(#disc),
                        },
                        VariantKind::Tuple(count) => {
                            let bindings = bindings(*count);
                            quote! {
                                #name::#vname(#(#bindings),*) => {
                                    let arr: Vec<dcbor::CBOR> = vec![
                                        dcbor::CBOR::from(#disc),
                                        #(#bindings.clone().into()),*
                                    ];
                                    arr.into()
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
                                #name::#vname { #(#names: #aliases),* } => {
                                    let mut inner_map = dcbor::Map::new();
                                    #(#inserts)*
                                    let arr: Vec<dcbor::CBOR> = vec![
                                        dcbor::CBOR::from(#disc),
                                        inner_map.into(),
                                    ];
                                    arr.into()
                                }
                            }
                        }
                    }
                });
                quote! {
                    match value {
                        #(#arms)*
                    }
                }
            }
        };

        let tagged_impls = match self.tag {
            Some(tag_value) => quote! {
                impl #tag_generics dcbor::CBORTagged for #name #tag_types #tag_where {
                    fn cbor_tags() -> Vec<dcbor::Tag> {
                        vec![dcbor::Tag::with_value(#tag_value)]
                    }
                }

                impl #impl_generics dcbor::CBORTaggedEncodable for #name #ty_generics #where_clause {
                    fn untagged_cbor(&self) -> dcbor::CBOR {
                        self.clone().into()
                    }
                }
            },
            None => quote! {},
        };

        quote! {
            impl #impl_generics From<#name #ty_generics> for dcbor::CBOR #where_clause {
                fn from(value: #name #ty_generics) -> Self {
                    #core_from
                }
            }
            #tagged_impls
        }
    }
}

// ---------------------------------------------------------------------------
// Decodable expansion
// ---------------------------------------------------------------------------

/// The extraction of every field of `fields` from `map`.
fn map_extracts(fields: &MapFields, map: &Ident) -> Vec<TokenStream2> {
    fields
        .0
        .iter()
        .map(|field| {
            let fname = &field.ident;
            let key = field.key;
            if field.optional {
                quote! { #fname: #map.get(#key) }
            } else {
                quote! { #fname: #map.extract(#key)? }
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
                .push(syn::parse_quote!(#ty: TryFrom<dcbor::CBOR>));
        }
        // Map extraction accepts any conversion error. Positional fields use
        // `?` directly, so their errors must also convert into dcbor::Error.
        let groups: Vec<&Fields> = match &self.input.data {
            Data::Struct(data) => vec![&data.fields],
            Data::Enum(data) => data.variants.iter().map(|v| &v.fields).collect(),
            Data::Union(_) => unreachable!(),
        };
        for fields in groups {
            if let Fields::Unnamed(fields) = fields {
                for field in &fields.unnamed {
                    let ty = &field.ty;
                    generics
                        .make_where_clause()
                        .predicates
                        .push(syn::parse_quote!(
                            dcbor::Error: From<<#ty as TryFrom<dcbor::CBOR>>::Error>
                        ));
                }
            }
        }
        if self.tag.is_some() {
            let (_, types, _) = self.input.generics.split_for_impl();
            generics
                .make_where_clause()
                .predicates
                .push(syn::parse_quote!(#name #types: dcbor::CBORTagged));
        }
        let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

        let core_decode = match &self.shape {
            Shape::Map(fields) => {
                let map = Ident::new("map", proc_macro2::Span::call_site());
                let extracts = map_extracts(fields, &map);
                quote! {
                    match cbor.into_case() {
                        dcbor::CBORCase::Map(map) => {
                            Ok(#name { #(#extracts),* })
                        }
                        _ => Err(dcbor::Error::WrongType),
                    }
                }
            }
            Shape::Newtype(_) => quote! {
                Ok(#name(cbor.try_into()?))
            },
            Shape::Unit => quote! {
                if cbor.is_null() {
                    Ok(#name)
                } else {
                    Err(dcbor::Error::WrongType)
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

                impl #impl_generics TryFrom<dcbor::CBOR> for #name #ty_generics #where_clause {
                    type Error = dcbor::Error;

                    fn try_from(cbor: dcbor::CBOR) -> dcbor::Result<Self> {
                        <Self as dcbor::CBORTaggedDecodable>::from_tagged_cbor(cbor)
                    }
                }
            },
            // For untagged types, TryFrom<CBOR> decodes directly
            None => quote! {
                impl #impl_generics TryFrom<dcbor::CBOR> for #name #ty_generics #where_clause {
                    type Error = dcbor::Error;

                    fn try_from(cbor: dcbor::CBOR) -> dcbor::Result<Self> {
                        #core_decode
                    }
                }
            },
        }
    }
}

fn decodable_enum(name: &Ident, variants: &[Variant]) -> TokenStream2 {
    let mut unit_arms = Vec::new();
    let mut array_arms = Vec::new();

    for variant in variants {
        let disc = variant.discriminant;
        let vname = &variant.ident;
        match &variant.kind {
            VariantKind::Unit => {
                unit_arms.push(quote! {
                    #disc => Ok(#name::#vname),
                });
            }
            VariantKind::Tuple(field_count) => {
                let field_extracts: Vec<TokenStream2> = (0..*field_count)
                    .map(|i| {
                        let idx = i + 1; // skip discriminant at index 0
                        quote! {
                            arr[#idx].clone().try_into()?
                        }
                    })
                    .collect();
                let expected_len = field_count + 1;
                array_arms.push(quote! {
                    #disc => {
                        if arr.len() != #expected_len {
                            return Err(dcbor::Error::WrongType);
                        }
                        Ok(#name::#vname(#(#field_extracts),*))
                    }
                });
            }
            VariantKind::Named(fields) => {
                let map = Ident::new("inner_map", proc_macro2::Span::call_site());
                let extracts = map_extracts(fields, &map);
                array_arms.push(quote! {
                    #disc => {
                        if arr.len() != 2 {
                            return Err(dcbor::Error::WrongType);
                        }
                        match arr[1].clone().into_case() {
                            dcbor::CBORCase::Map(inner_map) => {
                                Ok(#name::#vname { #(#extracts),* })
                            }
                            _ => Err(dcbor::Error::WrongType),
                        }
                    }
                });
            }
        }
    }

    // If all variants are unit, decode from bare integer
    // If mixed, decode from integer (unit) or array (non-unit)
    let has_non_unit = !array_arms.is_empty();
    let has_unit = !unit_arms.is_empty();

    if has_non_unit && has_unit {
        quote! {
            match cbor.clone().into_case() {
                dcbor::CBORCase::Unsigned(disc) => {
                    match disc {
                        #(#unit_arms)*
                        _ => Err(dcbor::Error::WrongType),
                    }
                }
                dcbor::CBORCase::Array(arr) => {
                    if arr.is_empty() {
                        return Err(dcbor::Error::WrongType);
                    }
                    let disc: u64 = arr[0].clone().try_into()?;
                    match disc {
                        #(#array_arms)*
                        _ => Err(dcbor::Error::WrongType),
                    }
                }
                _ => Err(dcbor::Error::WrongType),
            }
        }
    } else if has_non_unit {
        quote! {
            match cbor.into_case() {
                dcbor::CBORCase::Array(arr) => {
                    if arr.is_empty() {
                        return Err(dcbor::Error::WrongType);
                    }
                    let disc: u64 = arr[0].clone().try_into()?;
                    match disc {
                        #(#array_arms)*
                        _ => Err(dcbor::Error::WrongType),
                    }
                }
                _ => Err(dcbor::Error::WrongType),
            }
        }
    } else {
        quote! {
            match cbor.into_case() {
                dcbor::CBORCase::Unsigned(disc) => {
                    match disc {
                        #(#unit_arms)*
                        _ => Err(dcbor::Error::WrongType),
                    }
                }
                _ => Err(dcbor::Error::WrongType),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Bounded construction expansion
// ---------------------------------------------------------------------------

/// Report `values` values a synchronous construction examines to
/// `allocator` before the work, through typed construction's admission
/// route.
fn examine(values: u64) -> TokenStream2 {
    quote! {
        dcbor::bounded::decode::visits(#values, allocator)?;
    }
}

/// The construction of the map `node` (an expression of a decoded node) as
/// `path { fields }`: one pass over its entries in canonical key order, each
/// key a schema field's assigning its slot, every other key ignored as the
/// symbolic extraction ignores it; a required field without its key is
/// `MissingMapKey`, an optional one is `None`.
fn construct_map(fields: &MapFields, path: TokenStream2, node: TokenStream2) -> TokenStream2 {
    let visit = examine(1);
    let slots: Vec<Ident> = (0..fields.0.len())
        .map(|index| {
            Ident::new(
                &format!("__dcbor_field_{index}"),
                proc_macro2::Span::mixed_site(),
            )
        })
        .collect();
    let arms = fields.0.iter().zip(&slots).map(|(field, slot)| {
        let key = field.key;
        quote! {
            dcbor::bounded::decode::Kind::Unsigned(#key) => {
                #slot = Some(dcbor::bounded::decode::BoundedDecodable::construct(
                    __dcbor_value,
                    permits,
                    allocator,
                )?);
            }
        }
    });
    let values = fields.0.iter().zip(&slots).map(|(field, slot)| {
        let ident = &field.ident;
        if field.optional {
            quote! { #ident: #slot }
        } else {
            quote! {
                #ident: #slot.ok_or(dcbor::bounded::decode::DecodeError::Invalid(
                    dcbor::Error::MissingMapKey,
                ))?
            }
        }
    });
    quote! {{
        #visit
        let dcbor::bounded::decode::Kind::Map(_) = (#node).kind() else {
            return Err(dcbor::bounded::decode::wrong_type());
        };
        #(let mut #slots = None;)*
        let mut __dcbor_entries = (#node).children();
        while let Some(__dcbor_key) = __dcbor_entries.next() {
            let __dcbor_value = __dcbor_entries
                .next()
                .ok_or_else(dcbor::bounded::decode::wrong_type)?;
            #visit
            match __dcbor_key.kind() {
                #(#arms)*
                _ => {}
            }
        }
        Ok(#path { #(#values),* })
    }}
}

/// The construction of an enum from `node`: a unit variant from its bare
/// discriminant, a tuple variant from `[discriminant, fields...]`, a struct
/// variant from `[discriminant, {map}]`, accepting exactly the forms
/// `TryFrom<CBOR>` accepts.
fn construct_enum(name: &Ident, variants: &[Variant]) -> TokenStream2 {
    let visit = examine(1);
    let mut unit_arms = Vec::new();
    let mut array_arms = Vec::new();
    for variant in variants {
        let disc = variant.discriminant;
        let vname = &variant.ident;
        match &variant.kind {
            VariantKind::Unit => unit_arms.push(quote! { #disc => Ok(#name::#vname), }),
            VariantKind::Tuple(count) => {
                let expected = (*count as u64) + 1;
                let fields = (0..*count).map(|_| {
                    quote! {
                        dcbor::bounded::decode::BoundedDecodable::construct(
                            __dcbor_items
                                .next()
                                .ok_or_else(dcbor::bounded::decode::wrong_type)?,
                            permits,
                            allocator,
                        )?
                    }
                });
                array_arms.push(quote! {
                    #disc => {
                        if __dcbor_length != #expected {
                            return Err(dcbor::bounded::decode::wrong_type());
                        }
                        Ok(#name::#vname(#(#fields),*))
                    }
                });
            }
            VariantKind::Named(fields) => {
                let map = construct_map(fields, quote! { #name::#vname }, quote! { __dcbor_map });
                array_arms.push(quote! {
                    #disc => {
                        if __dcbor_length != 2 {
                            return Err(dcbor::bounded::decode::wrong_type());
                        }
                        let __dcbor_map = __dcbor_items
                            .next()
                            .ok_or_else(dcbor::bounded::decode::wrong_type)?;
                        #map
                    }
                });
            }
        }
    }
    let unit = (!unit_arms.is_empty()).then(|| {
        quote! {
            dcbor::bounded::decode::Kind::Unsigned(__dcbor_disc) => match __dcbor_disc {
                #(#unit_arms)*
                _ => Err(dcbor::bounded::decode::wrong_type()),
            },
        }
    });
    let array = (!array_arms.is_empty()).then(|| {
        quote! {
            dcbor::bounded::decode::Kind::Array(__dcbor_length) => {
                let mut __dcbor_items = node.children();
                let __dcbor_disc = match __dcbor_items.next().map(|item| item.kind()) {
                    Some(dcbor::bounded::decode::Kind::Unsigned(disc)) => disc,
                    Some(dcbor::bounded::decode::Kind::Negative(_)) => {
                        return Err(dcbor::bounded::decode::DecodeError::Invalid(
                            dcbor::Error::OutOfRange,
                        ));
                    }
                    _ => return Err(dcbor::bounded::decode::wrong_type()),
                };
                match __dcbor_disc {
                    #(#array_arms)*
                    _ => Err(dcbor::bounded::decode::wrong_type()),
                }
            }
        }
    });
    quote! {
        #visit
        match node.kind() {
            #unit
            #array
            _ => Err(dcbor::bounded::decode::wrong_type()),
        }
    }
}

impl Schema<'_> {
    fn constructible(&self) -> TokenStream2 {
        let name = self.name();
        let mut generics = self.input.generics.clone();
        for ty in self.field_types() {
            generics
                .make_where_clause()
                .predicates
                .push(syn::parse_quote!(#ty: dcbor::bounded::decode::BoundedDecodable));
        }
        let allocator_type = self.fresh("__DcborAllocator");
        let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
        let visit = examine(1);
        let untagged = match &self.shape {
            Shape::Map(fields) => construct_map(fields, quote! { #name }, quote! { node }),
            Shape::Newtype(inner) => quote! {
                Ok(#name(<#inner as dcbor::bounded::decode::BoundedDecodable>::construct(
                    node,
                    permits,
                    allocator,
                )?))
            },
            Shape::Unit => quote! {
                #visit
                match node.kind() {
                    dcbor::bounded::decode::Kind::Null => Ok(#name),
                    _ => Err(dcbor::bounded::decode::wrong_type()),
                }
            },
            Shape::Enum(variants) => construct_enum(name, variants),
        };
        // A tagged type is read inside its tag, as `TryFrom<CBOR>` reads it.
        let body = match self.tag {
            Some(tag) => quote! {
                #visit
                let node = match node.kind() {
                    dcbor::bounded::decode::Kind::Tagged(#tag) => node
                        .children()
                        .next()
                        .ok_or_else(dcbor::bounded::decode::wrong_type)?,
                    dcbor::bounded::decode::Kind::Tagged(found) => {
                        return Err(dcbor::bounded::decode::DecodeError::Invalid(
                            dcbor::Error::WrongTag(
                                dcbor::Tag::with_value(#tag),
                                dcbor::Tag::with_value(found),
                            ),
                        ));
                    }
                    _ => return Err(dcbor::bounded::decode::wrong_type()),
                };
                #untagged
            },
            None => untagged,
        };
        quote! {
            impl #impl_generics dcbor::bounded::decode::BoundedDecodable for #name #ty_generics #where_clause {
                #[allow(unused_variables, unused_mut, unreachable_code)]
                fn construct<#allocator_type: dcbor::bounded::Allocator>(
                    node: dcbor::bounded::decode::Node<'_, '_>,
                    permits: &mut dcbor::bounded::Owned<
                        #allocator_type::Permit,
                        #allocator_type::Permit,
                    >,
                    allocator: &mut #allocator_type,
                ) -> dcbor::bounded::decode::ConstructResult<Self, #allocator_type> {
                    #body
                }
            }
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
