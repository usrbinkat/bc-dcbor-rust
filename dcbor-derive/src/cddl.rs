//! The CDDL rule of a derived type (`dcbor::cddl::Cddl`), generated from the
//! validated schema the symbolic and bounded decoders are generated from: its
//! map keys and their optionality, the keys no field names (accepted and
//! ignored), its variants' discriminants and payloads, and its tag. Every
//! form is written by `dcbor::cddl`'s helpers, the one definition of the
//! CDDL text; this module passes them the schema alone.
use super::*;

/// The member of a map field: its key, whether it may be absent, and its
/// value's expression. A required field's value is its type's
/// (`dcbor::cddl::Cddl`); an optional field's is the type its `Option`
/// holds when present (`dcbor::cddl::Present`), the field absent when
/// `None`.
fn member(key: u64, optional: bool, ty: &Type) -> TokenStream2 {
    let value = if optional {
        quote!(<#ty as dcbor::cddl::Present>::cddl(rules))
    } else {
        quote!(<#ty as dcbor::cddl::Cddl>::cddl(rules))
    };
    quote! {
        dcbor::cddl::Member { key: #key, optional: #optional, value: #value }
    }
}

/// The bound a field of `ty` needs for its member: `Cddl`, or `Present`
/// when it is optional.
fn bound(optional: bool, ty: &Type) -> syn::WherePredicate {
    if optional {
        syn::parse_quote!(#ty: dcbor::cddl::Present)
    } else {
        syn::parse_quote!(#ty: dcbor::cddl::Cddl)
    }
}

/// The map of named `fields`, whose schema is `schema`'s map fields in
/// declaration order (`MapFields::parse` keeps it), in the order of their
/// keys, each field's bound added to `predicates`.
fn map(
    schema: &MapFields,
    fields: &syn::FieldsNamed,
    predicates: &mut Vec<syn::WherePredicate>,
) -> TokenStream2 {
    let mut members: Vec<(u64, TokenStream2)> = schema
        .0
        .iter()
        .zip(&fields.named)
        .map(|(field, declared)| {
            predicates.push(bound(field.optional, &declared.ty));
            (field.key, member(field.key, field.optional, &declared.ty))
        })
        .collect();
    members.sort_by_key(|(key, _)| *key);
    let members = members.into_iter().map(|(_, member)| member);
    quote!(dcbor::cddl::map(&[#(#members),*]))
}

pub(super) fn expand(schema: &Schema<'_>) -> TokenStream2 {
    let name = schema.name();
    let base = name.to_string();
    let mut predicates = Vec::new();
    let untagged = match (&schema.shape, &schema.input.data) {
        (Shape::Map(fields), Data::Struct(data)) => match &data.fields {
            Fields::Named(named) => map(fields, named, &mut predicates),
            _ => unreachable!("a map schema is a named struct"),
        },
        (Shape::Newtype, Data::Struct(data)) => {
            let ty = &data
                .fields
                .iter()
                .next()
                .expect("a newtype has one field")
                .ty;
            predicates.push(bound(false, ty));
            quote!(<#ty as dcbor::cddl::Cddl>::cddl(rules))
        }
        (Shape::Unit, _) => quote!(dcbor::cddl::unit()),
        (Shape::Enum(variants), Data::Enum(_)) if variants.is_empty() => {
            return Error::new_spanned(name, "an enum of no variants has no CDDL type")
                .to_compile_error();
        }
        (Shape::Enum(variants), Data::Enum(data)) => {
            // The schema's variants are the input's, in declaration order
            // (`Schema::parse` pushes each as it reads it).
            let alternatives: Vec<TokenStream2> = variants
                .iter()
                .zip(&data.variants)
                .map(|(variant, declared)| {
                    let discriminant = variant.discriminant;
                    match (&variant.kind, &declared.fields) {
                        (VariantKind::Unit, _) => {
                            quote!(dcbor::cddl::unit_variant(#discriminant))
                        }
                        (VariantKind::Tuple(_), Fields::Unnamed(fields)) => {
                            let items = fields.unnamed.iter().map(|field| {
                                predicates.push(bound(false, &field.ty));
                                let ty = &field.ty;
                                quote!(<#ty as dcbor::cddl::Cddl>::cddl(rules))
                            });
                            let items: Vec<TokenStream2> = items.collect();
                            quote!(dcbor::cddl::variant(#discriminant, &[#(#items),*]))
                        }
                        (VariantKind::Named(fields), Fields::Named(named)) => {
                            let inner = map(fields, named, &mut predicates);
                            quote!(dcbor::cddl::variant(#discriminant, &[#inner]))
                        }
                        _ => unreachable!("a variant's schema is its fields' kind"),
                    }
                })
                .collect();
            quote!(dcbor::cddl::choice(&[#(#alternatives),*]))
        }
        _ => unreachable!("a validated schema's shape is its input's"),
    };
    let expression = match schema.tag {
        Some(tag) => quote!(dcbor::cddl::tagged(#tag, &(#untagged))),
        None => untagged,
    };
    let mut generics = schema.input.generics.clone();
    generics.make_where_clause().predicates.extend(predicates);
    // A rule is keyed by its type's `TypeId` (`dcbor::cddl::Rules::rule`),
    // which only a `'static` type has: every parameter is bound `'static`, so
    // a type with a lifetime parameter has a rule only at `'static`.
    let statics: Vec<syn::WherePredicate> = schema
        .input
        .generics
        .params
        .iter()
        .filter_map(|param| match param {
            syn::GenericParam::Type(param) => {
                let ident = &param.ident;
                Some(syn::parse_quote!(#ident: 'static))
            }
            syn::GenericParam::Lifetime(param) => {
                let lifetime = &param.lifetime;
                Some(syn::parse_quote!(#lifetime: 'static))
            }
            syn::GenericParam::Const(_) => None,
        })
        .collect();
    generics.make_where_clause().predicates.extend(statics);
    let (ig, tg, wc) = generics.split_for_impl();
    quote! {
        impl #ig dcbor::cddl::Cddl for #name #tg #wc {
            fn cddl(rules: &mut dcbor::cddl::Rules) -> dcbor::String {
                rules.rule::<Self>(#base, |rules| #expression)
            }
        }
    }
}
