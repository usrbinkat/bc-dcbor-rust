//! Retained typed constructors generated from the validated representation.
use super::*;

struct Group<'a> {
    path: TokenStream2,
    fields: &'a Fields,
    first: usize,
    disc: Option<u64>,
    newtype: bool,
}

pub(super) fn expand(schema: &Schema<'_>) -> TokenStream2 {
    let name = schema.name();
    let types = schema.field_types();
    let mut generics = schema.input.generics.clone();
    for ty in &types {
        generics
            .make_where_clause()
            .predicates
            .push(syn::parse_quote!(
                #ty: dcbor::bounded::decode::construction::ResumableDecodable
            ));
    }
    let (ig, tg, wc) = generics.split_for_impl();
    let p = schema.fresh("__DcborPermit");
    let a = schema.fresh("__DcborAllocator");
    let slots = types.iter().map(|ty| quote!(Option<#ty>));
    let states = types.iter().map(|ty| quote!(Option<<#ty as dcbor::bounded::decode::construction::ResumableDecodable>::State<#p>>));
    let empty_slots = types.iter().map(|_| quote!(None));
    let empty_states = types.iter().map(|_| quote!(None));
    let mut groups = Vec::new();
    match &schema.input.data {
        Data::Struct(data) => groups.push(Group {
            path: quote!(#name),
            fields: &data.fields,
            first: 0,
            disc: None,
            newtype: matches!(data.fields, Fields::Unnamed(_)),
        }),
        Data::Enum(data) => {
            let mut first = 0;
            for variant in &data.variants {
                let ident = &variant.ident;
                // Schema::parse has already validated each discriminant.
                let disc = parse_n(&variant.attrs)
                    .expect("validated variant attributes")
                    .expect("validated discriminant")
                    .0;
                groups.push(Group {
                    path: quote!(#name::#ident),
                    fields: &variant.fields,
                    first,
                    disc: Some(disc),
                    newtype: false,
                });
                first += variant.fields.len();
            }
        }
        Data::Union(_) => unreachable!("validated schema excludes unions"),
    }
    let tag = if let Some(tag) = schema.tag {
        quote! {
            match node.kind() {
                dcbor::bounded::decode::Kind::Tagged(#tag) => state.1 = index + 1,
                dcbor::bounded::decode::Kind::Tagged(found) => return Err(dcbor::bounded::decode::DecodeError::Invalid(
                    dcbor::Error::WrongTag(dcbor::Tag::with_value(#tag), dcbor::Tag::with_value(found)))),
                _ => return Err(dcbor::bounded::decode::wrong_type()),
            }
        }
    } else {
        quote!(state.1 = index;)
    };
    let select = if matches!(schema.input.data, Data::Enum(_)) {
        let unit_arms = groups
            .iter()
            .enumerate()
            .filter(|(_, g)| matches!(g.fields, Fields::Unit))
            .map(|(i, g)| {
                let disc = g.disc.unwrap();
                quote!(#disc => state.2 = #i,)
            });
        let array_arms = groups
            .iter()
            .enumerate()
            .filter(|(_, g)| !matches!(g.fields, Fields::Unit))
            .map(|(i, g)| {
                let disc = g.disc.unwrap();
                let length = if matches!(g.fields, Fields::Named(_)) {
                    2
                } else {
                    g.fields.len() as u64 + 1
                };
                quote!(#disc if count == #length => { state.2 = #i; state.1 += 2; },)
            });
        quote! {
            match node.kind() {
                dcbor::bounded::decode::Kind::Unsigned(disc) => match disc {
                    #(#unit_arms)* _ => return Err(dcbor::bounded::decode::wrong_type()),
                },
                dcbor::bounded::decode::Kind::Array(count) => {
                    let disc = __c::node_at(document, state.1 + 1).ok_or_else(dcbor::bounded::decode::wrong_type)?;
                    match disc.kind() {
                        dcbor::bounded::decode::Kind::Unsigned(disc) => match disc {
                            #(#array_arms)* _ => return Err(dcbor::bounded::decode::wrong_type()),
                        },
                        dcbor::bounded::decode::Kind::Negative(_) => return Err(dcbor::bounded::decode::DecodeError::Invalid(dcbor::Error::OutOfRange)),
                        _ => return Err(dcbor::bounded::decode::wrong_type()),
                    }
                }
                _ => return Err(dcbor::bounded::decode::wrong_type()),
            }
        }
    } else {
        quote!(state.2 = 0;)
    };
    let group_arms = groups.iter().enumerate().map(|(i, g)| {
        let body = group_body(g);
        quote!(#i => { #body })
    });
    let child_arms = types.iter().enumerate().map(|(i,ty)| {
        let slot = syn::Index::from(i);
        quote! {
            #i => {
                let child = state.9.#slot.get_or_insert_with(<#ty as __c::ResumableDecodable>::start::<#a::Permit>);
                match <#ty as __c::ResumableDecodable>::construct_step(document, state.6, child, permits, allocator)? {
                    __c::BuildStep::Progress => {},
                    __c::BuildStep::Complete(value) => {
                        state.8.#slot = Some(value);
                        state.9.#slot = None;
                        state.0 = 3;
                        state.7 += 1;
                    }
                }
            }
        }
    });
    quote! {
        impl #ig dcbor::bounded::decode::construction::ResumableDecodable for #name #tg #wc {
            type State<#p> = (u8, usize, usize, usize, usize, usize, usize, usize, (#(#slots,)*), (#(#states,)*));
            fn start<#p>() -> Self::State<#p> {
                (0, 0, 0, 0, 0, 0, 0, 0, (#(#empty_slots,)*), (#(#empty_states,)*))
            }
            #[allow(unused_variables, unused_mut, unreachable_code)]
            fn construct_step<#a: dcbor::bounded::Allocator>(
                document: &dcbor::bounded::decode::Document<'_, #a::Permit>, index: usize,
                state: &mut Self::State<#a::Permit>,
                permits: &mut dcbor::bounded::decode::storage::Storage<#a::Permit, #a::Permit>,
                allocator: &mut #a,
            ) -> dcbor::bounded::decode::ConstructResult<dcbor::bounded::decode::construction::BuildStep<Self>, #a> {
                use dcbor::bounded::decode::construction as __c;
                if state.0 == 0 {
                    dcbor::bounded::decode::visit(allocator)?;
                    let node = __c::node_at(document, index).ok_or_else(dcbor::bounded::decode::wrong_type)?;
                    #tag
                    state.0 = 1;
                    return Ok(__c::BuildStep::Progress);
                }
                if state.0 == 1 {
                    dcbor::bounded::decode::visit(allocator)?;
                    let node = __c::node_at(document, state.1).ok_or_else(dcbor::bounded::decode::wrong_type)?;
                    #select
                    state.0 = 2;
                    return Ok(__c::BuildStep::Progress);
                }
                if state.0 == 4 {
                    match state.5 { #(#child_arms)* _ => return Err(dcbor::bounded::decode::wrong_type()), }
                    return Ok(__c::BuildStep::Progress);
                }
                dcbor::bounded::decode::visit(allocator)?;
                match state.2 { #(#group_arms)* _ => Err(dcbor::bounded::decode::wrong_type()), }
            }
        }
    }
}

fn group_body(group: &Group<'_>) -> TokenStream2 {
    let path = &group.path;
    let fields: Vec<_> = group.fields.iter().collect();
    let values = fields.iter().enumerate().map(|(i,field)| {
        let slot = syn::Index::from(group.first + i);
        let value = if matches!(group.fields, Fields::Named(_)) && is_option(&field.ty) {
            quote!(state.8.#slot.take())
        } else {
            quote!(state.8.#slot.take().ok_or(dcbor::bounded::decode::DecodeError::Invalid(dcbor::Error::MissingMapKey))?)
        };
        if let Some(name) = &field.ident { quote!(#name: #value) } else { value }
    });
    let complete = match group.fields {
        Fields::Named(_) => quote!(#path { #(#values),* }),
        Fields::Unnamed(_) => quote!(#path (#(#values),*)),
        Fields::Unit => quote!(#path),
    };
    if matches!(group.fields, Fields::Unit) {
        let check = if group.disc.is_none() {
            quote! {
                if !matches!(__c::node_at(document, state.1).map(|n| n.kind()), Some(dcbor::bounded::decode::Kind::Null)) {
                    return Err(dcbor::bounded::decode::wrong_type());
                }
            }
        } else {
            quote!()
        };
        return quote! { #check Ok(__c::BuildStep::Complete(#complete)) };
    }
    let init = if matches!(group.fields, Fields::Named(_)) {
        quote! {
            let node = __c::node_at(document, state.1).ok_or_else(dcbor::bounded::decode::wrong_type)?;
            if !matches!(node.kind(), dcbor::bounded::decode::Kind::Map(_)) { return Err(dcbor::bounded::decode::wrong_type()); }
            state.3 = state.1 + 1;
            state.4 = __c::next_index(node);
        }
    } else {
        quote!(state.3 = state.1;)
    };
    let scan = if matches!(group.fields, Fields::Named(_)) {
        let arms = fields.iter().enumerate().map(|(i,field)| {
            let key = parse_n(&field.attrs).expect("validated map key").expect("required map key").0;
            let slot = group.first + i;
            quote!(dcbor::bounded::decode::Kind::Unsigned(#key) => { state.5 = #slot; state.0 = 4; },)
        });
        quote! {
            if state.3 == state.4 { return Ok(__c::BuildStep::Complete(#complete)); }
            let key = __c::node_at(document, state.3).ok_or_else(dcbor::bounded::decode::wrong_type)?;
            state.6 = __c::next_index(key);
            let value = __c::node_at(document, state.6).ok_or_else(dcbor::bounded::decode::wrong_type)?;
            state.3 = __c::next_index(value);
            match key.kind() { #(#arms)* _ => {} }
        }
    } else {
        let count = fields.len();
        let first = group.first;
        let _newtype = group.newtype;
        quote! {
            if state.7 == #count { return Ok(__c::BuildStep::Complete(#complete)); }
            state.6 = state.3;
            state.5 = #first + state.7;
            let node = __c::node_at(document, state.3).ok_or_else(dcbor::bounded::decode::wrong_type)?;
            state.3 = __c::next_index(node);
            state.0 = 4;
        }
    };
    quote! {
        if state.0 == 2 { #init state.0 = 3; return Ok(__c::BuildStep::Progress); }
        #scan
        Ok(__c::BuildStep::Progress)
    }
}
