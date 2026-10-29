use super::super::super::*;

pub(super) fn expand(schema: &Schema<'_>, fields: &syn::FieldsNamed) -> TokenStream2 {
    expand_fields(schema, fields, false, true)
}

/// The field engine's cost over fields of `types`, in key order, whose field
/// state is `field`, under allocator `a` (`in_place::fields::cost`).
pub(super) fn cost(
    types: &[&syn::Type],
    positional: bool,
    field: &TokenStream2,
    a: &Ident,
) -> TokenStream2 {
    quote! {
        dcbor::bounded::decode::construction::in_place::fields::cost::<#field, <#a as dcbor::bounded::Allocator>::Permit>(
            #positional,
            &[#(<#types as dcbor::bounded::decode::construction::in_place::InPlace<#a>>::COST),*],
        )
    }
}

/// The field state type of the schema whose type is `ty` under allocator
/// `a`: its `Fields` implementation's `Field`.
pub(super) fn field_state(ty: &TokenStream2, a: &Ident) -> TokenStream2 {
    quote!(<#ty as dcbor::bounded::decode::construction::in_place::fields::Fields<#a>>::Field)
}

/// The `Fields` implementation of a schema of named `fields`, and the
/// definition of its field state: one variant per field, in key order, each
/// holding that field's construction state, so a state names its field and
/// can be paired with no other. The definition is `pub` because it is the
/// implementation's associated type; emitted inside an anonymous constant
/// (by the caller for an enum's variant, here for a complete type), it can
/// be named only through that associated type, and constructed only by the
/// generated `start`. When `complete_type` is set, the type's own `InPlace`
/// and `Reclaim` over the field engine are emitted too.
pub(super) fn expand_fields(
    schema: &Schema<'_>,
    fields: &syn::FieldsNamed,
    positional: bool,
    complete_type: bool,
) -> TokenStream2 {
    let name = schema.name();
    let a = schema.fresh("__DcborFieldAllocator");
    // Named after the schema's type, so the states of an enum's variant
    // helpers, emitted into one anonymous constant, are distinct.
    let state_name = schema.fresh(&format!("__DcborFieldState{name}"));
    let observation_name = schema.fresh(&format!("__DcborFieldObservation{name}"));
    let depth = super::dispatch_depth(schema, &a);
    let mut generics = schema.input.generics.clone();
    generics
        .params
        .push(syn::parse_quote!(#a: dcbor::bounded::Allocator));
    for field in &fields.named {
        let ty = &field.ty;
        generics
            .make_where_clause()
            .predicates
            .push(syn::parse_quote!(
                #ty: dcbor::bounded::decode::construction::in_place::InPlace<#a>
            ));
    }
    let (ig, state_tg, wc) = generics.split_for_impl();
    let (_, tg, _) = schema.input.generics.split_for_impl();
    let mut ordered: Vec<_> = fields
        .named
        .iter()
        .map(|field| {
            let key = parse_n(&field.attrs)
                .expect("validated field attribute")
                .expect("required field key")
                .0;
            (key, field)
        })
        .collect();
    ordered.sort_by_key(|(key, _)| *key);
    let count = ordered.len();
    let tag = match schema.tag {
        Some(tag) => quote!(Some(#tag)),
        None => quote!(None),
    };
    let keys = ordered.iter().map(|(key, _)| key);
    let mut variants = Vec::new();
    let mut starts = Vec::new();
    let mut builds = Vec::new();
    let mut reclaims = Vec::new();
    let mut remainings = Vec::new();
    let mut missing = Vec::new();
    let mut observed = Vec::new();
    let build_method = if positional {
        quote!(build_step)
    } else {
        quote!(build_present)
    };
    let optional = ordered.iter().enumerate().map(|(slot, (_, field))| {
        let ty = &field.ty;
        quote!(#slot => <#ty as dcbor::bounded::decode::construction::in_place::InPlace<#a>>::OPTIONAL)
    });
    for (slot, (_, field)) in ordered.iter().enumerate() {
        let ident = field.ident.as_ref().expect("named field");
        let ty = &field.ty;
        let variant = Ident::new(&format!("Field{slot}"), proc_macro2::Span::mixed_site());
        variants.push(quote! {
            #variant(<#ty as dcbor::bounded::decode::construction::reclamation::Reclaim<#a>>::State)
        });
        observed.push(super::Observed {
            variant: variant.clone(),
            label: ident.to_string(),
            observation: quote! {
                <<#ty as dcbor::bounded::decode::construction::reclamation::Reclaim<#a>>::State
                    as dcbor::bounded::decode::construction::reclamation::Custody>::Observation
            },
        });
        starts.push(quote! {
            #slot => Some(#state_name::#variant(
                <#ty as dcbor::bounded::decode::construction::reclamation::Reclaim<#a>>::INITIAL
            ))
        });
        // The field's slot: its place from the root's, in the root place's
        // mode, by compiler-provided aligned field projection alone, with no
        // reference to the enclosing struct, initialized or not; and the
        // field's own state, which this variant carries. Construction, cleanup
        // and the cleanup count all project the field through this one
        // expression.
        let child = quote! {
            // SAFETY: the compiler's projection of this field from the
            // record's place, by raw pointer alone, paired with the field's own
            // state, which this variant carries.
            unsafe {
                dcbor::bounded::decode::construction::reclamation::Slot::new(
                    place.project(|value| core::ptr::addr_of_mut!((*value).#ident)),
                    state,
                )
            }
        };
        builds.push(quote! { #state_name::#variant(state) =>
            <#ty as dcbor::bounded::decode::construction::in_place::InPlace<#a>>::#build_method(
                document, index, #child, allocator
            )
        });
        reclaims.push(quote! { #state_name::#variant(state) =>
            <#ty as dcbor::bounded::decode::construction::reclamation::Reclaim<#a>>::reclaim_step(
                #child, allocator
            )
        });
        remainings.push(quote! { #state_name::#variant(state) =>
            <#ty as dcbor::bounded::decode::construction::reclamation::Reclaim<#a>>::remaining(#child)
        });
        missing.push(quote! { #state_name::#variant(state) =>
            <#ty as dcbor::bounded::decode::construction::in_place::InPlace<#a>>::build_absent(
                #child, allocator
            )
        });
    }
    // The uninhabited marker variant uses every generic parameter, including
    // any the fields leave unused, and can never be constructed.
    let marker = quote! {
        #state_name::__Marker(never, _) => match *never {}
    };
    // A record of no fields matches only the marker, which never reads the
    // place.
    let unused_place = if count == 0 {
        quote!(let _ = place;)
    } else {
        quote!()
    };
    let phantom = quote!(core::marker::PhantomData<fn() -> (#name #tg, #a)>);
    let custody = super::custody(
        &state_name,
        &observation_name,
        &generics,
        &phantom,
        &observed,
    );
    let callbacks = quote! {
        #[doc(hidden)]
        pub enum #state_name #ig #wc {
            #(#variants,)*
            __Marker(core::convert::Infallible, #phantom),
        }
        #custody
        // SAFETY: schema validation guarantees unique keys; the sorted dense
        // indices select each actual field exactly once, and each field's
        // state variant delegates to that field alone. Packed types are
        // excluded.
        unsafe impl #ig dcbor::bounded::decode::construction::in_place::fields::Fields<#a> for #name #tg #wc {
            const COUNT: usize = #count;
            const TAG: Option<u64> = #tag;
            const POSITIONAL: bool = #positional;
            type Field = #state_name #state_tg;
            fn key(field: usize) -> u64 {
                const KEYS: &[u64] = &[#(#keys),*];
                KEYS[field]
            }
            fn optional(field: usize) -> bool {
                match field { #(#optional,)* _ => false }
            }
            fn start(field: usize) -> Option<Self::Field> {
                match field { #(#starts,)* _ => None }
            }
            fn missing_field(
                slot: dcbor::bounded::decode::construction::reclamation::Slot<'_, Self, Self::Field>,
                allocator: &mut #a,
            ) -> dcbor::bounded::decode::ConstructResult<dcbor::bounded::decode::construction::in_place::Built, #a> {
                let (place, state) = slot.into_parts();
                #unused_place
                match state { #(#missing,)* #marker }
            }
            fn build_field(
                document: &dcbor::bounded::decode::Document<'_, #a::Permit>, index: usize,
                slot: dcbor::bounded::decode::construction::reclamation::Slot<'_, Self, Self::Field>,
                allocator: &mut #a,
            ) -> dcbor::bounded::decode::ConstructResult<dcbor::bounded::decode::construction::in_place::Built, #a> {
                let (place, state) = slot.into_parts();
                #unused_place
                match state { #(#builds,)* #marker }
            }
            fn reclaim_field(
                slot: dcbor::bounded::decode::construction::reclamation::Slot<'_, Self, Self::Field>,
                allocator: &mut #a,
            ) -> dcbor::bounded::BoundedResult<dcbor::bounded::decode::construction::reclamation::Reclaimed, #a> {
                let (place, state) = slot.into_parts();
                #unused_place
                match state { #(#reclaims,)* #marker }
            }
            fn remaining_field(
                slot: dcbor::bounded::decode::construction::reclamation::PeekSlot<'_, Self, Self::Field>,
            ) -> u64 {
                let (place, state) = slot.into_parts();
                #unused_place
                match state { #(#remainings,)* #marker }
            }
        }
    };
    if !complete_type {
        return callbacks;
    }
    let field = field_state(&quote!(#name #tg), &a);
    let cost = cost(
        &ordered
            .iter()
            .map(|(_, field)| &field.ty)
            .collect::<Vec<_>>(),
        positional,
        &field,
        &a,
    );
    quote! {
        const _: () = {
            #callbacks
            // SAFETY: the shared engine retains each field's state and only
            // reports Done after every required field has completed in its
            // final destination.
            unsafe impl #ig dcbor::bounded::decode::construction::in_place::InPlace<#a> for #name #tg #wc {
                const COST: dcbor::bounded::decode::construction::in_place::ConstructionCost = #cost;

                fn build_step(document: &dcbor::bounded::decode::Document<'_, #a::Permit>, index: usize,
                    slot: dcbor::bounded::decode::construction::reclamation::Slot<'_, Self, Self::State>,
                    allocator: &mut #a,
                ) -> dcbor::bounded::decode::ConstructResult<dcbor::bounded::decode::construction::in_place::Built, #a> {
                    dcbor::bounded::decode::construction::in_place::fields::build(document, index, slot, allocator)
                }
            }
            // SAFETY: no whole-value Drop; generated field callbacks retain the
            // same address and state used to initialize each field.
            unsafe impl #ig dcbor::bounded::decode::construction::reclamation::Reclaim<#a> for #name #tg #wc {
                const DISPATCH_DEPTH: usize = #depth;
                type State = dcbor::bounded::decode::construction::in_place::fields::State<
                    #field,
                    <#a as dcbor::bounded::Allocator>::Permit,
                >;
                const INITIAL: Self::State = dcbor::bounded::decode::construction::in_place::fields::State::INITIAL;
                fn reclaim_step(
                    slot: dcbor::bounded::decode::construction::reclamation::Slot<'_, Self, Self::State>,
                    allocator: &mut #a,
                ) -> dcbor::bounded::BoundedResult<dcbor::bounded::decode::construction::reclamation::Reclaimed, #a> {
                    dcbor::bounded::decode::construction::in_place::fields::reclaim(slot, allocator)
                }
                fn remaining(
                    slot: dcbor::bounded::decode::construction::reclamation::PeekSlot<'_, Self, Self::State>,
                ) -> u64 {
                    dcbor::bounded::decode::construction::in_place::fields::remaining::<Self, #a>(slot)
                }
            }
        };
    }
}
