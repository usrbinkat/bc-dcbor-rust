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
        let project = quote! {
            // SAFETY: compiler-provided aligned field projection, with no
            // reference to an uninitialized enclosing struct.
            let child = unsafe { core::ptr::NonNull::new_unchecked(
                core::ptr::addr_of_mut!((*place.as_ptr().cast::<Self>()).#ident)
                    .cast::<core::mem::MaybeUninit<#ty>>()
            ) };
        };
        builds.push(quote! { #state_name::#variant(state) => {
            #project
            unsafe { <#ty as dcbor::bounded::decode::construction::in_place::InPlace<#a>>::#build_method(
                document, index, child, state, allocator
            ) }
        } });
        reclaims.push(quote! { #state_name::#variant(state) => {
            #project
            unsafe { <#ty as dcbor::bounded::decode::construction::reclamation::Reclaim<#a>>::reclaim_step(
                child, state, allocator
            ) }
        } });
        remainings.push(quote! { #state_name::#variant(state) => {
            #project
            unsafe { <#ty as dcbor::bounded::decode::construction::reclamation::Reclaim<#a>>::remaining(
                child, state
            ) }
        } });
        missing.push(quote! { #state_name::#variant(state) => {
            #project
            unsafe { <#ty as dcbor::bounded::decode::construction::in_place::InPlace<#a>>::build_absent(
                child, state, allocator
            ) }
        } });
    }
    // The uninhabited marker variant uses every generic parameter, including
    // any the fields leave unused, and can never be constructed.
    let marker = quote! {
        #state_name::__Marker(never, _) => match *never {}
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
            unsafe fn missing_field(
                place: core::ptr::NonNull<core::mem::MaybeUninit<Self>>,
                state: &mut Self::Field,
                allocator: &mut #a,
            ) -> dcbor::bounded::decode::ConstructResult<dcbor::bounded::decode::construction::in_place::Built, #a> {
                match state { #(#missing,)* #marker }
            }
            unsafe fn build_field(
                document: &dcbor::bounded::decode::Document<'_, #a::Permit>, index: usize,
                place: core::ptr::NonNull<core::mem::MaybeUninit<Self>>,
                state: &mut Self::Field,
                allocator: &mut #a,
            ) -> dcbor::bounded::decode::ConstructResult<dcbor::bounded::decode::construction::in_place::Built, #a> {
                match state { #(#builds,)* #marker }
            }
            unsafe fn reclaim_field(
                place: core::ptr::NonNull<core::mem::MaybeUninit<Self>>,
                state: &mut Self::Field,
                allocator: &mut #a,
            ) -> dcbor::bounded::BoundedResult<dcbor::bounded::decode::construction::reclamation::Reclaimed, #a> {
                match state { #(#reclaims,)* #marker }
            }
            unsafe fn remaining_field(
                place: core::ptr::NonNull<core::mem::MaybeUninit<Self>>,
                state: &mut Self::Field,
            ) -> u64 {
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

                unsafe fn build_step(document: &dcbor::bounded::decode::Document<'_, #a::Permit>, index: usize,
                    place: core::ptr::NonNull<core::mem::MaybeUninit<Self>>,
                    state: &mut Self::State,
                    allocator: &mut #a,
                ) -> dcbor::bounded::decode::ConstructResult<dcbor::bounded::decode::construction::in_place::Built, #a> {
                    unsafe { dcbor::bounded::decode::construction::in_place::fields::build(document, index, place, state, allocator) }
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
                unsafe fn reclaim_step(place: core::ptr::NonNull<core::mem::MaybeUninit<Self>>,
                    state: &mut Self::State,
                    allocator: &mut #a,
                ) -> dcbor::bounded::BoundedResult<dcbor::bounded::decode::construction::reclamation::Reclaimed, #a> {
                    unsafe { dcbor::bounded::decode::construction::in_place::fields::reclaim(place, state, allocator) }
                }
                unsafe fn remaining(place: core::ptr::NonNull<core::mem::MaybeUninit<Self>>,
                    state: &mut Self::State,
                ) -> u64 {
                    unsafe { dcbor::bounded::decode::construction::in_place::fields::remaining::<Self, #a>(place, state) }
                }
            }
        };
    }
}
