use super::super::super::*;

pub(super) fn expand(schema: &Schema<'_>, fields: &syn::FieldsNamed) -> TokenStream2 {
    expand_fields(schema, fields, false, true)
}

/// The field engine's cost over fields of `types`, in key order, whose field
/// state is `field`, under allocator `a` (`in_place::fields::cost`), its
/// composition checked and unwrapped in a constant (`dcbor::const_cost!`):
/// a record whose cost does not fit in `u64` fails to compile where it is
/// first used with a concrete allocator.
pub(super) fn cost(
    types: &[&syn::Type],
    positional: bool,
    field: &TokenStream2,
    a: &Ident,
) -> TokenStream2 {
    quote! {
        dcbor::const_cost!(dcbor::bounded::decode::construction::in_place::fields::cost::<#field, <#a as dcbor::bounded::Releasing>::Permit>(
            #positional,
            &[#(<#types as dcbor::bounded::decode::construction::in_place::InPlace<#a>>::COST),*],
        ))
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
    let mut observes = Vec::new();
    let mut missing = Vec::new();
    let mut which = Vec::new();
    let mut observed = Vec::new();
    // A field present in the document is built as a part of the record:
    // positionally (an enum's array payload) through `build_part`, as a map
    // field through `build_part_present`; an omitted field through
    // `build_part_absent` (`missing_field`). The field engine calls
    // `build_field` exactly when the field's key is in the map and
    // `missing_field` exactly when it is not (`in_place::fields::build`).
    let build_method = if positional {
        quote!(build_part)
    } else {
        quote!(build_part_present)
    };
    let refusal = quote!(dcbor::bounded::BoundedError::<<#a as dcbor::bounded::Budget>::Refusal>);
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
        // The field's context: projected from the record's (whose index is
        // the field's node, or the map's for an omitted field), its slot the
        // field's, from the record's place and this variant's state; refused
        // when the record's state is another field's.
        let part = quote! {
            // SAFETY: the compiler's projection of this field from the
            // record's place, by raw pointer alone, paired with the field's
            // own state, which this variant of the record's state carries.
            unsafe {
                __dcbor_ctx.part(__dcbor_index, |slot| {
                    let (place, state) = slot.into_parts();
                    match state {
                        #state_name::#variant(state) => ::core::result::Result::Ok(
                            dcbor::bounded::decode::construction::reclamation::Slot::new(
                                place.project(|value| ::core::ptr::addr_of_mut!((*value).#ident)),
                                state,
                            ),
                        ),
                        _ => ::core::result::Result::Err(#refusal::PlanMismatch),
                    }
                })
            }?
        };
        builds.push(quote! { #slot => {
            let __dcbor_part = #part;
            dcbor::bounded::decode::construction::in_place::#build_method::<#ty, #a>(__dcbor_part, allocator)
        } });
        missing.push(quote! { #slot => {
            let __dcbor_part = #part;
            dcbor::bounded::decode::construction::in_place::build_part_absent::<#ty, #a>(__dcbor_part, allocator)
        } });
        reclaims.push(quote! { #state_name::#variant(state) =>
            dcbor::bounded::decode::construction::in_place::reclaim_part::<#ty, #a>(#child, cleanup)
        });
        remainings.push(quote! { #state_name::#variant(state) =>
            dcbor::bounded::decode::construction::in_place::remaining_part::<#ty, #a>(#child)
        });
        observes.push(quote! { #state_name::#variant(state) =>
            dcbor::bounded::decode::construction::in_place::observe_part::<#ty, #a>(#child, sink)
        });
        which.push(quote! { #state_name::#variant(_) => #slot });
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
    // A field's construction: which field the record's state holds, read
    // apart from its projection (the slot's borrow ends with that
    // statement), then that field's part. A record of no fields has no
    // field state the engine could hold (its `start` returns none), so the
    // engine never calls either callback; they refuse, reading nothing.
    let dispatch = |arms: &[TokenStream2]| {
        if count == 0 {
            quote! {
                let _ = (__dcbor_ctx, allocator);
                ::core::result::Result::Err(dcbor::bounded::BoundedError::PlanMismatch.into())
            }
        } else {
            quote! {
                let mut __dcbor_ctx = __dcbor_ctx;
                let __dcbor_index = __dcbor_ctx.index();
                let __dcbor_which: usize = match __dcbor_ctx.slot().custody() {
                    #(#which,)*
                    #marker
                };
                match __dcbor_which {
                    #(#arms,)*
                    _ => ::core::result::Result::Err(dcbor::bounded::BoundedError::PlanMismatch.into()),
                }
            }
        }
    };
    let missing_body = dispatch(&missing);
    let build_body = dispatch(&builds);
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
        // SAFETY: keys: schema validation guarantees unique keys, emitted in
        // ascending order. count: the sorted dense indices select each actual
        // field exactly once, and COUNT is their number. layout: projections
        // are `addr_of_mut!` of the declared fields, the compiler's layout;
        // packed types are excluded. start: one arm per dense index returns
        // that field's state variant holding its type's `INITIAL`, a
        // constant, allocating nothing and never unwinding. delegation: each
        // field's state variant delegates to that field alone, through the
        // engine's part entries, its place projected by the one expression
        // construction, cleanup and the count share. order: each callback is
        // its field's own method at its place, sound in any order as it is.
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
                __dcbor_ctx: dcbor::bounded::decode::construction::Context<'_, '_, '_, '_, Self, Self::Field, #a>,
                allocator: &mut #a,
            ) -> dcbor::bounded::decode::ConstructResult<dcbor::bounded::decode::construction::in_place::Built, #a> {
                #missing_body
            }
            fn build_field(
                __dcbor_ctx: dcbor::bounded::decode::construction::Context<'_, '_, '_, '_, Self, Self::Field, #a>,
                allocator: &mut #a,
            ) -> dcbor::bounded::decode::ConstructResult<dcbor::bounded::decode::construction::in_place::Built, #a> {
                #build_body
            }
            fn reclaim_field(
                slot: dcbor::bounded::decode::construction::reclamation::Slot<'_, Self, Self::Field>,
                cleanup: &mut dcbor::bounded::decode::construction::reclamation::Cleanup<'_, #a>,
            ) -> dcbor::bounded::BoundedResult<dcbor::bounded::decode::construction::reclamation::Reclaimed, #a> {
                let (place, state) = slot.into_parts();
                #unused_place
                match state { #(#reclaims,)* #marker }
            }
            fn remaining_field(
                slot: dcbor::bounded::decode::construction::reclamation::PeekSlot<'_, Self, Self::Field>,
            ) -> ::core::option::Option<u64> {
                let (place, state) = slot.into_parts();
                #unused_place
                match state { #(#remainings,)* #marker }
            }
            fn observe_field(
                slot: dcbor::bounded::decode::construction::reclamation::PeekSlot<'_, Self, Self::Field>,
                sink: &mut dyn dcbor::bounded::CustodySink<<#a as dcbor::bounded::Releasing>::Permit>,
            ) -> dcbor::bounded::PermitsObserved {
                let (place, state) = slot.into_parts();
                #unused_place
                match state { #(#observes,)* #marker }
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
    let constructors = super::constructors(schema);
    quote! {
        const _: () = {
            #callbacks
            // SAFETY: admission, state, escape and order: the shared field-map
            // engine's (`fields::build`): admission: its inspections, each
            // field record and every field step are admitted before they
            // run. state: it retains each field's state, recorded before
            // each step returns. done: it mints the record's `Initialized`
            // only once every field's `Done` was verified and consumed in the
            // step it arrived, its record confined to that step by its brand.
            // escape: field places are never returned. provenance: each field
            // is built against its place projected from this record's.
            // order: a build past completion or once cleanup began is refused
            // `PlanMismatch`, nothing changed. cost: `cost` of the record's
            // parts over each field's `COST`.
            unsafe impl #ig dcbor::bounded::decode::construction::in_place::InPlace<#a> for #name #tg #wc {
                const COST: dcbor::bounded::decode::construction::in_place::ConstructionCost = #cost;

                fn build_step<'__dcbor_brand>(
                    __dcbor_ctx: dcbor::bounded::decode::construction::in_place::BindingContext<'__dcbor_brand, '_, '_, '_, Self, #a>,
                    allocator: &mut #a,
                ) -> dcbor::bounded::decode::ConstructResult<dcbor::bounded::decode::construction::in_place::Building<'__dcbor_brand, Self>, #a> {
                    #constructors
                    dcbor::bounded::decode::construction::in_place::fields::build(__dcbor_ctx, allocator)
                }
            }
            // SAFETY: initial: `fields::State::INITIAL`, nothing installed.
            // state: the engine's state records every field record and its
            // state. admission: each cleanup unit, the engine's and each
            // field's (`reclaim_part`), is admitted before it runs, a refusal
            // changing nothing. cleanup: no whole-value Drop; generated field
            // callbacks retain the same address and state used to initialize
            // each field, reclaimed newest first, allocating nothing and
            // never unwinding. done: `Done` once every field record is
            // reclaimed and the metadata released. order: a step after `Done`
            // reports `Done`; the count and observation read only recorded
            // fields. depth: the deepest field's plus the generated frames'
            // levels (`depth`), the census recording the margin. count:
            // `fields::remaining`, every recorded field's and the engine's.
            unsafe impl #ig dcbor::bounded::decode::construction::reclamation::Reclaim<#a> for #name #tg #wc {
                const DISPATCH_DEPTH: usize = #depth;
                type State = dcbor::bounded::decode::construction::in_place::fields::State<
                    #field,
                    <#a as dcbor::bounded::Releasing>::Permit,
                >;
                const INITIAL: Self::State = dcbor::bounded::decode::construction::in_place::fields::State::INITIAL;
                fn reclaim_step(
                    slot: dcbor::bounded::decode::construction::reclamation::Slot<'_, Self, Self::State>,
                    cleanup: &mut dcbor::bounded::decode::construction::reclamation::Cleanup<'_, #a>,
                ) -> dcbor::bounded::BoundedResult<dcbor::bounded::decode::construction::reclamation::Reclaimed, #a> {
                    dcbor::bounded::decode::construction::in_place::fields::reclaim(slot, cleanup)
                }
                fn remaining(
                    slot: dcbor::bounded::decode::construction::reclamation::PeekSlot<'_, Self, Self::State>,
                ) -> ::core::option::Option<u64> {
                    dcbor::bounded::decode::construction::in_place::fields::remaining::<Self, #a>(slot)
                }
                fn observe_permits(
                    slot: dcbor::bounded::decode::construction::reclamation::PeekSlot<'_, Self, Self::State>,
                    sink: &mut dyn dcbor::bounded::CustodySink<<#a as dcbor::bounded::Releasing>::Permit>,
                ) -> dcbor::bounded::PermitsObserved {
                    dcbor::bounded::decode::construction::in_place::fields::observe_permits::<Self, #a>(slot, sink)
                }
            }
        };
    }
}
