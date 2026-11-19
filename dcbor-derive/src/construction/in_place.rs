//! Stable projections for unit structs and transparent single-field schemas.
use super::super::*;
mod enumeration;
mod named;

fn dispatch_depth(schema: &Schema<'_>, allocator: &Ident) -> TokenStream2 {
    let fields: Vec<_> = match &schema.input.data {
        Data::Struct(data) => data.fields.iter().collect(),
        Data::Enum(data) => data
            .variants
            .iter()
            .flat_map(|variant| variant.fields.iter())
            .collect(),
        Data::Union(_) => unreachable!("validated schema excludes unions"),
    };
    if fields.is_empty() {
        return quote!(6usize);
    }
    let bounds = fields.iter().map(|field| {
        let ty = &field.ty;
        quote! {
            let child = <#ty as dcbor::bounded::decode::construction::reclamation::Reclaim<#allocator>>::DISPATCH_DEPTH;
            if child > maximum { maximum = child; }
        }
    });
    // Covers the generated method, shared engine, variant/payload callback,
    // field engine and field callback, including present-option delegation.
    quote!({
        let mut maximum = 0usize;
        #(#bounds)*
        maximum.saturating_add(6)
    })
}

/// One variant of a generated construction state: its identifier, the name
/// its observation reports in `Debug`, and the type of the custody it
/// carries (the observation of the construction state the variant holds).
pub(super) struct Observed {
    pub(super) variant: Ident,
    pub(super) label: String,
    pub(super) observation: TokenStream2,
}

/// The custody observation of a generated construction state `state`, an
/// enum of `variants`, each holding one construction state, and an
/// uninhabited `__Marker` variant of `marker`: the observation enum
/// `observation`, one variant per state variant carrying that state's whole
/// observation, and the state's `Custody` implementation, which projects the
/// state it holds and nothing else. Comparison and `Debug` are written out
/// rather than derived: a derive would bound every type parameter, the
/// allocator's included, while the variants need only their observations'
/// own bounds, which `Custody` states.
pub(super) fn custody(
    state: &Ident,
    observation: &Ident,
    generics: &syn::Generics,
    marker: &TokenStream2,
    variants: &[Observed],
) -> TokenStream2 {
    let (ig, tg, wc) = generics.split_for_impl();
    let custody = quote!(dcbor::bounded::decode::construction::reclamation::Custody);
    let declarations = variants.iter().map(
        |Observed {
             variant,
             observation,
             ..
         }| { quote!(#variant(#observation)) },
    );
    let ranks = variants
        .iter()
        .enumerate()
        .map(|(rank, Observed { variant, .. })| quote!(Self::#variant(_) => #rank));
    let pairs = variants.iter().map(|Observed { variant, .. }| {
        quote!((Self::#variant(left), Self::#variant(right)) => core::cmp::Ord::cmp(left, right))
    });
    let debug = variants.iter().map(|Observed { variant, label, .. }| {
        quote!(Self::#variant(custody) => formatter.debug_tuple(#label).field(custody).finish())
    });
    let observe = variants.iter().map(|Observed { variant, .. }| {
        quote!(#state::#variant(held) => #observation::#variant(#custody::observe(held)))
    });
    quote! {
        /// The custody of the generated construction state of the same
        /// variant: that state's whole observation.
        #[doc(hidden)]
        pub enum #observation #ig #wc {
            #(#declarations,)*
            __Marker(core::convert::Infallible, #marker),
        }
        impl #ig #observation #tg #wc {
            fn __dcbor_rank(&self) -> usize {
                match self {
                    #(#ranks,)*
                    Self::__Marker(never, _) => match *never {},
                }
            }
        }
        impl #ig core::clone::Clone for #observation #tg #wc {
            fn clone(&self) -> Self {
                *self
            }
        }
        impl #ig core::marker::Copy for #observation #tg #wc {}
        impl #ig core::cmp::Ord for #observation #tg #wc {
            fn cmp(&self, other: &Self) -> core::cmp::Ordering {
                match (self, other) {
                    #(#pairs,)*
                    _ => core::cmp::Ord::cmp(&self.__dcbor_rank(), &other.__dcbor_rank()),
                }
            }
        }
        impl #ig core::cmp::PartialOrd for #observation #tg #wc {
            fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
                Some(core::cmp::Ord::cmp(self, other))
            }
        }
        impl #ig core::cmp::PartialEq for #observation #tg #wc {
            fn eq(&self, other: &Self) -> bool {
                core::cmp::Ord::cmp(self, other) == core::cmp::Ordering::Equal
            }
        }
        impl #ig core::cmp::Eq for #observation #tg #wc {}
        impl #ig core::fmt::Debug for #observation #tg #wc {
            fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match self {
                    #(#debug,)*
                    Self::__Marker(never, _) => match *never {},
                }
            }
        }
        impl #ig #custody for #state #tg #wc {
            type Observation = #observation #tg;
            fn observe(&mut self) -> Self::Observation {
                match self {
                    #(#observe,)*
                    #state::__Marker(never, _) => match *never {},
                }
            }
        }
    }
}

/// Statements naming every constructor of the derived type: a struct's, or
/// each variant's of an enum, for the type's `build_step`, a body the
/// compiler always keeps live (a trait implementation's). The binding
/// constructs the value in place, each field by its own binding and an
/// enum's native tag by a raw write (`Variants::commit`), which the
/// dead-code analysis does not see; naming the constructors here, never
/// called, states that construction, so a type decoded only through this
/// binding is not reported as never constructed in the user's crate. A
/// tuple or unit constructor is named as a value, a named one through a
/// closure over its fields' own types; nothing is evaluated.
pub(super) fn constructors(schema: &Schema<'_>) -> TokenStream2 {
    let name = schema.name();
    let (_, tg, _) = schema.input.generics.split_for_impl();
    let turbofish = tg.as_turbofish();
    let named = |path: TokenStream2, fields: &Fields| match fields {
        Fields::Unit | Fields::Unnamed(_) => quote!(let _ = #path;),
        Fields::Named(named) => {
            let idents: Vec<_> = named.named.iter().map(|field| &field.ident).collect();
            let types = named.named.iter().map(|field| &field.ty);
            quote!(let _ = |#(#idents: #types),*| #path { #(#idents),* };)
        }
    };
    match &schema.input.data {
        Data::Struct(data) => named(quote!(#name #turbofish), &data.fields),
        Data::Enum(data) => data
            .variants
            .iter()
            .map(|variant| {
                let ident = &variant.ident;
                named(quote!(#name #turbofish :: #ident), &variant.fields)
            })
            .collect(),
        Data::Union(_) => unreachable!("validated schema excludes unions"),
    }
}

pub(super) fn expand(schema: &Schema<'_>) -> TokenStream2 {
    if let Data::Enum(data) = &schema.input.data {
        return enumeration::expand(schema, data);
    }
    let Data::Struct(data) = &schema.input.data else {
        return quote!();
    };
    // Child constructors require aligned destinations. A raw field projection
    // does not make a packed field suitably aligned for its own type.
    for attr in &schema.input.attrs {
        if attr.path().is_ident("repr")
            && let Ok(items) = attr.parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            )
            && items.iter().any(|item| item.path().is_ident("packed"))
        {
            return quote!();
        }
    }
    let field = match &data.fields {
        Fields::Named(fields) => return named::expand(schema, fields),
        Fields::Unit => None,
        Fields::Unnamed(fields) if fields.unnamed.len() == 1 => Some(&fields.unnamed[0].ty),
        _ => return quote!(),
    };
    let name = schema.name();
    let a = schema.fresh("__DcborInPlaceAllocator");
    let depth = dispatch_depth(schema, &a);
    let mut generics = schema.input.generics.clone();
    generics
        .params
        .push(syn::parse_quote!(#a: dcbor::bounded::Allocator));
    if let Some(ty) = field {
        generics
            .make_where_clause()
            .predicates
            .push(syn::parse_quote!(
                #ty: dcbor::bounded::decode::construction::in_place::InPlace<#a>
            ));
    }
    let (ig, _, wc) = generics.split_for_impl();
    let (_, tg, _) = schema.input.generics.split_for_impl();
    // The untagged value's construction state: the field's own for a
    // newtype, which is built in the same bytes; whether the value is
    // written for a unit struct.
    let (untagged, untagged_initial) = match field {
        Some(ty) => (
            quote!(<#ty as dcbor::bounded::decode::construction::reclamation::Reclaim<#a>>::State),
            quote!(<#ty as dcbor::bounded::decode::construction::reclamation::Reclaim<#a>>::INITIAL),
        ),
        None => (
            quote!(dcbor::bounded::decode::construction::reclamation::Written),
            quote!(dcbor::bounded::decode::construction::reclamation::Written::Empty),
        ),
    };
    // The newtype's field slot from the value's, in the slot's mode: the
    // field's place by compiler-provided field projection over the actual
    // struct layout (packed representations are excluded above), forming no
    // reference, and the newtype's state, which is the field's own.
    // Construction, cleanup and the cleanup count all project the field
    // through this one expression.
    let child = field.map(|ty| {
        // The projection itself, in an unsafe context its user supplies.
        let child_raw = quote! {
            slot.child(|value| ::core::ptr::addr_of_mut!((*value).0), |state| state)
        };
        let child_of = quote! {
            // SAFETY: the compiler's projection of the newtype's one field,
            // within the value, and the newtype's state, which is that
            // field's own: a one-field struct has exactly its field's
            // initialization and resource ownership.
            unsafe { #child_raw }
        };
        (ty, child_of, child_raw)
    });
    // Construction takes the value's context (`__dcbor_ctx`); a newtype's
    // field is a part in the same bytes, from the same node, its context
    // projected from the value's and stepped through the engine's part
    // entry. The newtype holds no index of its own: the field's node is the
    // context's, recomputed at every step. The untagged body is shared by a
    // tagged payload's step, which reports the engine's `Built` to the tagged
    // engine, and by an untagged value's `build_step`, which reports
    // `Building` with the value's record minted from its context's assembly,
    // read before the context is consumed (`__dcbor_assembly`).
    let (body, reclaim) = if let Some((ty, child_of, child_raw)) = &child {
        (
            quote! {
                let mut __dcbor_ctx = __dcbor_ctx;
                let __dcbor_index = __dcbor_ctx.index();
                // SAFETY: the field's slot is the compiler's projection of
                // the newtype's one field within the value's own slot, its
                // state the newtype's, which is that field's own.
                let __dcbor_field = match unsafe {
                    __dcbor_ctx.part(__dcbor_index, |slot| {
                        ::core::result::Result::Ok::<_, ::core::convert::Infallible>(#child_raw)
                    })
                } {
                    ::core::result::Result::Ok(field) => field,
                    ::core::result::Result::Err(never) => match never {},
                };
                let __dcbor_built = __i::build_part::<#ty, #a>(__dcbor_field, allocator)?;
            },
            quote! {
                dcbor::bounded::decode::construction::in_place::reclaim_part::<#ty, #a>(#child_of, cleanup)
            },
        )
    } else {
        (
            quote! {
                let __dcbor_node = __dcbor_ctx.node();
                let mut slot = __dcbor_ctx.into_slot();
                let (place, state) = slot.parts();
                if *state != dcbor::bounded::decode::construction::reclamation::Written::Empty {
                    return ::core::result::Result::Err(dcbor::bounded::BoundedError::PlanMismatch.into());
                }
                dcbor::bounded::decode::construction::in_place::step(allocator)?;
                if !matches!(
                    __dcbor_node.map(|node| node.kind()),
                    ::core::option::Option::Some(dcbor::bounded::decode::Kind::Null)
                ) { return ::core::result::Result::Err(dcbor::bounded::decode::wrong_type()); }
                // SAFETY: the slot pairs the place with this state, which is
                // empty; a unit struct is zero-sized and has no fields to
                // initialize.
                unsafe { place.write(state, Self) };
                *state = dcbor::bounded::decode::construction::reclamation::Written::Initialized;
                let __dcbor_built = __i::Built::Done;
            },
            quote! {
                let mut slot = slot;
                dcbor::bounded::decode::construction::in_place::step(cleanup)?;
                *slot.custody() = dcbor::bounded::decode::construction::reclamation::Written::Empty;
                Ok(__r::Reclaimed::Done)
            },
        )
    };
    let build = quote! {
        #body
        ::core::result::Result::Ok(__dcbor_built)
    };
    let building = quote! {
        let __dcbor_assembly = __dcbor_ctx.assembly();
        #body
        // SAFETY: `Done` is reported only once the value is initialized whole
        // at the context's place: a newtype's one field by a `Done` whose
        // record, confined by its brand to this step, `build_part` verified
        // against the field's place, projected from this value's; a unit
        // struct, zero-sized, by its admitted write recorded `Initialized`.
        // A build never follows the value's cleanup: its state is refused
        // once written, and its owner refuses a build once cleanup began.
        ::core::result::Result::Ok(unsafe { __i::reported(__dcbor_built, __dcbor_assembly) })
    };
    // The untagged value's remaining cleanup calls: the field's own for a
    // newtype; one for a unit struct, whose cleanup is one step.
    let untagged_remaining = match &child {
        Some((ty, child_of, _)) => quote! {
            dcbor::bounded::decode::construction::in_place::remaining_part::<#ty, #a>(#child_of)
        },
        None => quote! {
            let _ = slot;
            ::core::option::Option::Some(1)
        },
    };
    // The untagged value's permits, reported inside the caller's open
    // group: the field's own for a newtype, through the same projection;
    // none for a unit struct.
    let untagged_permits = match &child {
        Some((ty, child_of, _)) => quote! {
            dcbor::bounded::decode::construction::in_place::observe_part::<#ty, #a>(#child_of, sink)
        },
        None => quote! {
            let _ = (slot, sink);
            dcbor::bounded::PermitsObserved::Complete
        },
    };
    let sink_of =
        quote!(&mut dyn dcbor::bounded::CustodySink<<#a as dcbor::bounded::Releasing>::Permit>);
    let cleanup_of =
        quote!(&mut dcbor::bounded::decode::construction::reclamation::Cleanup<'_, #a>);
    let slot_of = |state: TokenStream2| quote!(dcbor::bounded::decode::construction::reclamation::Slot<'_, Self, #state>);
    let peek_of = |state: TokenStream2| quote!(dcbor::bounded::decode::construction::reclamation::PeekSlot<'_, Self, #state>);
    let payload = if let Some(tag) = schema.tag {
        let slot = slot_of(quote!(Self::Untagged));
        let peek = peek_of(quote!(Self::Untagged));
        quote! {
            // SAFETY: initial: the untagged state starts as the untagged
            // value's initial state (the field's `INITIAL`, or a unit's
            // unwritten state). projection: compiler field projections
            // (`addr_of_mut!`) preserve payload addresses, and each callback
            // delegates to the field's own InPlace and Reclaim through the
            // engine's part entries with the state it carries. tag: the
            // callbacks read and write the untagged payload alone, never the
            // outer tag, which `tagged::build` inspects. order: each callback
            // is the field's own method at its place, sound in any order as
            // that method is.
            unsafe impl #ig dcbor::bounded::decode::construction::in_place::tagged::Payload<#a> for #name #tg #wc {
                const TAG: u64 = #tag;
                type Untagged = #untagged;
                const UNTAGGED: Self::Untagged = #untagged_initial;
                fn build_payload(
                    __dcbor_ctx: dcbor::bounded::decode::construction::Context<'_, '_, '_, '_, Self, Self::Untagged, #a>,
                    allocator: &mut #a,
                ) -> dcbor::bounded::decode::ConstructResult<dcbor::bounded::decode::construction::in_place::Built, #a> {
                    use dcbor::bounded::decode::construction::in_place as __i;
                    #build
                }
                fn reclaim_payload(
                    slot: #slot,
                    cleanup: #cleanup_of,
                ) -> dcbor::bounded::BoundedResult<dcbor::bounded::decode::construction::reclamation::Reclaimed, #a> {
                    use dcbor::bounded::decode::construction::reclamation as __r;
                    #reclaim
                }
                fn remaining_payload(slot: #peek) -> ::core::option::Option<u64> {
                    #untagged_remaining
                }
                fn observe_payload(slot: #peek, sink: #sink_of) -> dcbor::bounded::PermitsObserved {
                    #untagged_permits
                }
            }
        }
    } else {
        quote!()
    };
    // A unit is one check step and one cleanup step (`in_place::step`); a
    // newtype is its field's construction in the same bytes. Every composed
    // cost is checked and unwrapped by `const_cost!`, so one that does not
    // fit in `u64` fails to compile where the type is first used.
    let payload_cost = match field {
        Some(ty) => {
            quote!(<#ty as dcbor::bounded::decode::construction::in_place::InPlace<#a>>::COST)
        }
        None => quote!(dcbor::const_cost!(
            match dcbor::bounded::decode::construction::in_place::STEP_COST.checked_mul(2) {
                ::core::option::Option::Some(steps) => ::core::option::Option::Some(
                    dcbor::bounded::decode::construction::in_place::ConstructionCost::fixed(steps),
                ),
                ::core::option::Option::None => ::core::option::Option::None,
            }
        )),
    };
    let cost = if schema.tag.is_some() {
        quote!(
            dcbor::const_cost!(dcbor::bounded::decode::construction::in_place::tagged::cost::<#untagged, <#a as dcbor::bounded::Releasing>::Permit>(#payload_cost))
        )
    } else {
        payload_cost
    };
    let (building, reclaim, remaining, permits, state, initial) = if schema.tag.is_some() {
        (
            quote!(__i::tagged::build::<Self, #a>(__dcbor_ctx, allocator)),
            quote!(dcbor::bounded::decode::construction::in_place::tagged::reclaim::<Self, #a>(slot, cleanup)),
            quote!(dcbor::bounded::decode::construction::in_place::tagged::remaining::<Self, #a>(slot)),
            quote!(dcbor::bounded::decode::construction::in_place::tagged::observe_permits::<Self, #a>(slot, sink)),
            quote!(dcbor::bounded::decode::construction::in_place::tagged::State<#untagged, <#a as dcbor::bounded::Releasing>::Permit>),
            quote!(dcbor::bounded::decode::construction::in_place::tagged::State::INITIAL),
        )
    } else {
        (
            building,
            quote! {
                use dcbor::bounded::decode::construction::reclamation as __r;
                #reclaim
            },
            untagged_remaining,
            untagged_permits,
            untagged,
            untagged_initial,
        )
    };
    let slot = slot_of(quote!(Self::State));
    let peek = peek_of(quote!(Self::State));
    let constructors = constructors(schema);
    quote! {
        #payload
        // SAFETY: admission, state, done, escape and order: the generated
        // code delegates initialization to the field's mandatory in-place
        // contract through the engine's part entries (`build_part`), or, for
        // a tagged value, to `tagged::build`; a unit struct's one check unit
        // is admitted before it writes nothing: admission: every unit is the
        // field's or the engine's, admitted first. state: the field's state,
        // carried in this one, records every write. done: `Done` exactly
        // when the field's construction is. escape: no place is returned or
        // kept. provenance: the generated projection (`addr_of_mut!`)
        // preserves the final address, a child of the slot's place. order:
        // the field's own refusals, and the session's, apply unchanged.
        // cost: the field's `COST`, a unit's two steps, or the tagged
        // composition over either.
        unsafe impl #ig dcbor::bounded::decode::construction::in_place::InPlace<#a> for #name #tg #wc {
            const COST: dcbor::bounded::decode::construction::in_place::ConstructionCost = #cost;

            fn build_step<'__dcbor_brand>(
                __dcbor_ctx: dcbor::bounded::decode::construction::in_place::BindingContext<'__dcbor_brand, '_, '_, '_, Self, #a>,
                allocator: &mut #a,
            ) -> dcbor::bounded::decode::ConstructResult<dcbor::bounded::decode::construction::in_place::Building<'__dcbor_brand, Self>, #a> {
                use dcbor::bounded::decode::construction::in_place as __i;
                #constructors
                #building
            }
        }
        // SAFETY: initial: the field's `INITIAL`, a unit's unwritten state,
        // or the tagged initial state. state: the field's state records what
        // it initialized and acquired. admission: every cleanup unit is the
        // field's (`reclaim_part`) or the tagged engine's, admitted first.
        // cleanup: no generated type Drop is invoked; the separate coherence
        // guard rejects user-defined Drop, and field cleanup is mandatory,
        // allocating nothing and never unwinding. done: `Done` exactly when
        // the field's cleanup is. order: the field's own methods at its
        // place, sound in any order as they are. depth: the field's plus the
        // generated frames' levels (`depth`), the census recording the
        // margin. count: the field's remaining, or a unit's one step.
        unsafe impl #ig dcbor::bounded::decode::construction::reclamation::Reclaim<#a> for #name #tg #wc {
            const DISPATCH_DEPTH: usize = #depth;
            type State = #state;
            const INITIAL: Self::State = #initial;
            fn reclaim_step(
                slot: #slot,
                cleanup: #cleanup_of,
            ) -> dcbor::bounded::BoundedResult<dcbor::bounded::decode::construction::reclamation::Reclaimed, #a> {
                #reclaim
            }
            fn remaining(slot: #peek) -> ::core::option::Option<u64> {
                #remaining
            }
            fn observe_permits(slot: #peek, sink: #sink_of) -> dcbor::bounded::PermitsObserved {
                #permits
            }
        }
    }
}
