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
        let child_of = quote! {
            // SAFETY: the compiler's projection of the newtype's one field,
            // within the value, and the newtype's state, which is that
            // field's own: a one-field struct has exactly its field's
            // initialization and resource ownership.
            unsafe { slot.child(|value| core::ptr::addr_of_mut!((*value).0), |state| state) }
        };
        (ty, child_of)
    });
    let (build, reclaim) = if let Some((ty, child_of)) = &child {
        (
            quote! {
                <#ty as __i::InPlace<#a>>::build_step(document, index, #child_of, allocator)
            },
            quote! {
                <#ty as __r::Reclaim<#a>>::reclaim_step(#child_of, allocator)
            },
        )
    } else {
        (
            quote! {
                let mut slot = slot;
                let (place, state) = slot.parts();
                if *state != dcbor::bounded::decode::construction::reclamation::Written::Empty {
                    return Err(dcbor::bounded::BoundedError::PlanMismatch.into());
                }
                dcbor::bounded::decode::construction::in_place::step(allocator)?;
                if !matches!(
                    dcbor::bounded::decode::construction::node_at(document, index).map(|node| node.kind()),
                    Some(dcbor::bounded::decode::Kind::Null)
                ) { return Err(dcbor::bounded::decode::wrong_type()); }
                // SAFETY: the slot pairs the place with this state, which is
                // empty; a unit struct is zero-sized and has no fields to
                // initialize.
                unsafe { place.write(state, Self) };
                *state = dcbor::bounded::decode::construction::reclamation::Written::Initialized;
                Ok(__i::Built::Done)
            },
            quote! {
                let mut slot = slot;
                dcbor::bounded::decode::construction::in_place::step(allocator)?;
                *slot.custody() = dcbor::bounded::decode::construction::reclamation::Written::Empty;
                Ok(__r::Reclaimed::Done)
            },
        )
    };
    // The untagged value's remaining cleanup calls: the field's own for a
    // newtype; one for a unit struct, whose cleanup is one step.
    let untagged_remaining = match &child {
        Some((ty, child_of)) => quote! {
            <#ty as dcbor::bounded::decode::construction::reclamation::Reclaim<#a>>::remaining(#child_of)
        },
        None => quote! {
            let _ = slot;
            1
        },
    };
    let slot_of = |state: TokenStream2| quote!(dcbor::bounded::decode::construction::reclamation::Slot<'_, Self, #state>);
    let peek_of = |state: TokenStream2| quote!(dcbor::bounded::decode::construction::reclamation::PeekSlot<'_, Self, #state>);
    let payload = if let Some(tag) = schema.tag {
        let slot = slot_of(quote!(Self::Untagged));
        let peek = peek_of(quote!(Self::Untagged));
        quote! {
            // SAFETY: compiler field projections preserve payload addresses,
            // and the untagged state starts as the untagged value's initial
            // state.
            unsafe impl #ig dcbor::bounded::decode::construction::in_place::tagged::Payload<#a> for #name #tg #wc {
                const TAG: u64 = #tag;
                type Untagged = #untagged;
                const UNTAGGED: Self::Untagged = #untagged_initial;
                fn build_payload(
                    document: &dcbor::bounded::decode::Document<'_, #a::Permit>, index: usize,
                    slot: #slot,
                    allocator: &mut #a,
                ) -> dcbor::bounded::decode::ConstructResult<dcbor::bounded::decode::construction::in_place::Built, #a> {
                    use dcbor::bounded::decode::construction::in_place as __i;
                    #build
                }
                fn reclaim_payload(
                    slot: #slot,
                    allocator: &mut #a,
                ) -> dcbor::bounded::BoundedResult<dcbor::bounded::decode::construction::reclamation::Reclaimed, #a> {
                    use dcbor::bounded::decode::construction::reclamation as __r;
                    #reclaim
                }
                fn remaining_payload(slot: #peek) -> u64 {
                    #untagged_remaining
                }
            }
        }
    } else {
        quote!()
    };
    // A unit is one check step and one cleanup step (`in_place::step`); a
    // newtype is its field's construction in the same bytes.
    let payload_cost = match field {
        Some(ty) => {
            quote!(<#ty as dcbor::bounded::decode::construction::in_place::InPlace<#a>>::COST)
        }
        None => quote!(
            dcbor::bounded::decode::construction::in_place::ConstructionCost::fixed(
                dcbor::bounded::decode::construction::in_place::times(
                    dcbor::bounded::decode::construction::in_place::STEP_COST,
                    2,
                )
            )
        ),
    };
    let cost = if schema.tag.is_some() {
        quote!(dcbor::bounded::decode::construction::in_place::tagged::cost::<#untagged, <#a as dcbor::bounded::Allocator>::Permit>(#payload_cost))
    } else {
        payload_cost
    };
    let (build, reclaim, remaining, state, initial) = if schema.tag.is_some() {
        (
            quote!(__i::tagged::build::<Self, #a>(document, index, slot, allocator)),
            quote!(dcbor::bounded::decode::construction::in_place::tagged::reclaim::<Self, #a>(slot, allocator)),
            quote!(dcbor::bounded::decode::construction::in_place::tagged::remaining::<Self, #a>(slot)),
            quote!(dcbor::bounded::decode::construction::in_place::tagged::State<#untagged, <#a as dcbor::bounded::Allocator>::Permit>),
            quote!(dcbor::bounded::decode::construction::in_place::tagged::State::INITIAL),
        )
    } else {
        (
            build,
            quote! {
                use dcbor::bounded::decode::construction::reclamation as __r;
                #reclaim
            },
            untagged_remaining,
            untagged,
            untagged_initial,
        )
    };
    let slot = slot_of(quote!(Self::State));
    let peek = peek_of(quote!(Self::State));
    quote! {
        #payload
        // SAFETY: the generated projection preserves the final address and
        // delegates initialization to the field's mandatory in-place contract.
        unsafe impl #ig dcbor::bounded::decode::construction::in_place::InPlace<#a> for #name #tg #wc {
            const COST: dcbor::bounded::decode::construction::in_place::ConstructionCost = #cost;

            fn build_step(
                document: &dcbor::bounded::decode::Document<'_, #a::Permit>, index: usize,
                slot: #slot,
                allocator: &mut #a,
            ) -> dcbor::bounded::decode::ConstructResult<dcbor::bounded::decode::construction::in_place::Built, #a> {
                use dcbor::bounded::decode::construction::in_place as __i;
                #build
            }
        }
        // SAFETY: no generated type Drop is invoked. The separate coherence
        // guard rejects user-defined Drop; field cleanup is mandatory.
        unsafe impl #ig dcbor::bounded::decode::construction::reclamation::Reclaim<#a> for #name #tg #wc {
            const DISPATCH_DEPTH: usize = #depth;
            type State = #state;
            const INITIAL: Self::State = #initial;
            fn reclaim_step(
                slot: #slot,
                allocator: &mut #a,
            ) -> dcbor::bounded::BoundedResult<dcbor::bounded::decode::construction::reclamation::Reclaimed, #a> {
                #reclaim
            }
            fn remaining(slot: #peek) -> u64 {
                #remaining
            }
        }
    }
}
