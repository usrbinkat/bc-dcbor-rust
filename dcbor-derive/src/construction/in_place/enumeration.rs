use super::super::super::*;

pub(super) fn expand(schema: &Schema<'_>, data: &syn::DataEnum) -> TokenStream2 {
    let mut c = false;
    let mut u8_repr = false;
    let mut unsupported = false;
    for attr in &schema.input.attrs {
        if !attr.path().is_ident("repr") {
            continue;
        }
        let Ok(items) = attr.parse_args_with(
            syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
        ) else {
            return Error::new_spanned(attr, "invalid enum representation").to_compile_error();
        };
        for item in items {
            if item.path().is_ident("C") {
                c = true;
            } else if item.path().is_ident("u8") {
                u8_repr = true;
            } else {
                unsupported = true;
            }
        }
    }
    if unsupported || (!c && !u8_repr) {
        return Error::new_spanned(
            &schema.input.ident,
            "bounded in-place enum construction requires repr(C), repr(u8), or repr(C, u8)",
        )
        .to_compile_error();
    }
    if data.variants.is_empty() {
        return Error::new_spanned(&schema.input.ident, "empty enums cannot be decoded")
            .to_compile_error();
    }
    let name = schema.name();
    let a = schema.fresh("__DcborEnumAllocator");
    let depth = super::dispatch_depth(schema, &a);
    let tag_name = schema.fresh("__DcborNativeTag");
    let union_name = schema.fresh("__DcborPayloadUnion");
    let root_name = schema.fresh("__DcborEnumLayout");
    let payload_name = schema.fresh("__DcborPayloadState");
    let observation_name = schema.fresh("__DcborPayloadObservation");
    let (base_ig, tg, base_wc) = schema.input.generics.split_for_impl();
    let mut generics = schema.input.generics.clone();
    generics
        .params
        .push(syn::parse_quote!(#a: dcbor::bounded::Allocator));
    for variant in &data.variants {
        for field in &variant.fields {
            let ty = &field.ty;
            generics
                .make_where_clause()
                .predicates
                .push(syn::parse_quote!(
                    #ty: dcbor::bounded::decode::construction::in_place::InPlace<#a>
                ));
        }
    }
    let (ig, payload_tg, wc) = generics.split_for_impl();
    let tag_repr = if u8_repr { quote!(u8) } else { quote!(C) };
    let tag_variants = data.variants.iter().map(|v| &v.ident);
    let count = data.variants.len();
    let tag = match schema.tag {
        Some(tag) => quote!(Some(#tag)),
        None => quote!(None),
    };
    let mut definitions = Vec::new();
    let mut union_fields = Vec::new();
    let mut descriptors = Vec::new();
    let mut builds = Vec::new();
    let mut reclaims = Vec::new();
    let mut remainings = Vec::new();
    let mut commits = Vec::new();
    let mut costs = Vec::new();
    let mut payloads = Vec::new();
    let mut observed = Vec::new();
    let mut starts = Vec::new();
    let permit = quote!(<#a as dcbor::bounded::Allocator>::Permit);
    for (slot, variant) in data.variants.iter().enumerate() {
        let helper = schema.fresh(&format!("__DcborVariant{slot}"));
        let union_field = Ident::new(&format!("v{slot}"), proc_macro2::Span::mixed_site());
        let payload_variant =
            Ident::new(&format!("Variant{slot}"), proc_macro2::Span::mixed_site());
        let native_variant = &variant.ident;
        let disc = parse_n(&variant.attrs)
            .expect("validated variant")
            .expect("variant key")
            .0;
        let positional = !matches!(&variant.fields, Fields::Named(_));
        let length = match &variant.fields {
            Fields::Unit => 0,
            Fields::Named(_) => 2,
            Fields::Unnamed(fields) => fields.unnamed.len() as u64 + 1,
        };
        descriptors.push(quote!(#slot => (#disc, #length)));
        let mut fields: syn::FieldsNamed = syn::parse_quote!({});
        for (index, field) in variant.fields.iter().enumerate() {
            let mut field = field.clone();
            if positional {
                field.ident = Some(Ident::new(
                    &format!("f{index}"),
                    proc_macro2::Span::mixed_site(),
                ));
                let key = index as u64;
                field.attrs = vec![syn::parse_quote!(#[cbor(n = #key)])];
            }
            fields.named.push(field);
        }
        // The synthetic schema lists payload fields only. The native tag and
        // zero-sized generic marker are not part of payload initialization.
        let fake: DeriveInput = syn::parse_quote!(struct #helper #base_ig #base_wc #fields);
        let payload_schema = Schema::parse(&fake).expect("validated variant payload");
        let callbacks = super::named::expand_fields(&payload_schema, &fields, positional, false);
        // A variant's payload is built by the field engine, its fields in key
        // order: positional keys are their indices, named ones their own.
        let mut keyed: Vec<_> = fields
            .named
            .iter()
            .map(|field| {
                let key = parse_n(&field.attrs)
                    .expect("validated field attribute")
                    .expect("required field key")
                    .0;
                (key, &field.ty)
            })
            .collect();
        keyed.sort_by_key(|(key, _)| *key);
        let types: Vec<_> = keyed.into_iter().map(|(_, ty)| ty).collect();
        let field = super::named::field_state(&quote!(#helper #tg), &a);
        costs.push(super::named::cost(&types, positional, &field, &a));
        // The variant's payload state: the field engine's over the variant's
        // payload fields.
        payloads.push(quote! {
            #payload_variant(dcbor::bounded::decode::construction::in_place::fields::State<#field, #permit>)
        });
        observed.push(super::Observed {
            variant: payload_variant.clone(),
            label: native_variant.to_string(),
            observation: quote! {
                <dcbor::bounded::decode::construction::in_place::fields::State<#field, #permit>
                    as dcbor::bounded::decode::construction::reclamation::Custody>::Observation
            },
        });
        starts.push(quote! {
            #slot => Some(#payload_name::#payload_variant(
                dcbor::bounded::decode::construction::in_place::fields::State::INITIAL
            ))
        });
        let declarations = fields.named.iter().map(|f| {
            let ident = &f.ident;
            let ty = &f.ty;
            quote!(#ident: #ty)
        });
        let fresh_field = |base: &str| {
            let mut candidate = base.to_owned();
            while fields
                .named
                .iter()
                .any(|f| f.ident.as_ref().is_some_and(|id| id == &candidate))
            {
                candidate.push('_');
            }
            Ident::new(&candidate, proc_macro2::Span::mixed_site())
        };
        let tag_field = fresh_field("__tag");
        let marker_field = fresh_field("__marker");
        let native_tag = if c {
            quote!()
        } else {
            quote!(#tag_field: #tag_name,)
        };
        definitions.push(quote! {
            #[repr(C)]
            struct #helper #base_ig #base_wc {
                #native_tag
                #(#declarations,)*
                #marker_field: core::marker::PhantomData<fn() -> #name #tg>,
            }
            #callbacks
        });
        union_fields.push(quote!(#union_field: core::mem::ManuallyDrop<#helper #tg>));
        // The variant's payload place from the root's, in the root place's
        // mode, by raw projection alone. With repr(C) the tag precedes the
        // payload union, whose `ManuallyDrop` members lay out each helper at
        // its start; with repr(u8) the enum is a union of repr(C) variant
        // structs, each starting with the native tag and then its own
        // fields. Construction, cleanup and the cleanup count all project the
        // payload through this one expression.
        let place_of = if c {
            quote! {
                place.project(|value| {
                    core::ptr::addr_of_mut!((*value.cast::<#root_name #tg>()).payload)
                        .cast::<#helper #tg>()
                })
            }
        } else {
            quote! { place.cast::<#helper #tg>() }
        };
        let payload = quote! {
            // SAFETY: the payload projection above, by raw pointer alone,
            // paired with the payload's own field-engine state, which this
            // variant carries.
            unsafe {
                dcbor::bounded::decode::construction::reclamation::Slot::new(#place_of, state)
            }
        };
        builds.push(quote! { #payload_name::#payload_variant(state) =>
            dcbor::bounded::decode::construction::in_place::fields::build::<#helper #tg, #a>(
                document, index, #payload, allocator
            )
        });
        reclaims.push(quote! { #payload_name::#payload_variant(state) =>
            dcbor::bounded::decode::construction::in_place::fields::reclaim::<#helper #tg, #a>(
                #payload, allocator
            )
        });
        remainings.push(quote! { #payload_name::#payload_variant(state) =>
            dcbor::bounded::decode::construction::in_place::fields::remaining::<#helper #tg, #a>(
                #payload
            )
        });
        // The native tag of the variant the payload state names.
        commits.push(quote! { #payload_name::#payload_variant(_) => #tag_name::#native_variant });
    }
    // The uninhabited marker variant uses every generic parameter and can
    // never be constructed.
    let marker = quote! {
        #payload_name::__Marker(never, _) => match *never {}
    };
    let phantom = quote!(core::marker::PhantomData<fn() -> (#name #tg, #a)>);
    let custody = super::custody(
        &payload_name,
        &observation_name,
        &generics,
        &phantom,
        &observed,
    );
    let c_layout = if c {
        quote! {
            #[repr(C)]
            union #union_name #base_ig #base_wc { #(#union_fields,)* }
            #[repr(C)]
            struct #root_name #base_ig #base_wc {
                tag: #tag_name,
                payload: #union_name #tg,
            }
        }
    } else {
        quote!()
    };
    quote! {
        const _: () = {
            #[repr(#tag_repr)]
            enum #tag_name { #(#tag_variants,)* }
            #(#definitions)*
            #c_layout
            /// The selected variant's payload state, naming the variant: a
            /// `pub` associated type, unnameable outside this constant and
            /// constructed only by the generated `start`.
            #[doc(hidden)]
            pub enum #payload_name #ig #wc {
                #(#payloads,)*
                __Marker(core::convert::Infallible, #phantom),
            }
            #custody
            // SAFETY: helpers mirror the explicitly declared enum layout;
            // each payload state variant delegates to its own variant's
            // helper; no enum reference is created until the final native tag
            // write.
            unsafe impl #ig dcbor::bounded::decode::construction::in_place::enumeration::Variants<#a> for #name #tg #wc {
                const COUNT: usize = #count;
                const TAG: Option<u64> = #tag;
                const TAG_BYTES: usize = core::mem::size_of::<#tag_name>();
                type Payload = #payload_name #payload_tg;
                fn descriptor(variant: usize) -> (u64, u64) {
                    match variant { #(#descriptors,)* _ => unreachable!("validated variant index") }
                }
                fn start(variant: usize) -> Option<Self::Payload> {
                    match variant { #(#starts,)* _ => None }
                }
                fn build_variant(
                    document: &dcbor::bounded::decode::Document<'_, #a::Permit>, index: usize,
                    slot: dcbor::bounded::decode::construction::reclamation::Slot<'_, Self, Self::Payload>,
                    allocator: &mut #a,
                ) -> dcbor::bounded::decode::ConstructResult<dcbor::bounded::decode::construction::in_place::Built, #a> {
                    let (place, state) = slot.into_parts();
                    match state { #(#builds,)* #marker }
                }
                fn reclaim_variant(
                    slot: dcbor::bounded::decode::construction::reclamation::Slot<'_, Self, Self::Payload>,
                    allocator: &mut #a,
                ) -> dcbor::bounded::BoundedResult<dcbor::bounded::decode::construction::reclamation::Reclaimed, #a> {
                    let (place, state) = slot.into_parts();
                    match state { #(#reclaims,)* #marker }
                }
                fn remaining_variant(
                    slot: dcbor::bounded::decode::construction::reclamation::PeekSlot<'_, Self, Self::Payload>,
                ) -> u64 {
                    let (place, state) = slot.into_parts();
                    match state { #(#remainings,)* #marker }
                }
                fn commit(slot: dcbor::bounded::decode::construction::reclamation::Slot<'_, Self, Self::Payload>) {
                    let (place, state) = slot.into_parts();
                    let tag = match state { #(#commits,)* #marker };
                    // SAFETY: the native tag lies at the start of the value in
                    // both layouts, in bytes no payload place covers; it is
                    // plain data, so the write drops nothing.
                    unsafe { place.cast::<#tag_name>().write(state, tag) };
                }
            }
            unsafe impl #ig dcbor::bounded::decode::construction::in_place::InPlace<#a> for #name #tg #wc {
                const COST: dcbor::bounded::decode::construction::in_place::ConstructionCost =
                    dcbor::bounded::decode::construction::in_place::enumeration::cost::<
                        <Self as dcbor::bounded::decode::construction::in_place::enumeration::Variants<#a>>::Payload,
                        #permit,
                    >(
                        core::mem::size_of::<#tag_name>(),
                        &[#(#costs),*],
                    );

                fn build_step(document: &dcbor::bounded::decode::Document<'_, #a::Permit>, index: usize,
                    slot: dcbor::bounded::decode::construction::reclamation::Slot<'_, Self, Self::State>,
                    allocator: &mut #a,
                ) -> dcbor::bounded::decode::ConstructResult<dcbor::bounded::decode::construction::in_place::Built, #a> {
                    dcbor::bounded::decode::construction::in_place::enumeration::build(document, index, slot, allocator)
                }
            }
            unsafe impl #ig dcbor::bounded::decode::construction::reclamation::Reclaim<#a> for #name #tg #wc {
                const DISPATCH_DEPTH: usize = #depth;
                type State = dcbor::bounded::decode::construction::in_place::enumeration::State<
                    <Self as dcbor::bounded::decode::construction::in_place::enumeration::Variants<#a>>::Payload,
                    #permit,
                >;
                const INITIAL: Self::State = dcbor::bounded::decode::construction::in_place::enumeration::State::INITIAL;
                fn reclaim_step(
                    slot: dcbor::bounded::decode::construction::reclamation::Slot<'_, Self, Self::State>,
                    allocator: &mut #a,
                ) -> dcbor::bounded::BoundedResult<dcbor::bounded::decode::construction::reclamation::Reclaimed, #a> {
                    dcbor::bounded::decode::construction::in_place::enumeration::reclaim(slot, allocator)
                }
                fn remaining(
                    slot: dcbor::bounded::decode::construction::reclamation::PeekSlot<'_, Self, Self::State>,
                ) -> u64 {
                    dcbor::bounded::decode::construction::in_place::enumeration::remaining::<Self, #a>(slot)
                }
            }
        };
    }
}
