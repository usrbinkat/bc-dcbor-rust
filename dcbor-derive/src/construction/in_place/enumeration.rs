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
    let (ig, _, wc) = generics.split_for_impl();
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
    let mut commits = Vec::new();
    for (slot, variant) in data.variants.iter().enumerate() {
        let helper = schema.fresh(&format!("__DcborVariant{slot}"));
        let union_field = Ident::new(&format!("v{slot}"), proc_macro2::Span::mixed_site());
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
        let projection = if c {
            quote! {
                // SAFETY: repr(C) places the tag before the payload union.
                let payload = unsafe { core::ptr::NonNull::new_unchecked(
                    core::ptr::addr_of_mut!((*place.as_ptr().cast::<#root_name #tg>()).payload)
                        .cast::<core::mem::MaybeUninit<#helper #tg>>()
                ) };
            }
        } else {
            quote! {
                // SAFETY: repr(u8) is a union of repr(C) variant structs,
                // each starting with the native tag and then its own fields.
                let payload = place.cast::<core::mem::MaybeUninit<#helper #tg>>();
            }
        };
        builds.push(quote! { #slot => {
            #projection
            unsafe { dcbor::bounded::decode::construction::in_place::fields::build::<#helper #tg, #a>(
                document, index, payload, cursor, allocator
            ) }
        } });
        reclaims.push(quote! { #slot => {
            #projection
            unsafe { dcbor::bounded::decode::construction::in_place::fields::reclaim::<#helper #tg, #a>(
                payload, cursor, allocator
            ) }
        } });
        commits.push(quote! { #slot => unsafe {
            place.as_ptr().cast::<#tag_name>().write(#tag_name::#native_variant);
        } });
    }
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
            // SAFETY: helpers mirror the explicitly declared enum layout;
            // no enum reference is created until the final native tag write.
            unsafe impl #ig dcbor::bounded::decode::construction::in_place::enumeration::Variants<#a> for #name #tg #wc {
                const COUNT: usize = #count;
                const TAG: Option<u64> = #tag;
                const TAG_BYTES: usize = core::mem::size_of::<#tag_name>();
                fn descriptor(variant: usize) -> (u64, u64) {
                    match variant { #(#descriptors,)* _ => unreachable!("validated variant index") }
                }
                unsafe fn build_variant(variant: usize,
                    document: &dcbor::bounded::decode::Document<'_, #a::Permit>, index: usize,
                    place: core::ptr::NonNull<core::mem::MaybeUninit<Self>>,
                    cursor: &mut dcbor::bounded::decode::construction::reclamation::Cursor, allocator: &mut #a,
                ) -> dcbor::bounded::decode::ConstructResult<dcbor::bounded::decode::construction::in_place::Built, #a> {
                    match variant { #(#builds,)* _ => Err(dcbor::bounded::BoundedError::PlanMismatch.into()) }
                }
                unsafe fn reclaim_variant(variant: usize,
                    place: core::ptr::NonNull<core::mem::MaybeUninit<Self>>,
                    cursor: &mut dcbor::bounded::decode::construction::reclamation::Cursor, allocator: &mut #a,
                ) -> dcbor::bounded::BoundedResult<dcbor::bounded::decode::construction::reclamation::Reclaimed, #a> {
                    match variant { #(#reclaims,)* _ => Err(dcbor::bounded::BoundedError::PlanMismatch) }
                }
                unsafe fn commit(variant: usize, place: core::ptr::NonNull<core::mem::MaybeUninit<Self>>) {
                    match variant { #(#commits,)* _ => unreachable!("validated variant index") }
                }
            }
            unsafe impl #ig dcbor::bounded::decode::construction::in_place::InPlace<#a> for #name #tg #wc {
                unsafe fn build_step(document: &dcbor::bounded::decode::Document<'_, #a::Permit>, index: usize,
                    place: core::ptr::NonNull<core::mem::MaybeUninit<Self>>,
                    cursor: &mut dcbor::bounded::decode::construction::reclamation::Cursor, allocator: &mut #a,
                ) -> dcbor::bounded::decode::ConstructResult<dcbor::bounded::decode::construction::in_place::Built, #a> {
                    unsafe { dcbor::bounded::decode::construction::in_place::enumeration::build(document, index, place, cursor, allocator) }
                }
            }
            unsafe impl #ig dcbor::bounded::decode::construction::reclamation::Reclaim<#a> for #name #tg #wc {
                const DISPATCH_DEPTH: usize = #depth;
                unsafe fn reclaim_step(place: core::ptr::NonNull<core::mem::MaybeUninit<Self>>,
                    cursor: &mut dcbor::bounded::decode::construction::reclamation::Cursor, allocator: &mut #a,
                ) -> dcbor::bounded::BoundedResult<dcbor::bounded::decode::construction::reclamation::Reclaimed, #a> {
                    unsafe { dcbor::bounded::decode::construction::in_place::enumeration::reclaim(place, cursor, allocator) }
                }
            }
        };
    }
}
