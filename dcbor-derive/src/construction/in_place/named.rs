use super::super::super::*;

pub(super) fn expand(schema: &Schema<'_>, fields: &syn::FieldsNamed) -> TokenStream2 {
    expand_fields(schema, fields, false, true)
}

pub(super) fn expand_fields(
    schema: &Schema<'_>,
    fields: &syn::FieldsNamed,
    positional: bool,
    complete_type: bool,
) -> TokenStream2 {
    let name = schema.name();
    let a = schema.fresh("__DcborFieldAllocator");
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
    let (ig, _, wc) = generics.split_for_impl();
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
    let mut builds = Vec::new();
    let mut reclaims = Vec::new();
    let mut missing = Vec::new();
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
        let project = quote! {
            // SAFETY: compiler-provided aligned field projection, with no
            // reference to an uninitialized enclosing struct.
            let child = unsafe { core::ptr::NonNull::new_unchecked(
                core::ptr::addr_of_mut!((*place.as_ptr().cast::<Self>()).#ident)
                    .cast::<core::mem::MaybeUninit<#ty>>()
            ) };
        };
        builds.push(quote! { #slot => {
            #project
            unsafe { <#ty as dcbor::bounded::decode::construction::in_place::InPlace<#a>>::#build_method(
                document, index, child, cursor, allocator
            ) }
        } });
        reclaims.push(quote! { #slot => {
            #project
            unsafe { <#ty as dcbor::bounded::decode::construction::reclamation::Reclaim<#a>>::reclaim_step(
                child, cursor, allocator
            ) }
        } });
        missing.push(quote! { #slot => {
            #project
            unsafe { <#ty as dcbor::bounded::decode::construction::in_place::InPlace<#a>>::build_absent(
                child, cursor, allocator
            ) }
        } });
    }
    let callbacks = quote! {
        // SAFETY: schema validation guarantees unique keys; the sorted dense
        // indices select each actual field exactly once. Packed types are excluded.
        unsafe impl #ig dcbor::bounded::decode::construction::in_place::fields::Fields<#a> for #name #tg #wc {
            const COUNT: usize = #count;
            const TAG: Option<u64> = #tag;
            const POSITIONAL: bool = #positional;
            fn key(field: usize) -> u64 {
                const KEYS: &[u64] = &[#(#keys),*];
                KEYS[field]
            }
            fn optional(field: usize) -> bool {
                match field { #(#optional,)* _ => false }
            }
            unsafe fn missing_field(field: usize,
                place: core::ptr::NonNull<core::mem::MaybeUninit<Self>>,
                cursor: &mut dcbor::bounded::decode::construction::reclamation::Cursor,
                allocator: &mut #a,
            ) -> dcbor::bounded::decode::ConstructResult<dcbor::bounded::decode::construction::in_place::Built, #a> {
                match field { #(#missing,)* _ => Err(dcbor::bounded::BoundedError::PlanMismatch.into()) }
            }
            unsafe fn build_field(field: usize,
                document: &dcbor::bounded::decode::Document<'_, #a::Permit>, index: usize,
                place: core::ptr::NonNull<core::mem::MaybeUninit<Self>>,
                cursor: &mut dcbor::bounded::decode::construction::reclamation::Cursor,
                allocator: &mut #a,
            ) -> dcbor::bounded::decode::ConstructResult<dcbor::bounded::decode::construction::in_place::Built, #a> {
                match field { #(#builds,)* _ => Err(dcbor::bounded::BoundedError::PlanMismatch.into()) }
            }
            unsafe fn reclaim_field(field: usize,
                place: core::ptr::NonNull<core::mem::MaybeUninit<Self>>,
                cursor: &mut dcbor::bounded::decode::construction::reclamation::Cursor,
                allocator: &mut #a,
            ) -> dcbor::bounded::BoundedResult<dcbor::bounded::decode::construction::reclamation::Reclaimed, #a> {
                match field { #(#reclaims,)* _ => Err(dcbor::bounded::BoundedError::PlanMismatch) }
            }
        }
    };
    if !complete_type {
        return callbacks;
    }
    quote! {
        #callbacks
        // SAFETY: the shared engine retains each field cursor and only reports
        // Done after every required field has completed in its final destination.
        unsafe impl #ig dcbor::bounded::decode::construction::in_place::InPlace<#a> for #name #tg #wc {
            unsafe fn build_step(document: &dcbor::bounded::decode::Document<'_, #a::Permit>, index: usize,
                place: core::ptr::NonNull<core::mem::MaybeUninit<Self>>,
                cursor: &mut dcbor::bounded::decode::construction::reclamation::Cursor,
                allocator: &mut #a,
            ) -> dcbor::bounded::decode::ConstructResult<dcbor::bounded::decode::construction::in_place::Built, #a> {
                unsafe { dcbor::bounded::decode::construction::in_place::fields::build(document, index, place, cursor, allocator) }
            }
        }
        // SAFETY: no whole-value Drop; generated field callbacks retain the
        // same address and cursor used to initialize each field.
        unsafe impl #ig dcbor::bounded::decode::construction::reclamation::Reclaim<#a> for #name #tg #wc {
            const DISPATCH_DEPTH: usize = #depth;
            unsafe fn reclaim_step(place: core::ptr::NonNull<core::mem::MaybeUninit<Self>>,
                cursor: &mut dcbor::bounded::decode::construction::reclamation::Cursor,
                allocator: &mut #a,
            ) -> dcbor::bounded::BoundedResult<dcbor::bounded::decode::construction::reclamation::Reclaimed, #a> {
                unsafe { dcbor::bounded::decode::construction::in_place::fields::reclaim(place, cursor, allocator) }
            }
        }
    }
}
