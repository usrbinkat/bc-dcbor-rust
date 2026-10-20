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
    let (build, reclaim) = if let Some(ty) = field {
        let projection = quote! {
            // SAFETY: compiler-provided field projection uses the actual
            // struct layout; packed representations are excluded above.
            let child = unsafe {
                core::ptr::NonNull::new_unchecked(
                    core::ptr::addr_of_mut!((*place.as_ptr().cast::<Self>()).0)
                        .cast::<core::mem::MaybeUninit<#ty>>()
                )
            };
        };
        (
            quote! {
                #projection
                // SAFETY: a one-field struct has exactly the child's initialization
                // and resource ownership; its cursor is retained without conversion.
                unsafe { <#ty as __i::InPlace<#a>>::build_step(document, index, child, cursor, allocator) }
            },
            quote! {
                #projection
                // SAFETY: the child retains the same destination and cursor used
                // during construction, including partial initialization on failure.
                unsafe { <#ty as __r::Reclaim<#a>>::reclaim_step(child, cursor, allocator) }
            },
        )
    } else {
        (
            quote! {
                dcbor::bounded::Budget::traverse(allocator, 1, 0)
                    .map_err(dcbor::bounded::BoundedError::Refused)?;
                if !matches!(
                    dcbor::bounded::decode::construction::node_at(document, index).map(|node| node.kind()),
                    Some(dcbor::bounded::decode::Kind::Null)
                ) { return Err(dcbor::bounded::decode::wrong_type()); }
                // SAFETY: a unit struct is zero-sized and has no fields to initialize.
                unsafe { place.as_ptr().write(core::mem::MaybeUninit::new(Self)) };
                cursor.state = 1;
                Ok(__i::Built::Done)
            },
            quote! {
                dcbor::bounded::Budget::traverse(allocator, 1, 0)
                    .map_err(dcbor::bounded::BoundedError::Refused)?;
                cursor.state = 0;
                Ok(__r::Reclaimed::Done)
            },
        )
    };
    let payload = if let Some(tag) = schema.tag {
        quote! {
            // SAFETY: compiler field projections preserve payload addresses.
            unsafe impl #ig dcbor::bounded::decode::construction::in_place::tagged::Payload<#a> for #name #tg #wc {
                const TAG: u64 = #tag;
                unsafe fn build_payload(
                    document: &dcbor::bounded::decode::Document<'_, #a::Permit>, index: usize,
                    place: core::ptr::NonNull<core::mem::MaybeUninit<Self>>,
                    cursor: &mut dcbor::bounded::decode::construction::reclamation::Cursor,
                    allocator: &mut #a,
                ) -> dcbor::bounded::decode::ConstructResult<dcbor::bounded::decode::construction::in_place::Built, #a> {
                    use dcbor::bounded::decode::construction::in_place as __i;
                    #build
                }
                unsafe fn reclaim_payload(
                    place: core::ptr::NonNull<core::mem::MaybeUninit<Self>>,
                    cursor: &mut dcbor::bounded::decode::construction::reclamation::Cursor,
                    allocator: &mut #a,
                ) -> dcbor::bounded::BoundedResult<dcbor::bounded::decode::construction::reclamation::Reclaimed, #a> {
                    use dcbor::bounded::decode::construction::reclamation as __r;
                    let _ = place;
                    #reclaim
                }
            }
        }
    } else {
        quote!()
    };
    let (build, reclaim) = if schema.tag.is_some() {
        (
            quote!(unsafe { __i::tagged::build::<Self, #a>(document, index, place, cursor, allocator) }),
            quote!(unsafe { dcbor::bounded::decode::construction::in_place::tagged::reclaim::<Self, #a>(place, cursor, allocator) }),
        )
    } else {
        (
            build,
            quote! {
                use dcbor::bounded::decode::construction::reclamation as __r;
                #reclaim
            },
        )
    };
    quote! {
        #payload
        // SAFETY: the generated projection preserves the final address and
        // delegates initialization to the field's mandatory in-place contract.
        unsafe impl #ig dcbor::bounded::decode::construction::in_place::InPlace<#a> for #name #tg #wc {
            unsafe fn build_step(
                document: &dcbor::bounded::decode::Document<'_, #a::Permit>, index: usize,
                place: core::ptr::NonNull<core::mem::MaybeUninit<Self>>,
                cursor: &mut dcbor::bounded::decode::construction::reclamation::Cursor,
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
            unsafe fn reclaim_step(
                place: core::ptr::NonNull<core::mem::MaybeUninit<Self>>,
                cursor: &mut dcbor::bounded::decode::construction::reclamation::Cursor,
                allocator: &mut #a,
            ) -> dcbor::bounded::BoundedResult<dcbor::bounded::decode::construction::reclamation::Reclaimed, #a> {
                let _ = place;
                #reclaim
            }
        }
    }
}
