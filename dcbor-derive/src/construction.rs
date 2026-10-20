//! Stable typed construction generated from the validated representation.
use super::*;
mod in_place;

pub(super) fn expand(schema: &Schema<'_>) -> TokenStream2 {
    let implementation = in_place::expand(schema);
    let name = schema.name();
    let (ig, tg, wc) = schema.input.generics.split_for_impl();
    quote! {
        #implementation
        // Field-by-field reclamation must not silently bypass a user Drop impl.
        // This guard applies independently of any allocator or field binding.
        const _: () = {
            trait __DcborMustNotImplDrop {}
            #[allow(drop_bounds)]
            impl<__T: core::ops::Drop> __DcborMustNotImplDrop for __T {}
            impl #ig __DcborMustNotImplDrop for #name #tg #wc {}
        };
    }
}
