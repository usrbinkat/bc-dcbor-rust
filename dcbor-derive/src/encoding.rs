//! Constant-work instructions from the validated encoding schema: the one
//! bounded encoding of a derived type, prepared by the retained engine
//! whether driven in one call or in steps.
use super::*;

/// The instructions of the map of `fields` from instruction `start`, each
/// field read through `access`. Its head carries its count at once: the
/// required fields, and each optional field present, a fixed number of
/// presence checks announced first ([`Inspect`]) so they are admitted
/// before the head's instruction makes them. Then each field in the order
/// of its encoded key: unsigned integer keys' shortest encodings order as
/// the integers do.
///
/// [`Inspect`]: https://docs.rs/dcbor/latest/dcbor/bounded/encoding/enum.Instruction.html
fn map(fields: &MapFields, start: usize, access: impl Fn(&Ident) -> TokenStream2) -> TokenStream2 {
    let ordered = fields.in_key_order();
    let optional: Vec<&&MapField> = ordered.iter().filter(|field| field.optional).collect();
    let inspected = optional.len() as u64;
    let required = (ordered.len() - optional.len()) as u64;
    let (inspect, head) = if inspected == 0 {
        (quote!(), start)
    } else {
        (quote!(#start => __i::Inspect(#inspected),), start + 1)
    };
    let presences = optional.iter().map(|field| {
        let value = access(&field.ident);
        quote!(u64::from((#value).is_some()))
    });
    let arms = ordered.iter().enumerate().map(|(i, field)| {
        let index = head + 1 + i;
        let key = field.key;
        let value = access(&field.ident);
        let value = if field.optional {
            quote!((#value).as_ref().map(|v| v as &dyn dcbor::bounded::encoding::Schema))
        } else {
            quote!(Some(#value as &dyn dcbor::bounded::encoding::Schema))
        };
        quote!(#index => __i::Field(#key, #value),)
    });
    quote!(
        #inspect
        #head => __i::CountedMap(#required #(+ #presences)*),
        #(#arms)*
    )
}

pub(super) fn expand(schema: &Schema<'_>) -> TokenStream2 {
    let name = schema.name();
    let mut generics = schema.input.generics.clone();
    for ty in schema.field_types() {
        generics
            .make_where_clause()
            .predicates
            .push(syn::parse_quote!(#ty: dcbor::bounded::encoding::Schema));
    }
    let (ig, tg, wc) = generics.split_for_impl();
    let mut transfer = generics.clone();
    for ty in schema.field_types() {
        transfer
            .make_where_clause()
            .predicates
            .push(syn::parse_quote!(#ty: dcbor::bounded::encoding::TransferableSchema));
    }
    transfer
        .make_where_clause()
        .predicates
        .push(syn::parse_quote!(Self: Sync));
    let (transfer_ig, transfer_tg, transfer_wc) = transfer.split_for_impl();
    let body = match &schema.shape {
        Shape::Unit => quote!(match index {
            0 => __i::Head(__m::Simple, __a::Shortest(22)),
            _ => __i::End,
        }),
        Shape::Newtype(_) => quote!(match index {
            0 => __i::Child(&self.0),
            _ => __i::End,
        }),
        Shape::Map(fields) => {
            let arms = map(fields, 0, |f| quote!(&self.#f));
            quote!(match index { #arms _ => __i::End })
        }
        Shape::Enum(variants) => {
            let arms = variants.iter().map(|variant| {
                let v = &variant.ident;
                let disc = variant.discriminant;
                match &variant.kind {
                    VariantKind::Unit => quote!(Self::#v => match index { 0 => __i::Head(__m::Unsigned, __a::Shortest(#disc)), _ => __i::End }),
                    VariantKind::Tuple(count) => {
                        let fields = (0..*count).map(|i| {
                            let index = i + 2;
                            let pattern = (0..*count).map(|j| if i == j { quote!(__value) } else { quote!(_) });
                            quote!(#index => match self {
                                Self::#v(#(#pattern),*) => __i::Child(__value),
                                _ => unreachable!("variant selected by enclosing match"),
                            },)
                        });
                        let len = *count as u64 + 1;
                        quote!(Self::#v(..) => match index {
                            0 => __i::Head(__m::Array, __a::Shortest(#len)),
                            1 => __i::Head(__m::Unsigned, __a::Shortest(#disc)),
                            #(#fields)* _ => __i::End,
                        })
                    },
                    VariantKind::Named(fields) => {
                        let map = map(fields, 2, |f| {
                            quote!(match self {
                                Self::#v { #f: __value, .. } => __value,
                                _ => unreachable!("variant selected by enclosing match"),
                            })
                        });
                        quote!(Self::#v { .. } => match index {
                            0 => __i::Head(__m::Array, __a::Shortest(2)),
                            1 => __i::Head(__m::Unsigned, __a::Shortest(#disc)),
                            #map _ => __i::End,
                        })
                    },
                }
            });
            // The variant patterns bind nothing, so the match is on the
            // value itself: an enum of no variants is matched exhaustively
            // by no arms, where a reference to it is always inhabited.
            quote!(match *self { #(#arms),* })
        }
    };
    quote! {
        // SAFETY: generated instructions return only fields of self and
        // scalar heads. Each field carries the recursive transfer contract;
        // generated schemas create no entry cursors or external references.
        unsafe impl #transfer_ig dcbor::bounded::encoding::TransferableSchema
            for #name #transfer_tg #transfer_wc {}
        impl #ig dcbor::bounded::encoding::Schema for #name #tg #wc {
            fn instruction(&self, index: usize) -> dcbor::bounded::encoding::Instruction<'_> {
                use dcbor::bounded::{Argument as __a, MajorType as __m};
                use dcbor::bounded::encoding::Instruction as __i;
                #body
            }
        }
    }
}
