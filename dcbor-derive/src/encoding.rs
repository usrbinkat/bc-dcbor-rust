//! Constant-work field instructions from the validated encoding schema.
use super::*;

fn map(fields: &MapFields, start: usize, access: impl Fn(&Ident) -> TokenStream2) -> TokenStream2 {
    let arms = fields
        .in_key_order()
        .into_iter()
        .enumerate()
        .map(|(i, field)| {
            let index = start + 1 + i;
            let key = field.key;
            let value = access(&field.ident);
            let value = if field.optional {
                quote!((#value).as_ref().map(|v| v as &dyn dcbor::bounded::encoding::Schema))
            } else {
                quote!(Some(#value as &dyn dcbor::bounded::encoding::Schema))
            };
            quote!(#index => __i::Field(#key, #value),)
        });
    quote!(#start => __i::Map, #(#arms)*)
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
            quote!(match self { #(#arms),* })
        }
    };
    quote! {
        impl #ig dcbor::bounded::encoding::Schema for #name #tg #wc {
            fn instruction(&self, index: usize) -> dcbor::bounded::encoding::Instruction<'_> {
                use dcbor::bounded::{Argument as __a, MajorType as __m};
                use dcbor::bounded::encoding::Instruction as __i;
                #body
            }
        }
    }
}
