//! The symbolic surface every refinement of dCBOR text shares: a type
//! transparent over its `String` whose `new` checks the type's rule
//! ([`crate::StabilizedText`], [`crate::AsciiText`]). One definition, so the
//! accessors, conversions and encoding of every refinement are the same
//! code; each type states only its rule and its construction.

/// The accessors, the conversions from `String` and `CBOR` and into `CBOR`,
/// and the bounded encoding of `$type`, a refinement transparent over its
/// `String` with `fn new(impl Into<String>) -> Result<Self>` checking its
/// rule.
macro_rules! checked_text {
    ($type:ident) => {
        impl $type {
            /// The text.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// The text, taken.
            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl TryFrom<String> for $type {
            type Error = $crate::Error;

            fn try_from(text: String) -> $crate::Result<Self> {
                Self::new(text)
            }
        }

        impl From<$type> for $crate::CBOR {
            fn from(text: $type) -> Self {
                $crate::CBOR::from(text.0)
            }
        }

        /// A CBOR text, accepted as dCBOR accepts it (NFC), then refused by
        /// the type's rule (its `new`); any other value is
        /// [`crate::Error::WrongType`].
        impl TryFrom<$crate::CBOR> for $type {
            type Error = $crate::Error;

            fn try_from(cbor: $crate::CBOR) -> $crate::Result<Self> {
                match cbor.into_case() {
                    $crate::CBORCase::Text(text) => Self::new(text),
                    _ => Err($crate::Error::WrongType),
                }
            }
        }

        /// Bounded encoding: the text, which the value's construction
        /// already proved to keep the type's rule.
        impl $crate::bounded::encoding::Schema for $type {
            fn instruction(&self, index: usize) -> $crate::bounded::encoding::Instruction<'_> {
                $crate::bounded::encoding::Schema::instruction(self.0.as_str(), index)
            }
        }
    };
}

pub(crate) use checked_text;
