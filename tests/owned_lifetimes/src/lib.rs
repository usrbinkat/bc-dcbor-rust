//! Positive import control: compile-fail cases below must exercise lifetimes,
//! not unavailable types or missing trait implementations.
//! ```
//! use dcbor::{ByteString, bounded::{Limits, decode::construction::TypedValue}};
//! fn borrow<'a>(value: &'a TypedValue<'static, ByteString, String, Limits>) -> &'a String {
//!     value.value()
//! }
//! ```
//!
//! Output references cannot escape ownership.
//! ```compile_fail,E0515
//! use dcbor::{ByteString, bounded::{Limits, decode::construction::TypedValue}};
//! fn escape<'a>(value: TypedValue<'static, ByteString, String, Limits>) -> &'a String {
//!     value.value()
//! }
//! ```
//!
//! Retirement cannot happen while a value borrow is subsequently used.
//! ```compile_fail,E0505
//! use dcbor::{ByteString, bounded::{Limits, decode::construction::TypedValue}};
//! fn retire(value: TypedValue<'static, ByteString, String, Limits>) {
//!     let borrowed = value.value();
//!     drop(value);
//!     assert_eq!(borrowed, "still live");
//! }
//! ```
//!
//! Published values cannot be mutated through the read-only owning handle.
//! ```compile_fail,E0596
//! use dcbor::{ByteString, bounded::{Limits, decode::construction::TypedValue}};
//! fn mutate(value: TypedValue<'static, ByteString, String, Limits>) {
//!     value.value().push('x');
//! }
//! ```
