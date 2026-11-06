//! The evidence gates' one implementation. The gate scripts
//! (`tests/*.sh`) launch the `gate` binary; every decision about what a run
//! produced, and whether it is evidence, is made here, once, with its own
//! tests and planted-defect controls.
//!
//! This crate depends on the record format (`dcbor_record`), the
//! model-bounds rows (`dcbor_model_bounds`), the census rows
//! (`dcbor_census`) and the library itself, for the boundary predicates a
//! run's inventory names (`dcbor::bounded::boundary`); and on no test
//! support: the support crate's heap observer is a global allocator, and a
//! gate linked with it would run, and measure, under test instrumentation.

pub mod cfgs;
pub mod costs;
pub mod domains;
pub mod inventory;
pub mod miri;
pub mod models;
pub mod mutation;
pub mod outcome;
pub mod process;
pub mod reach;
pub mod records;
pub mod rows;
