//! Canonical map preparation uses the shared schema traversal engine.
use super::*;
pub(super) mod order;
pub use order::{OrderPhase, OrderPosition};

/// Compatibility name for the shared preparation engine. No child preparation
/// arenas or second payload assembly are introduced by this entry point.
pub type MapPreparation<'a, P> = Preparation<'a, P>;
pub type MapPosition = Position;
