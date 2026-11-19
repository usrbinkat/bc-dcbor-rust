//! Case eligibility, independent of the representation a record measures.

/// An optional capability required to execute an evidence case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    Derive,
    Hashbrown,
}

impl Capability {
    pub const ALL: [Self; 2] = [Self::Derive, Self::Hashbrown];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Derive => "derive",
            Self::Hashbrown => "hashbrown",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|capability| capability.name() == name)
    }
}

/// The [`Capabilities`] of the crate this expands in, read from that crate's
/// own features: the one projection of every consumer's build, written once
/// here and evaluated where it expands, since this crate's features are not
/// the consumer's.
#[macro_export]
macro_rules! capabilities {
    () => {
        $crate::capabilities::Capabilities {
            derive: cfg!(feature = "derive"),
            hashbrown: cfg!(feature = "hashbrown"),
        }
    };
}

/// The capabilities of the consuming crate, passed explicitly because Cargo
/// features of this leaf crate are not the consumer's features.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub derive: bool,
    pub hashbrown: bool,
}

impl Capabilities {
    pub const fn enables(self, capability: Capability) -> bool {
        match capability {
            Capability::Derive => self.derive,
            Capability::Hashbrown => self.hashbrown,
        }
    }

    /// Refuse publication unless every optional case can be executed.
    pub fn require_complete(self) {
        let disabled: Vec<_> = Capability::ALL
            .into_iter()
            .filter(|&capability| !self.enables(capability))
            .map(Capability::name)
            .collect();
        assert!(
            disabled.is_empty(),
            "recording requires every gating feature; disabled: {disabled:?}"
        );
    }
}

/// A case's explicit eligibility, serialized even when unconditional.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Requirement {
    #[default]
    Always,
    Capability(Capability),
}

impl Requirement {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Always => "-",
            Self::Capability(capability) => capability.name(),
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "-" => Some(Self::Always),
            name => Capability::parse(name).map(Self::Capability),
        }
    }

    pub const fn eligible(self, available: Capabilities) -> bool {
        match self {
            Self::Always => true,
            Self::Capability(capability) => available.enables(capability),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eligibility_is_explicit_and_unknown_requirements_are_refused() {
        let minimal = Capabilities {
            derive: false,
            hashbrown: false,
        };
        assert!(Requirement::Always.eligible(minimal));
        for capability in Capability::ALL {
            let requirement = Requirement::Capability(capability);
            assert_eq!(Requirement::parse(requirement.name()), Some(requirement));
            assert!(!requirement.eligible(minimal));
        }
        for unknown in ["", "all", "std", "hashbrown,derive"] {
            assert_eq!(Requirement::parse(unknown), None);
        }
    }

    #[test]
    fn every_incomplete_recording_build_is_refused() {
        for available in [
            Capabilities {
                derive: false,
                hashbrown: false,
            },
            Capabilities {
                derive: true,
                hashbrown: false,
            },
            Capabilities {
                derive: false,
                hashbrown: true,
            },
        ] {
            assert!(std::panic::catch_unwind(|| available.require_complete()).is_err());
        }
        Capabilities {
            derive: true,
            hashbrown: true,
        }
        .require_complete();
    }
}
