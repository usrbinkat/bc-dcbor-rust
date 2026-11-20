//! The Kani harnesses' one stand-in for a caller's policy: a budget that
//! counts every admission it is asked for and admits it, or, while
//! refusing or at its scheduled attempt, refuses it, admitting nothing; and
//! an allocator that counts every request and its bytes and grants it, or,
//! at its scheduled request, refuses it, granting nothing, counting what is
//! live and held at most. It records nothing else. One definition, shared
//! by every harness that drives an operation through [`Budget`] or
//! [`Allocator`]. Compiled only under `cfg(kani)`, whose build links `std`.

use std::cell::Cell;
use std::rc::Rc;

use super::decode::{Options, TextPolicy};
use super::{
    Allocator, Budget, Effect, Hold, Identity, Owner, Performer, Releasing, ResourceBound,
    WriteWork, boundary,
};

/// Select a bound by enumerating every length through `most`. Each unrolled
/// iteration calls the production bound with its concrete length. An absent
/// case fails the harness rather than supplying a default bound.
pub(crate) fn bound_at(
    length: usize,
    most: usize,
    bound: impl Fn(u64) -> ResourceBound,
) -> ResourceBound {
    let mut selected = None;
    let mut size = 0;
    while size <= most {
        if size == length {
            selected = Some(bound(size as u64));
        }
        size += 1;
    }
    selected.expect("every length of the domain is enumerated")
}

/// Select a decode bound over every length, nesting limit and both text
/// policies. The caller supplies the production bound and its proof-domain
/// limits; no bound arithmetic is reproduced here.
pub(crate) fn decode_bound_at(
    length: usize,
    options: Options,
    input: usize,
    nesting: usize,
    bound: impl Fn(u64, Options) -> ResourceBound,
) -> ResourceBound {
    bound_at(length, input, |size| {
        let mut selected = None;
        let mut depth = 0;
        while depth <= nesting {
            for text in [TextPolicy::Normalize, TextPolicy::QuickOnly] {
                let case = Options {
                    max_depth: depth,
                    text,
                };
                if case == options {
                    selected = Some(bound(size, case));
                }
            }
            depth += 1;
        }
        selected.expect("every nesting limit and text policy of the domain is enumerated")
    })
}

pub(crate) struct Counting {
    /// The work admitted.
    pub(crate) admitted: WriteWork,
    /// Every admission asked for, refused ones included.
    pub(crate) attempts: u64,
    /// Refuse every admission while set.
    pub(crate) refusing: bool,
    /// Refuse the admission whose attempt index (from 0, in [`Self::attempts`]
    /// order) equals it, admitting nothing.
    pub(crate) refuse_attempt: Option<u64>,
    /// Refuse the allocation request whose index (from 0, in
    /// [`Self::requests`] order) equals it, granting nothing.
    pub(crate) refuse_request: Option<u64>,
    /// Whether any admission or request was refused.
    pub(crate) refused: bool,
    /// Every allocation request attempted, refused ones included, and their
    /// bytes.
    pub(crate) requests: u64,
    pub(crate) requested: u64,
    /// The bytes of the requests granted alone: what a bound's `allocated`
    /// states ([`crate::bounded::ResourceBound::allocated`], "the sum of
    /// every allocation request" an operation is granted).
    pub(crate) granted: u64,
    /// The bytes the granted permits hold now, shared with each permit,
    /// whose drop releases its bytes.
    pub(crate) live: Rc<Cell<u64>>,
    /// The most bytes held at once.
    pub(crate) peak: u64,
}

impl Counting {
    pub(crate) fn new(refusing: bool) -> Self {
        Self {
            refusing,
            ..Self::scheduled(None, None)
        }
    }

    /// A policy that refuses only the admission at attempt `refuse_attempt`
    /// and the request at index `refuse_request`, each when given.
    pub(crate) fn scheduled(refuse_attempt: Option<u64>, refuse_request: Option<u64>) -> Self {
        Self {
            admitted: WriteWork::new(0, 0),
            attempts: 0,
            refusing: false,
            refuse_attempt,
            refuse_request,
            refused: false,
            requests: 0,
            requested: 0,
            granted: 0,
            live: Rc::new(Cell::new(0)),
            peak: 0,
        }
    }

    /// The bytes the granted permits hold now.
    pub(crate) fn live(&self) -> u64 {
        self.live.get()
    }
}

/// A permit of [`Counting`]: its bytes, released from the live count when
/// it drops. Two words, within `PERMIT_BYTES`.
pub(crate) struct Permit {
    live: Rc<Cell<u64>>,
    bytes: u64,
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.live.set(self.live.get() - self.bytes);
    }
}

impl Budget for Counting {
    type Refusal = ();

    fn traverse(&mut self, values: u64, bytes: u64) -> Result<(), ()> {
        let attempt = self.attempts;
        self.attempts += 1;
        if self.refusing || self.refuse_attempt == Some(attempt) {
            self.refused = true;
            return Err(());
        }
        self.admitted = WriteWork::new(self.admitted.values + values, self.admitted.bytes + bytes);
        Ok(())
    }

    fn boundary(&mut self, _: boundary::Boundary) {}

    type Origin = ();

    fn origin(&self) {}

    fn admitted(&mut self, _: WriteWork) {}

    fn identify(&mut self) -> Result<Identity, ()> {
        Ok(Identity::UNOBSERVED)
    }

    fn held(&mut self, _: WriteWork, _: Hold) {}

    fn effect(&mut self, _: Effect) {}

    fn owner(&mut self) -> Result<Owner, ()> {
        Ok(Owner::unobserved())
    }

    /// The proof model excludes owner and session pairing: no validation,
    /// and no evidence of pairing, acquisition identity or acquisition end.
    /// A recorded owner binds nothing.
    fn acquisition(&mut self, owner: &Owner) -> Result<super::Acquisition<()>, ()> {
        super::Acquisition::unobserved(owner).ok_or(())
    }

    fn validate_owner(&mut self, _: &Owner) -> Result<(), ()> {
        Ok(())
    }

    fn performer(&self) -> Performer {
        Performer::None
    }
}

impl Releasing for Counting {
    type Permit = Permit;

    fn permit_identity(_: &Permit) -> Identity {
        Identity::UNOBSERVED
    }

    /// The proof model records no record lifecycle.
    fn custody(_: &Permit, _: Identity, _: super::RecordStage) {}
}

impl Allocator for Counting {
    fn allocate(&mut self, bytes: u64) -> Result<Permit, ()> {
        let request = self.requests;
        self.requests += 1;
        self.requested += bytes;
        if self.refuse_request == Some(request) {
            self.refused = true;
            return Err(());
        }
        self.granted += bytes;
        let live = self.live.get() + bytes;
        self.live.set(live);
        self.peak = self.peak.max(live);
        Ok(Permit {
            live: self.live.clone(),
            bytes,
        })
    }
}
