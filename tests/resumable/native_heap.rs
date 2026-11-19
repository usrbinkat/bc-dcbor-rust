//! Physical heap tests over the shared observer: every real allocation of a
//! retained decode, normalization and storage growth can fail, and failure,
//! retirement and drain release physical storage and reservations exactly
//! without allocating.
use super::bindings::text_encoder;
use super::harness::*;
use super::heap::Observation;
use super::support::{
    self, Fault, Finding, PolicyId, RecordedRun, Retirement, Stopped, allowed, physical_matrix,
    pipeline::Unwitnessed, refusal_matrix, rigor::rigor,
};
use dcbor::bounded::decode::construction::{
    DecodeOwner,
    in_place::{StableOption, Transferable},
};
use dcbor::bounded::decode::{DecodeError, Options};
use dcbor::bounded::{
    BoundedError, Credits, Custodial, Failure, Family, Reservation, Step, WriteWork,
};

/// After cleanup: no physical request since `calls`, nothing observed live,
/// every request admitted, and complete bookkeeping.
fn cleaned(observer: &Observation, calls: usize) {
    let stats = observer.snapshot();
    assert_eq!(stats.calls, calls, "cleanup allocated");
    assert_eq!(stats.live, 0);
    assert_eq!(stats.unadmitted, 0);
    assert!(!stats.overflow);
}

/// Every physical allocation of decoding `wire` as `T`, failed in turn. The
/// baseline publishes a value `check` accepts, within its reservations;
/// retirement and drain are observed and allocate nothing. Every failure is an
/// allocation error whose cleanup allocates nothing and recovers every byte
/// and reservation.
fn allocation_matrix<T: Transferable<Limits> + 'static>(wire: &[u8], check: impl Fn(&T)) {
    let name = format!("decode physically of {}", core::any::type_name::<T>());
    let options = Options::normalizing(8);
    physical_matrix(&name, |failure| {
        suite(|run, policy| {
            let observer = Observation::begin(failure);
            observer.stop();
            // The scope and its input are setup, unwitnessed; the decode, its
            // retirement and the drain run in armed windows of `observer`.
            let calls = run.holding(
                DecodeOwner::new(),
                Retirement::Scope,
                &Unwitnessed,
                |owner| {
                    owner.initialize(policy)?;
                    let decoded = owner.decoder::<_, T, _, _>(
                        policy,
                        support::Borrowing(wire),
                        options,
                        &observer,
                        |decoding| {
                            decoding.drive(
                                policy,
                                support::borrowed_decode_turns::<T>(wire.len(), options),
                                Retirement::Published,
                                |value| {
                                    check(value.value().value());
                                    let published = observer.snapshot();
                                    value.with_policy(policy, |_, m| {
                                        assert!(published.calls > 0 && !published.overflow);
                                        assert_eq!(published.unadmitted, 0);
                                        assert!(published.live <= m.live_bytes() as usize);
                                        assert!(published.peak <= m.peak_bytes() as usize);
                                    });
                                    published
                                },
                            )
                        },
                    )?;
                    // The published value, then the failed decoder, retired
                    // inside the armed window as their holdings exited.
                    let calls = match (failure, decoded) {
                        (None, Ok(published)) => {
                            let queued = observer.snapshot();
                            assert_eq!(
                                (queued.calls, queued.live),
                                (published.calls, published.live),
                                "retirement allocated or released synchronously"
                            );
                            published.calls
                        }
                        (
                            Some(_),
                            Err(Stopped::Operation(DecodeError::Resource(
                                BoundedError::Allocation { .. },
                            ))),
                        ) => {
                            let failed = observer.snapshot();
                            assert_eq!(failed.denied, 1, "the failed allocation never intercepted");
                            failed.calls
                        }
                        (Some(index), Ok(_)) => {
                            return Err(Finding::Defect(format!(
                                "allocation {index} did not fail the decode"
                            )));
                        }
                        (_, Err(stop)) => return Err(Finding::from(stop)),
                    };
                    owner.witnessed(&observer, |owner| {
                        owner.drain(policy)?;
                        cleaned(&observer, calls);
                        Ok::<_, Finding>(calls)
                    })
                },
            )?;
            Ok(run.with_policy(policy, |m| {
                assert_eq!(m.live_bytes(), 0);
                (calls, m.reached())
            }))
        })
    });
}

#[test]
fn physical_observer_detects_an_unreported_allocation() {
    let observer = Observation::begin(None);
    let bytes = std::hint::black_box(vec![7u8; 1024]);
    observer.stop();
    let stats = observer.snapshot();
    assert!(stats.calls > 0 && stats.unadmitted > 0);
    assert!(stats.live >= 1024);
    drop(bytes);
    assert_eq!(observer.snapshot().live, 0);
}

#[test]
fn every_real_decoder_allocation_failure_releases_physical_and_permit_ownership() {
    let text = "q\u{301}\u{1f600}".repeat(64);
    allocation_matrix::<String>(&text_wire(&text), |value| assert_eq!(*value, text));
}

#[test]
fn stable_optional_acquisitions_fail_physically_and_cleanup_never_allocates() {
    allocation_matrix::<StableOption<String, Limits>>(&[0x63, b'q', 0xcc, 0x81], |value| {
        assert_eq!(value.as_ref().map(String::as_str), Some("q\u{301}"));
    });
}

/// A typed decode of a literal vector of texts under the fault matrix, its
/// heap observed: constructing the decoder allocates nothing; wherever a
/// refusal cancels it (each turn begins with an admission, so every turn
/// boundary is among them), dropping it there allocates nothing and
/// releases only granted acquisition blocks synchronously. Published records
/// stay queued until the drain, which allocates nothing and releases
/// everything; a resumed decode publishes the literal value.
#[test]
fn every_public_decoder_cancellation_transfers_custody_without_allocating() {
    // Literal ["q\u{301}", "b"] crosses parser, normalizer, document transfer,
    // vector child construction and pre-publication cleanup boundaries.
    let wire = [0x82, 0x63, b'q', 0xcc, 0x81, 0x61, b'b'];
    refusal_matrix(
        "typed decode of a text vector, observed",
        rigor(),
        |fault: Fault| {
            suite(|run, setup| {
                let observer = Observation::begin(None);
                observer.stop();
                // The decode alone is under test, under a share of the
                // policy with a trace of its own; the scope and its input are
                // setup, unwitnessed, under the policy itself.
                let decoding = run.shared_policy(setup);
                let options = Options::normalizing(8);
                // The decoder's state after its last turn, read while it is
                // still held: its permits with their bytes, the policy's
                // live bytes, and the observer's figures.
                let mut last: Option<(PermitBytes, u64, super::heap::Stats)> = None;
                let calls = run.holding(
                    DecodeOwner::new(),
                    Retirement::Scope,
                    &Unwitnessed,
                    |owner| {
                        owner.initialize(setup)?;
                        owner.decoder::<_, Vec<String>, _, _>(
                            setup,
                            support::Borrowing(&wire),
                            options,
                            &observer,
                            |decoder| {
                                assert_eq!(observer.snapshot().calls, 0, "constructors allocated");
                                decoder.drive_faulted(
                                    decoding,
                                    typed_turns::<Vec<String>>(wire.len()),
                                    Retirement::Published,
                                    fault,
                                    |m, decoder| {
                                        let mut bytes = PermitBytes { bytes: Vec::new() };
                                        assert_eq!(
                                            decoder.observe_custody(&mut bytes),
                                            dcbor::bounded::PermitsObserved::Complete,
                                        );
                                        let permits =
                                            support::collect(|sink| decoder.observe_custody(sink))
                                                .expect("complete decoder custody")
                                                .iter()
                                                .map(|group| group.permits.len())
                                                .sum::<usize>();
                                        assert_eq!(bytes.bytes.len(), permits);
                                        last = Some((bytes, m.live_bytes(), observer.snapshot()));
                                    },
                                    |value| {
                                        assert_eq!(value.value().value(), &["q\u{301}", "b"]);
                                    },
                                )
                            },
                        )??;
                        // The decoder, exhausted or cancelled, and any
                        // published value retired inside the armed window as
                        // their holdings exited: what was released is exactly
                        // the decoder's custody absent from the scope queue,
                        // and nothing was allocated.
                        let (permit_bytes, held, before) =
                            last.take().expect("the decode took a turn");
                        let retired = observer.snapshot();
                        let queued_custody =
                            support::collect(|sink| owner.value().observe_custody(sink))
                                .expect("complete queued custody");
                        let released = permit_bytes
                            .bytes
                            .iter()
                            .filter(|(id, _)| {
                                !queued_custody.iter().any(|group| {
                                    group.permits.iter().any(|reported| reported.permit == *id)
                                })
                            })
                            .try_fold(0u64, |sum, (_, bytes)| sum.checked_add(*bytes))
                            .expect("released bytes fit in u64");
                        assert_eq!(retired.calls, before.calls, "retirement allocated");
                        assert_eq!(
                            before.live.checked_sub(retired.live),
                            Some(usize::try_from(released).expect("physical bytes fit usize")),
                            "physical releases must match custody absent from the scope queue"
                        );
                        owner.with_policy(decoding, |_, m| {
                            assert_eq!(held.checked_sub(m.live_bytes()), Some(released));
                        });
                        let calls = owner.with_policy(decoding, |_, m| support::RefusalRun::of(m));
                        owner.witnessed(&observer, |owner| {
                            owner.drain(setup)?;
                            cleaned(&observer, before.calls);
                            Ok::<_, Finding>(calls)
                        })
                    },
                )?;
                run.with_policy(setup, |m| assert_eq!(m.live_bytes(), 0));
                Ok(calls)
            })
        },
    );
}

/// Every permit a custody reports, with its bytes, whether a record block's
/// or not.
struct PermitBytes {
    bytes: Vec<(dcbor::bounded::Identity, u64)>,
}

impl dcbor::bounded::CustodySink<Reservation> for PermitBytes {
    fn begin(&mut self, _: Option<dcbor::bounded::Identity>) {}
    fn bound(&mut self, _: dcbor::bounded::Identity) {}
    fn held(&mut self, _: dcbor::bounded::Hold) {}
    fn permit(&mut self, permit: &Reservation, _: Option<dcbor::bounded::RecordStage>) {
        self.bytes.push((permit.identity(), permit.bytes()));
    }
    fn end(&mut self) {}
    /// Every permit the custody reports, shared custody once: by the first
    /// holder, while its permit is not yet recorded.
    fn shared(&mut self, custody: dcbor::bounded::Identity) -> bool {
        !self.bytes.iter().any(|(id, _)| *id == custody)
    }
}

/// `holds`, or `finding` kept in `findings`: an oracle check of a witness
/// that must still drop what it holds and reach its run's finalization
/// before it reports ([`support::RecordedRun::defect`]).
fn check(findings: &mut Vec<Finding>, holds: bool, finding: impl FnOnce() -> String) {
    if !holds {
        findings.push(Finding::Defect(finding()));
    }
}

/// What a published encoding showed while it was held, as detached data: its
/// bytes the expected ones, its length, and the observed heap within the
/// policy's accounting at publication.
struct Published {
    expected: bool,
    len: u64,
    within: bool,
}

/// What [`encoded`] returns: the encoding's outcome, a publication read
/// while it was held or the encoding's own error, and the findings its
/// cleanup kept; or the stop that ended the witness.
type Encoded = Result<(Result<Published, BoundedError<LimitRefusal>>, Vec<Finding>), Finding>;

/// Encode `source` under `policy` of `run`, the encoder held by the run
/// under `observer`, every turn in an armed window, the run's recording
/// storage made before it (the run's observed policy). A publication is
/// read inside its own holding ([`Published`]) and retired there. The
/// encoding's own error is its outcome, kept typed; any other stop of its
/// drive ends the witness as the run's finding. A terminal failure is
/// followed by the encoder's own cleanup in the same holding, also
/// observed: its stop is kept as a finding (a cleanup that published, failed
/// or exceeded its bound), never asserted here, except a lost recording,
/// which no later reading of the run's history may follow and which ends
/// the witness. The encoder retires at each end as its type declares
/// ([`super::support::Terminal`]).
fn encoded(
    run: &mut RecordedRun,
    policy: PolicyId,
    source: &str,
    expected: &[u8],
    observer: &Observation,
) -> Encoded {
    observer.stop();
    let bound = normalize_turns(source);
    run.holding(
        text_encoder(source),
        Retirement::Released,
        observer,
        |encoder| {
            let mut findings = Vec::new();
            let result = match encoder.drive(policy, bound, Retirement::Released, |output| {
                let within = output.with_policy(policy, |_, m| {
                    let measured = observer.snapshot();
                    measured.live <= m.live_bytes() as usize
                        && measured.peak <= m.peak_bytes() as usize
                });
                Published {
                    expected: output.value().as_ref() == expected,
                    len: output.value().as_ref().len() as u64,
                    within,
                }
            }) {
                Ok(published) => Ok(published),
                Err(Stopped::Operation(error)) => Err(error),
                Err(stop) => return Err(stop.into()),
            };
            if result.is_err() {
                match encoder.finish(policy, bound, Retirement::Released) {
                    Ok(()) => {}
                    Err(lost @ Stopped::Lost(..)) => return Err(lost.into()),
                    Err(stop) => findings.push(stop.into()),
                }
            }
            Ok((result, findings))
        },
    )
}

/// The unfailed encoding's admitted calls, the index of its output's
/// allocation (its last), the release unit admitted just before it, and its
/// physical request count: the oracle every failed run is held to.
struct TextOracle {
    calls: Vec<dcbor::bounded::Call>,
    output: usize,
    release: dcbor::bounded::Call,
    requests: usize,
}

/// Every physical request of a text encoding, the output's included, failed
/// in turn: each failure is an allocation error whose cleanup recovers every
/// byte and reservation. A failed run takes the unfailed run's path to its
/// failed request (its calls through its last allocation are the oracle's
/// prefix), and no allocation follows the failure (a retry would admit
/// another, out of the oracle's order). When the output's request fails, its
/// release, the unit admitted before its allocation, is admitted exactly as
/// often as before that allocation in the oracle, and never after: a failed
/// output reservation is terminal and goes to cleanup
/// (`TextEncoder::step`), never back to `ReleaseOutput`. The calls are the
/// recorded run's (its observed policy's, its recording storage made before
/// the window, so recording allocates nothing observed).
///
/// Each run is a recorded run of its own ([`support::recorded_run`]), and
/// nothing it checks ends it early: the encoder's cleanup reports its
/// stop as data ([`encoded`], [`support::Holding::finish`]), every oracle
/// check is kept as a finding ([`check`]), the output and the encoder are
/// retired by their holdings, and only then is each finding recorded as the
/// run's defect ([`support::RecordedRun::defect`]), which the runner reports
/// beside what the recording finished as. Planted control
/// `tests/data/controls/text-allocation-retried.patch` (a failed output
/// reservation sent back to `ReleaseOutput`) makes the failed encoding's
/// cleanup publish its retried output: the cleanup's stop, "the operation
/// published where its schedule admits none", is reported with the
/// recording's own result, the output held and retired by the holding the
/// stop detached it into, as its evidence.
#[test]
fn every_real_normalization_and_output_allocation_can_fail_without_leaking() {
    use dcbor::bounded::Call;
    let source = format!("q{}", "\u{301}\u{316}".repeat(64));
    let expected = text_wire(&format!(
        "q{}{}",
        "\u{316}".repeat(64),
        "\u{301}".repeat(64)
    ));
    let oracle: std::cell::RefCell<Option<TextOracle>> = std::cell::RefCell::new(None);
    let last_allocation = |calls: &[Call]| {
        calls
            .iter()
            .rposition(|call| matches!(call, Call::Allocate(_)))
    };
    physical_matrix("text encoding physically", |failure| {
        support::recorded_run(|run| {
            let policy = run.observed_policy(POOL);
            let observer = Observation::begin(failure);
            let (output, mut findings) = encoded(run, policy, &source, &expected, &observer)?;
            let (requests, reached, findings) = run.with_policy(policy, |pool| {
                let measured = observer.snapshot();
                check(&mut findings, !measured.overflow, || {
                    "the physical observation overflowed".to_owned()
                });
                check(&mut findings, measured.unadmitted == 0, || {
                    format!(
                        "{} physical requests were not admitted",
                        measured.unadmitted
                    )
                });
                let calls = pool.calls();
                let calls = calls.as_slice();
                match (failure, &output) {
                    (None, Ok(published)) => {
                        check(&mut findings, published.expected, || {
                            "the baseline encoded other bytes".to_owned()
                        });
                        check(&mut findings, measured.calls > 0, || {
                            "the baseline made no physical request".to_owned()
                        });
                        check(&mut findings, published.within, || {
                            "the physical heap exceeded the policy's accounting".to_owned()
                        });
                        match last_allocation(calls) {
                            Some(at)
                                if at > 0
                                    && calls[at] == Call::Allocate(published.len)
                                    && matches!(calls[at - 1], Call::Work { .. }) =>
                            {
                                *oracle.borrow_mut() = Some(TextOracle {
                                    calls: calls.to_vec(),
                                    output: at,
                                    release: calls[at - 1],
                                    requests: measured.calls,
                                });
                            }
                            at => findings.push(Finding::Defect(format!(
                                "the baseline's last allocation, at {at:?}, is not its output's \
                                 after its release"
                            ))),
                        }
                    }
                    (None, Err(error)) => {
                        findings.push(Finding::Defect(format!(
                            "the baseline encoding failed: {error:?}"
                        )));
                    }
                    (Some(index), output) => {
                        check(&mut findings, measured.denied == 1, || {
                            format!("physical failure {index} was not exercised")
                        });
                        check(
                            &mut findings,
                            matches!(output, Err(BoundedError::Allocation { .. })),
                            || format!("physical failure {index} did not fail the encoding"),
                        );
                        let oracle = oracle.borrow();
                        let oracle = oracle.as_ref().expect("the baseline runs first");
                        match last_allocation(calls) {
                            None => findings.push(Finding::Defect(format!(
                                "failure {index}: no failed request was admitted"
                            ))),
                            Some(last) => {
                                check(
                                    &mut findings,
                                    calls.get(..=last) == oracle.calls.get(..=last),
                                    || {
                                        format!(
                                            "failure {index}: another path to the failed request"
                                        )
                                    },
                                );
                                if index == oracle.requests - 1 {
                                    check(&mut findings, last == oracle.output, || {
                                        "the output's request is not the last".to_owned()
                                    });
                                    let releases = |calls: &[Call]| {
                                        calls.iter().filter(|call| **call == oracle.release).count()
                                    };
                                    check(
                                        &mut findings,
                                        releases(&calls[..=last])
                                            == releases(&oracle.calls[..=oracle.output]),
                                        || {
                                            "the output's release was not admitted exactly as \
                                             before its allocation"
                                                .to_owned()
                                        },
                                    );
                                    let after = &calls[last + 1..];
                                    check(&mut findings, releases(after) == 0, || {
                                        format!(
                                            "the output's release was admitted again after the \
                                             failure: {after:?}"
                                        )
                                    });
                                }
                            }
                        }
                    }
                }
                check(&mut findings, observer.snapshot().live == 0, || {
                    "observed physical storage outlived the encoding".to_owned()
                });
                check(&mut findings, pool.live_bytes() == 0, || {
                    "the policy's storage outlived the encoding".to_owned()
                });
                Ok::<_, Finding>((measured.calls, pool.reached(), findings))
            })?;
            for finding in findings {
                run.defect(finding);
            }
            Ok((requests, reached))
        })
    });
}

#[test]
fn physical_growth_failure_preserves_old_bytes_and_their_reservation() {
    use dcbor::bounded::Owned;
    suite(|run, policy| {
        // The custody holding the vector: its growths are its acquisitions.
        let owner = run.with_policy(policy, |m| m.owner().expect("a recorded owner"));
        let observer = Observation::begin(None);
        observer.stop();
        run.holding(
            PublishedArena {
                storage: Owned::new(),
                owner: Some(owner.id()),
            },
            support::Retirement::Released,
            &observer,
            |bytes| {
                bytes.with_policy(policy, |bytes, m| {
                    observer
                        .window(|| bytes.storage.push(7u8, m, &owner))
                        .unwrap();
                });
                let old = observer.snapshot().live;
                let held = bytes.with_policy(policy, |_, m| m.live_bytes());
                assert!(old > 0 && old <= held as usize);
                // Re-arm the same observation, retaining the old allocation registry.
                observer.fail_next();
                observer.stop();
                let result = bytes.with_policy(policy, |bytes, m| {
                    observer.window(|| bytes.storage.reserve(4096, m, &owner))
                });
                assert!(matches!(result, Err(BoundedError::Allocation { .. })));
                assert_eq!(observer.snapshot().denied, 1);
                assert_eq!(bytes.value().storage.as_slice(), &[7]);
                assert_eq!(observer.snapshot().live, old);
                bytes.with_policy(policy, |_, m| assert_eq!(m.live_bytes(), held));
            },
        );
        assert_eq!(observer.snapshot().live, 0);
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok(())
    });
}

/// A dropped `Owned` frees its vector's buffer before it releases the permit
/// accounting for it, witnessed physically: its permit, when released, reads
/// the observation and requires every byte observed allocated to be freed
/// already. Three elements take one allocation of four, so the one permit
/// is never replaced by a growth, which releases a permit beside the grown
/// allocation by design. Every physical request was admitted and the
/// observation is complete. Reordering `Owned`'s fields so the permit drops
/// first fails the permit's own check.
#[test]
fn a_dropped_owned_frees_its_buffer_before_releasing_its_permit() {
    use dcbor::bounded::boundary::Boundary;
    use dcbor::bounded::{
        Allocator, Budget, Effect, Hold, Identity, Owned, Owner, Performer, Releasing,
    };
    /// A view of this thread's observer that is never dropped, so reading it
    /// never disarms the observation in progress, as dropping an
    /// `Observation` does.
    static VIEW: Observation = Observation;
    /// A permit requiring, when released, the observed heap to hold nothing.
    struct Checked {
        /// Held for its drop alone: the reservation released after the
        /// check.
        _reservation: Reservation,
    }
    impl Drop for Checked {
        fn drop(&mut self) {
            let live = VIEW.snapshot().live;
            assert_eq!(
                live, 0,
                "the permit was released while {live} observed bytes were still allocated"
            );
        }
    }
    /// The suite's recorded policy, granting [`Checked`] permits: every
    /// other method forwards to it, so its credit family, owners and
    /// identities are the recorded run's own.
    struct Policy<'m>(&'m mut Limits);
    impl Budget for Policy<'_> {
        type Refusal = LimitRefusal;
        #[expect(
            clippy::disallowed_methods,
            reason = "a third-party policy forwards an admission already made through the route"
        )]
        fn traverse(&mut self, values: u64, bytes: u64) -> Result<(), LimitRefusal> {
            self.0.traverse(values, bytes)
        }
        fn boundary(&mut self, boundary: Boundary) {
            self.0.boundary(boundary);
        }
        type Origin = Family;
        fn origin(&self) -> Family {
            self.0.origin()
        }
        fn admitted(&mut self, work: WriteWork) {
            self.0.admitted(work);
        }
        fn identify(&mut self) -> Result<Identity, LimitRefusal> {
            self.0.identify()
        }
        fn held(&mut self, work: WriteWork, hold: Hold) {
            self.0.held(work, hold);
        }
        fn effect(&mut self, effect: Effect) {
            self.0.effect(effect);
        }
        fn owner(&mut self) -> Result<Owner, LimitRefusal> {
            self.0.owner()
        }
        fn acquisition(
            &mut self,
            owner: &Owner,
        ) -> Result<dcbor::bounded::Acquisition<Family>, LimitRefusal> {
            self.0.acquisition(owner)
        }
        fn validate_owner(&mut self, owner: &Owner) -> Result<(), LimitRefusal> {
            self.0.validate_owner(owner)
        }
        fn performer(&self) -> Performer {
            self.0.performer()
        }
    }
    impl Releasing for Policy<'_> {
        type Permit = Checked;
        fn permit_identity(permit: &Checked) -> Identity {
            Limits::permit_identity(&permit._reservation)
        }
        fn custody(permit: &Checked, owner: Identity, stage: dcbor::bounded::RecordStage) {
            Limits::custody(&permit._reservation, owner, stage)
        }
    }
    impl Allocator for Policy<'_> {
        fn allocate(&mut self, bytes: u64) -> Result<Checked, LimitRefusal> {
            self.0.allocate(bytes).map(|reservation| Checked {
                _reservation: reservation,
            })
        }
    }
    struct CheckedCustody {
        storage: Owned<u64, Checked>,
        owner: Identity,
    }
    impl Custodial<Reservation> for CheckedCustody {
        fn observe_custody(
            &mut self,
            sink: &mut dyn dcbor::bounded::CustodySink<Reservation>,
        ) -> dcbor::bounded::PermitsObserved {
            sink.begin(Some(self.owner));
            if let Some(permit) = self.storage.permit() {
                sink.permit(&permit._reservation, None);
            }
            sink.end();
            dcbor::bounded::PermitsObserved::Complete
        }
    }
    suite(|run, policy| {
        let owner = run.with_policy(policy, |m| m.owner().expect("a recorded owner"));
        let observer = Observation::begin(None);
        observer.stop();
        run.holding(
            CheckedCustody {
                storage: Owned::new(),
                owner: owner.id(),
            },
            support::Retirement::Released,
            &observer,
            |owned| {
                owned.with_policy(policy, |owned, m| {
                    let mut policy = Policy(m);
                    for element in 0..3 {
                        observer
                            .window(|| owned.storage.push(element, &mut policy, &owner))
                            .unwrap();
                    }
                    assert_eq!(owned.storage.as_slice(), [0, 1, 2]);
                });
            },
        );
        let stats = observer.snapshot();
        assert!(!stats.overflow, "the observation is incomplete");
        assert_eq!(stats.calls, 1, "one physical allocation, the buffer");
        assert_eq!(stats.unadmitted, 0, "every physical request was admitted");
        assert_eq!(stats.live, 0, "the buffer was freed");
        run.with_policy(policy, |m| {
            assert_eq!(m.requests(), 1, "one permit, never replaced");
            assert_eq!(m.live_bytes(), 0, "and it was released");
        });
        Ok(())
    });
}

/// The credit oracle of one operation at a point of its run: the ledgers of
/// the policy instances that served it, summed, conserve its credit with
/// what its custody still holds ([`Credits::conserved_with`]). Every run here
/// is served by policies dedicated to its one operation, so their ledgers
/// hold that operation's events alone; a policy serving several operations
/// is read as a delta around each ([`Credits::checked_sub`]).
fn conserved(credits: Credits, held: Option<WriteWork>, at: &str) {
    if let Some(discrepancy) = unconserved(credits, held, at) {
        panic!("{discrepancy}");
    }
}

/// What [`conserved`] refuses, as detached data, or none: the one
/// conservation check, for a witness that must finish its run and its
/// recording before it reports.
fn unconserved(credits: Credits, held: Option<WriteWork>, at: &str) -> Option<String> {
    let Some(held) = held else {
        return Some(format!("{at}: the held credit does not fit in u64"));
    };
    // What the ledgers leave admitted and neither consumed nor forfeited:
    // the credit some custody must still report. `None` when the ledgers
    // closed more than they admitted.
    let unclosed = credits
        .consumed
        .checked_then(credits.forfeited)
        .and_then(|closed| {
            Some(WriteWork::new(
                credits.admitted.values.checked_sub(closed.values)?,
                credits.admitted.bytes.checked_sub(closed.bytes)?,
            ))
        });
    (credits.conserved_with(held) != Some(true)).then(|| {
        format!(
            "{at}: lost credit: the custody reports {held:?} held, the ledgers leave \
             {unclosed:?} neither consumed nor forfeited ({credits:?})"
        )
    })
}

/// The terminal oracle: conserved, and nothing held once the operation
/// completed or finished its cleanup.
fn settled(credits: Credits, held: Option<WriteWork>, at: &str) {
    if let Some(discrepancy) = unsettled(credits, held, at) {
        panic!("{discrepancy}");
    }
}

/// What [`settled`] refuses, as detached data, or none.
fn unsettled(credits: Credits, held: Option<WriteWork>, at: &str) -> Option<String> {
    unconserved(credits, held, at).or_else(|| {
        (held != Some(WriteWork::default())).then(|| format!("{at}: an obligation left held"))
    })
}

/// The text the credit tests encode: its decomposition grows both arenas
/// and its output is requested once.
fn credit_text() -> String {
    format!("q{}", "\u{301}\u{316}".repeat(64))
}

/// The text continuation's explicit cancellation entry, driven by the same
/// held cleanup schedule as terminal errors. It cannot resume production.
struct TextCleanup<'s>(dcbor::bounded::text_cursor::TextEncoder<'s, Reservation, Family>);

impl Custodial<Reservation> for TextCleanup<'_> {
    fn observe_custody(
        &mut self,
        sink: &mut dyn dcbor::bounded::CustodySink<Reservation>,
    ) -> dcbor::bounded::PermitsObserved {
        self.0.observe_custody(sink)
    }
}

dcbor_test_support::terminal!(Exhausted: ['s] TextCleanup<'s>);

impl dcbor::bounded::Resumable<Limits> for TextCleanup<'_> {
    type Output = ();
    type Error = BoundedError<LimitRefusal>;
    type Position = dcbor::bounded::text_cursor::Position;

    fn step(&mut self, policy: &mut Limits) -> Result<Step<()>, Self::Error> {
        self.0.reclaim_step(policy).map(|finished| {
            if finished {
                Step::Finished
            } else {
                Step::Progress
            }
        })
    }

    fn position(&mut self) -> Self::Position {
        self.0.position()
    }
}

/// A text encoding's credit, across every admission refused once, each
/// refused alone, and a cancellation at every call: conserved with its
/// custody's held credit after every turn, its releases held across a
/// refused request included, and settled once it publishes or finishes its
/// cleanup. Planted controls `tests/data/controls/credit-spend-dropped.patch`
/// and `credit-spend-twice.patch` must fail it.
///
/// Each fault's run is a recorded run of its own, the encoder and its output
/// held by the run: the first accounting discrepancy is kept where its
/// defect shows, every ordinary cleanup still runs (the encoding's own
/// cleanup stepped when cancelled, its output and itself retired by their
/// holdings), and the discrepancy is recorded as the run's defect
/// ([`support::RecordedRun::defect`]), reported beside what the recording
/// actually finished as. So credit-spend-dropped reports "lost credit" with
/// its recording's own result, never in place of it. Settlement is read
/// before any destruction can settle what the encoder keeps: after its last
/// turn while it is still held, or after its cleanup.
#[test]
fn text_encoding_credit_is_conserved_at_every_suspension_and_settled_at_its_end() {
    let source = credit_text();
    refusal_matrix("text encoding credit", rigor(), |fault| {
        support::recorded_run(|run| {
            let policy = run.observed_policy(POOL);
            let turns = normalize_turns(&source);
            let ledger = run.with_policy(policy, |m| m.share());
            let mut discrepancy = None;
            let mut last = None;
            let cancelled = run.holding(
                text_encoder(&source),
                Retirement::Released,
                &Unwitnessed,
                |encoder| {
                    let published = encoder.drive_faulted(
                        policy,
                        turns,
                        Retirement::Released,
                        fault,
                        |m, encoder| {
                            let held = encoder.held_credit();
                            if discrepancy.is_none() {
                                discrepancy = unconserved(m.credits(), held, "a turn");
                            }
                            last = Some((m.credits(), held));
                        },
                        |_| (),
                    )?;
                    if published.is_some() {
                        return Ok::<_, Finding>(None);
                    }
                    let calls = encoder.with_policy(policy, |_, m| support::RefusalRun::of(m));
                    encoder.transfer(TextCleanup, Retirement::Released, |cleanup| {
                        cleanup.finish_observed(policy, turns, Retirement::Released, |cleanup| {
                            last = Some((ledger.credits(), cleanup.0.held_credit()));
                        })
                    })?;
                    Ok(Some(calls))
                },
            )?;
            if discrepancy.is_none() {
                let (credits, held) = last.expect("the encoding took a turn");
                discrepancy = unsettled(credits, held, &format!("{fault:?}"));
            }
            let calls = match cancelled {
                Some(calls) => calls,
                None => run.with_policy(policy, |m| support::RefusalRun::of(m)),
            };
            if let Some(discrepancy) = discrepancy {
                run.defect(discrepancy);
            }
            Ok(calls)
        })
    });
}

/// A text encoding's credit after every physical failure, its cleanup
/// included: settled. A failed output reservation forfeits nothing: its
/// release was spent at the grant, bound to the permit that drops.
#[test]
fn text_encoding_credit_is_settled_after_every_physical_failure() {
    let source = credit_text();
    physical_matrix("text encoding credit physically", |failure| {
        support::recorded_run(|run| {
            let policy = run.observed_policy(POOL);
            let observer = Observation::begin(failure);
            observer.stop();
            let bound = normalize_turns(&source);
            let ledger = run.with_policy(policy, |m| m.share());
            let mut last = None;
            run.holding(
                text_encoder(&source),
                support::Retirement::Released,
                &observer,
                |encoder| {
                    match encoder.drive_observed(
                        policy,
                        bound,
                        support::Retirement::Released,
                        |m, encoder| last = Some((m.credits(), encoder.held_credit())),
                        |_| (),
                    ) {
                        Ok(()) => assert!(failure.is_none(), "the injected request did not fail"),
                        Err(Stopped::Operation(BoundedError::Allocation { .. })) => {
                            assert!(failure.is_some(), "the baseline allocation failed");
                            encoder.finish_observed(
                                policy,
                                bound,
                                support::Retirement::Released,
                                |encoder| last = Some((ledger.credits(), encoder.held_credit())),
                            )?;
                        }
                        Err(stop) => return Err(Finding::from(stop)),
                    }
                    Ok(())
                },
            )?;
            let (credits, held) = last.expect("the encoding or its cleanup took a turn");
            settled(credits, held, &format!("physical failure {failure:?}"));
            let stats = observer.snapshot();
            assert_eq!(stats.denied, usize::from(failure.is_some()));
            assert_eq!(stats.live, 0);
            assert_eq!(stats.unadmitted, 0);
            assert!(!stats.overflow);
            Ok((
                stats.calls,
                run.with_policy(policy, |m| {
                    assert_eq!(m.live_bytes(), 0);
                    m.reached()
                }),
            ))
        })
    });
}

/// A text encoding resumed on a new policy every turn, fresh ones and
/// shares of one pool alternating, every third refusing its request: credit
/// held under one policy is spent under another, and the ledgers of every
/// family that served it conserve it after every turn and settle it at the
/// end. A fresh policy is a family of its own, summed; every share of the
/// pool records into the pool's one ledger, read once. The run must hold
/// credit across a change of policy, or the case is vacuous.
#[test]
fn text_encoding_credit_is_conserved_across_fresh_and_shared_policies() {
    let source = credit_text();
    support::recorded_run(|run| {
        let pool = run.policy(POOL);
        // Every turn's policy registered with the run before the encoder is
        // held: a fresh family of the run, or a share of the pool's, with a
        // trace of its own. Later policies settle obligations into their
        // original families, so the families are summed by handle, not by
        // snapshots taken before that settlement; every share records into
        // the pool's one ledger, read once.
        let turns = 3 * normalize_turns(&source);
        let mut families = vec![pool];
        let policies: Vec<_> = (0..turns)
            .map(|turn| {
                if turn % 2 == 1 {
                    run.shared_policy(pool)
                } else {
                    let family = run.policy(POOL);
                    families.push(family);
                    family
                }
            })
            .collect();
        run.holding(
            text_encoder(&source),
            Retirement::Released,
            &Unwitnessed,
            |encoder| {
                let mut crossed = false;
                for (turn, &policy) in policies.iter().enumerate() {
                    crossed |= encoder.value().held_credit() != Some(WriteWork::default());
                    let result = encoder.with_policy(policy, |encoder, m| {
                        if turn % 3 == 2 {
                            m.fail_requests(usize::MAX);
                        }
                        m.turn();
                        encoder.step(m)
                    });
                    let credits = families.iter().fold(Credits::default(), |total, &family| {
                        total
                            .checked_add(encoder.with_policy(family, |_, m| m.credits()))
                            .expect("a run's ledgers sum within u64")
                    });
                    let held = encoder.value().held_credit();
                    match result {
                        Ok(Step::Complete(output)) => {
                            // Settled while the encoder is still held, then
                            // the output handed over from its exhausted
                            // publisher.
                            assert!(crossed, "no credit was held across a change of policy");
                            settled(credits, held, "the published encoding");
                            return encoder.hand_over(
                                Retirement::Exhausted,
                                output,
                                Retirement::Released,
                                |_| Ok(()),
                            );
                        }
                        Ok(_) => conserved(credits, held, &format!("turn {turn}")),
                        Err(error) if error.refused() => {
                            conserved(credits, held, &format!("turn {turn}"));
                        }
                        Err(error) => {
                            return Err(Finding::Driver(format!("turn {turn}: {error:?}")));
                        }
                    }
                }
                Err(Finding::Driver("the text did not encode".to_owned()))
            },
        )
    });
}

/// The bucket traversal of a sparse table, every admission refused once, and
/// cancelled at every call: its window credit conserved after every call,
/// each control's spent as it is inspected, and settled once the enumeration
/// completes, its remainder forfeited, or once a cancellation ends it.
///
/// Each run is a recorded run of its own whose whole stream and checkpoints
/// the shared runner finishes and refines ([`support::recorded_run`]). An
/// accounting discrepancy is kept, the first one, where its defect shows,
/// rather than ending the run there: every ordinary cleanup still runs (the
/// cursor's window and the owner dropped), and the discrepancy is recorded
/// as the run's defect ([`support::RecordedRun::defect`]), which the runner
/// reports together with what the recording actually finished as. So a
/// planted defect is named by its accounting and its recording consequence
/// apart: `tests/data/controls/credit-left-held.patch` (a finished cursor
/// still holding its window, seen before any destruction could settle it)
/// reports "an obligation left held" beside a recording that finishes and
/// refines, the kept window forfeited at its drop;
/// `credit-lost-across-suspension.patch` (the window forgotten at a yield)
/// reports "lost credit", custody reporting nothing while the ledgers leave
/// the window unclosed, beside the recording's own refusal of the leaked
/// capability, observed, not presumed.
#[cfg(feature = "hashbrown")]
#[test]
fn bucket_credit_is_conserved_at_every_call_and_settled_at_its_end() {
    use dcbor::bounded::Forfeit;
    use dcbor::bounded::encoding::buckets::{BucketCursor, BucketPosition, BucketStep};
    let hash = |pair: &(u64, u64)| pair.0;
    let mut table = dcbor::hashbrown::HashTable::with_capacity(200);
    for key in [0u64, 70, 199] {
        table.insert_unique(key, (key, key), hash);
    }
    let bound = 4 * table.num_buckets() + 16;
    // Each enumeration a recorded run of its own, the owner of the windows'
    // acquisitions minted in its session, every admission refused once and
    // each call a fresh turn, its refusal cleared.
    let enumerate = |cancel: Option<usize>| -> (usize, dcbor::bounded::boundary::Reached) {
        support::recorded_run(|run| {
            let policy = run.observed_policy(POOL);
            let owner = run.with_policy(policy, |m| {
                m.fail_each();
                m.owner().expect("a recorded owner")
            });
            // The cursor's position, window and acquisition held by the run
            // with their owner, observed at every checkpoint and retired
            // once the body exits.
            let (calls, discrepancy) = run.holding(
                EnumerationCustody {
                    enumeration: (BucketPosition::new(), None, None),
                    owner,
                },
                Retirement::Released,
                &Unwitnessed,
                |enumeration| {
                    enumeration.with_policy(policy, |enumeration, m| {
                        let EnumerationCustody {
                            enumeration: (position, window, acquisition),
                            owner,
                        } = enumeration;
                        let mut cursor = BucketCursor::new(position, window, acquisition);
                        let mut calls = 0;
                        let mut discrepancy = None;
                        loop {
                            assert!(calls < bound, "the enumeration exceeded {bound} calls");
                            if cancel == Some(calls) {
                                cursor.end(m.performer(), Forfeit::Cancelled);
                                break;
                            }
                            calls += 1;
                            m.turn();
                            let result = cursor
                                .step(&table, owner, m)
                                .map(|step| matches!(step, BucketStep::Complete));
                            if discrepancy.is_none() {
                                discrepancy = unconserved(
                                    m.credits(),
                                    cursor.held_credit(),
                                    &format!("call {calls}"),
                                );
                            }
                            match result {
                                Ok(true) => break,
                                Ok(false) => {}
                                Err(error) if error.refused() => {}
                                Err(error) => panic!("call {calls}: {error:?}"),
                            }
                        }
                        // Before any destruction can settle what the cursor
                        // keeps.
                        if discrepancy.is_none() {
                            discrepancy = unsettled(
                                m.credits(),
                                cursor.held_credit(),
                                &format!("cancelled at {cancel:?}"),
                            );
                        }
                        (calls, discrepancy)
                    })
                },
            );
            if let Some(discrepancy) = discrepancy {
                run.defect(discrepancy);
            }
            Ok((calls, run.with_policy(policy, |m| m.reached())))
        })
    };
    // A cancellation before each call, the last case the completed
    // enumeration itself ([`support::stop_matrix`]): no cleanup class is
    // certified for a cursor's states, so every call is stopped at in both
    // layers.
    let (calls, _) = enumerate(None);
    support::stop_matrix("bucket credit cancellation", calls, |at| {
        enumerate(Some(at)).1
    });
}

/// Two operations on one policy, a bucket enumeration then a text encoding,
/// each checked by the delta of the policy's ledgers around it: each delta
/// conserves its own operation's credit and settles it. Planted control
/// `tests/data/controls/credit-attribution-misscoped.patch` scopes the
/// second's delta to begin after its first admission, and must fail it.
///
/// One recorded run: the first discrepancy is kept where it shows, every
/// ordinary cleanup still runs (the window, the owner, the output and the
/// encoder dropped), and the discrepancy is recorded as the run's defect
/// ([`support::RecordedRun::defect`]), reported beside what the recording
/// actually finished as.
#[cfg(feature = "hashbrown")]
#[test]
fn two_operations_on_one_policy_are_checked_by_their_deltas() {
    use dcbor::bounded::encoding::buckets::{BucketCursor, BucketPosition, BucketStep};
    let hash = |pair: &(u64, u64)| pair.0;
    let mut table = dcbor::hashbrown::HashTable::with_capacity(200);
    for key in [3u64, 150] {
        table.insert_unique(key, (key, key), hash);
    }
    let source = credit_text();
    support::recorded_run(|run| {
        let policy = run.observed_policy(POOL);
        let owner = run.with_policy(policy, |m| m.owner().expect("a recorded owner"));
        // The enumeration, held with its owner; its delta read before its
        // custody retires.
        let (between, mut discrepancy) = run.holding(
            EnumerationCustody {
                enumeration: (BucketPosition::new(), None, None),
                owner,
            },
            Retirement::Released,
            &Unwitnessed,
            |enumeration| {
                enumeration.with_policy(policy, |enumeration, m| {
                    let EnumerationCustody {
                        enumeration: (position, window, acquisition),
                        owner,
                    } = enumeration;
                    let start = m.credits();
                    let mut cursor = BucketCursor::new(position, window, acquisition);
                    for _ in 0..4 * table.num_buckets() + 16 {
                        m.turn();
                        if let BucketStep::Complete = cursor
                            .step(&table, owner, m)
                            .expect("a policy of the suite's pool")
                        {
                            break;
                        }
                    }
                    let between = m.credits();
                    let first = between.checked_sub(start).expect("a later snapshot");
                    (
                        between,
                        unsettled(first, cursor.held_credit(), "the enumeration's delta"),
                    )
                })
            },
        );
        // The encoding, held; its delta read after its last turn while it is
        // still held, before its output or itself can settle anything.
        let mut last = None;
        run.holding(
            text_encoder(&source),
            Retirement::Released,
            &Unwitnessed,
            |encoder| {
                encoder.drive_observed(
                    policy,
                    normalize_turns(&source),
                    Retirement::Released,
                    |m, encoder| last = Some((m.credits(), encoder.held_credit())),
                    |_| (),
                )
            },
        )?;
        if discrepancy.is_none() {
            let (credits, held) = last.expect("the encoding took a turn");
            let second = credits.checked_sub(between).expect("a later snapshot");
            discrepancy = unsettled(second, held, "the encoding's delta");
        }
        if let Some(discrepancy) = discrepancy {
            run.defect(discrepancy);
        }
        Ok(())
    });
}

/// A scope abandoned in the middle of a typed decode, at every turn of a run
/// that refuses every admission once ([`support::stop_matrix`]: no cleanup
/// class is certified for an abandoned scope, so every turn is stopped at in
/// both layers), so a refused request leaves credit
/// held: the decoder and the owner dropped without stepped cleanup, the
/// scope drained terminally by a policy minted from its permit
/// (`drain_terminally`). The originating policy's snapshot holds the
/// terminal drain's events, its forfeits included, and conserves with
/// nothing held, since no custody survives. Some run must forfeit, or the
/// terminal path recorded nothing.
///
/// The terminal drain's own work is the originating family's: its cleanup
/// units, admitted by the terminal policy minted from the scope's permit,
/// are recorded into that permit's family's ledgers, so the family's
/// admitted work rises across the owner's drop. A forfeit reaches its
/// obligation's own origin whatever policy performs it (`Retained`), so
/// conservation alone cannot tell a terminal policy of the family from one
/// of counters of its own; the drain's admissions can. Planted control
/// `tests/data/controls/credit-terminal-fresh-counters.patch` (the terminal
/// policy over fresh counters) must fail the last assertion: no drain's
/// work reaches the originating family.
#[test]
fn an_abandoned_scope_conserves_credit_through_its_terminal_drain() {
    let wire = [0x82, 0x63, b'q', 0xcc, 0x81, 0x61, b'b'];
    let mut forfeited = false;
    let mut drained = false;
    // The bound of turns the decode is driven within; its unobstructed run
    // publishes after far fewer.
    let bound = suite(|run, policy| {
        Ok(run.with_policy(policy, |m| {
            m.fail_each();
            allowed(m, typed_turns::<Vec<String>>(wire.len()))
        }))
    });
    // The decode abandoned after `stop` turns, or never (`None`), which
    // publishes: the scope's credits, its credits before the owner's drop,
    // the boundary valuations reached, and the turns the decode began.
    let abandon = |stop: Option<usize>| {
        let mut began = 0;
        let (credits, before, reached) = suite(|run, policy| {
            run.with_policy(policy, |m| m.fail_each());
            let before = run.holding(
                DecodeOwner::new(),
                support::Retirement::Scope,
                &support::pipeline::Unwitnessed,
                |owner| {
                    owner.initialize(policy)?;
                    // The decode abandoned after `stop` turns, published or
                    // not: its decoder and any value retire here, and the
                    // scope is never drained, its own destruction the
                    // terminal drain.
                    owner.decoder::<_, Vec<String>, _, _>(
                        policy,
                        support::Borrowing(&wire),
                        Options::normalizing(8),
                        &support::pipeline::Unwitnessed,
                        |decoder| {
                            decoder.controlled(
                                policy,
                                bound,
                                support::Retirement::Published,
                                true,
                                |_, _, at| {
                                    began = at + 1;
                                    Some(at) == stop
                                },
                                |_| (),
                            )
                        },
                    )??;
                    Ok::<_, Finding>(owner.with_policy(policy, |_, m| m.credits()))
                },
            )?;
            run.with_policy(policy, |m| {
                assert_eq!(
                    m.live_bytes(),
                    0,
                    "stop {stop:?}: the terminal drain kept storage"
                );
                Ok((m.credits(), before, m.reached()))
            })
        });
        (credits, before, reached, began)
    };
    // Every stop from none through publication ([`support::stop_matrix`]):
    // the turns the unobstructed decode takes, counted by its own run.
    let (.., published) = abandon(None);
    support::stop_matrix("abandoned scope terminal drain", published, |stop| {
        let (credits, before, reached, _) = abandon(Some(stop));
        forfeited |= credits.forfeited != WriteWork::default();
        drained |= credits.admitted != before.admitted;
        settled(
            credits,
            Some(WriteWork::default()),
            &format!("abandoned after {stop} turns"),
        );
        reached
    });
    assert!(forfeited, "no terminal drain forfeited held credit");
    assert!(
        drained,
        "no terminal drain's admitted work reached the originating family"
    );
}

#[cfg(feature = "derive")]
#[test]
fn derived_nested_values_release_every_failed_physical_allocation() {
    #[derive(dcbor::CBORBoundedDecodable)]
    struct Record {
        #[cbor(n = 1)]
        first: String,
        #[cbor(n = 2)]
        nested: Vec<Vec<String>>,
    }
    // Literal map {1: "a", 2: [["b", "c"], ["d"]]}.
    let wire = [
        0xa2, 1, 0x61, b'a', 2, 0x82, 0x82, 0x61, b'b', 0x61, b'c', 0x81, 0x61, b'd',
    ];
    allocation_matrix::<Record>(&wire, |value| {
        assert_eq!(value.first, "a");
        assert_eq!(value.nested[0], ["b", "c"]);
        assert_eq!(value.nested[1], ["d"]);
    });
}
