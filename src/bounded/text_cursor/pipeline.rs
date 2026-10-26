//! Separately retained preparation and allocation-free destination emission.
use super::*;

pub struct PreparedText<P> {
    chars: Owned<char, P>,
    count: usize,
    header: [u8; MAX_HEAD_LEN],
    header_len: usize,
    length: u64,
}

impl<P> PreparedText<P> {
    pub fn len(&self) -> u64 {
        self.length
    }
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    pub fn writer<'p, 'o>(&'p self, output: &'o mut [u8]) -> TextWriter<'p, 'o, P> {
        TextWriter {
            plan: self,
            output,
            position: 0,
            scalar: 0,
            finished: false,
        }
    }
}

/// Normalization up to, and not including, output allocation. A terminal
/// error of the normalizer is followed by its cleanup, one admitted unit per
/// step, then [`Step::Finished`].
pub struct TextPreparation<'a, P> {
    cursor: TextEncoder<'a, P>,
    failed: bool,
    finished: bool,
}

impl<'a, P> TextPreparation<'a, P> {
    pub fn new(source: &'a str) -> Self {
        Self {
            cursor: TextEncoder::new(source),
            failed: false,
            finished: false,
        }
    }

    pub fn position(&self) -> Position {
        self.cursor.position()
    }

    pub fn step<A: Allocator<Permit = P>>(
        &mut self,
        allocator: &mut A,
    ) -> BoundedResult<Step<PreparedText<P>>, A> {
        if self.finished {
            return Ok(Step::Finished);
        }
        match self.cursor.step(allocator) {
            Ok(Step::Progress) => {}
            Ok(Step::Finished) if self.failed => {
                self.finished = true;
                return Ok(Step::Finished);
            }
            // Preparation stops before the normalizer allocates its output,
            // so the normalizer never completes or finishes on its own here.
            Ok(Step::Complete(_) | Step::Finished) => {
                self.failed = true;
                return Err(BoundedError::PlanMismatch);
            }
            Err(error) => {
                if !error.refused() {
                    self.failed = true;
                }
                return Err(error);
            }
        }
        if self.failed {
            return Ok(Step::Progress);
        }
        // Preparation stops before the output's release is admitted: it
        // publishes the characters, never an output.
        if self.cursor.phase == Phase::ReleaseOutput {
            let length = add(self.cursor.payload_len, self.cursor.header_len as u64)?;
            let Some(chars) = self.cursor.chars.take_step(allocator)? else {
                return Ok(Step::Progress);
            };
            self.finished = true;
            self.cursor.phase = Phase::Finished;
            return Ok(Step::Complete(PreparedText {
                chars,
                count: self.cursor.written,
                header: self.cursor.header,
                header_len: self.cursor.header_len,
                length,
            }));
        }
        Ok(Step::Progress)
    }
}

/// The [`ResourceBound`] of a [`TextPreparation`] of a text of `text`'s
/// shape: the encoding's ([`encode_bound`]) as far as its output
/// allocation, which it never reaches, so neither the output, the header,
/// the emission, the characters' release nor the publication; a terminal
/// error's cleanup with permits of type `P`. What it publishes is the arena
/// of decomposed characters, of at most the text's parts.
pub fn preparation_bound<P, R>(text: TextShape) -> Result<ResourceBound, BoundedError<R>> {
    TextTerms::of::<R>(
        text,
        WriteWork::default(),
        WriteWork::default(),
        super::cleanup::<R>()?,
    )?
    .prepared()
    .bound()
}

places! {
    /// The places a [`TextWriter`] charges, one term of [`writer_bound`]
    /// each.
    pub(crate) enum WriterPlace {
        /// The head and the scalars, which together are the text's bytes.
        Emitting,
        Completion,
    }
}

/// Writing the head: one value and its bytes.
const HEAD: Capped<WriterPlace> = Capped::new(WriterPlace::Emitting, 1, MAX_HEAD_LEN as u64);

/// Writing one scalar: one value and its bytes.
const SCALAR: Capped<WriterPlace> =
    Capped::new(WriterPlace::Emitting, 1, char::MAX.len_utf8() as u64);

/// Completing the write.
const DONE: Unit<WriterPlace> = Unit::new(WriterPlace::Completion, 1, 0);

/// The terms [`writer_bound`] sums, one per [`WriterPlace`].
struct WriterTerms {
    emitting: WriteWork,
    completion: WriteWork,
}

impl WriterTerms {
    /// A text of `len` encoded bytes has at most `len` scalars beside its
    /// head, and its head and scalars are its bytes, each written once.
    fn of<R>(len: u64) -> Result<Self, BoundedError<R>> {
        const { assert!(HEAD.values() == 1 && SCALAR.values() == 1) };
        Ok(Self {
            emitting: WriteWork::new(add(len, 1)?, len),
            completion: DONE.times(1)?,
        })
    }
}

impl Places for WriterTerms {
    type Place = WriterPlace;

    fn term(&self, place: WriterPlace) -> ResourceBound {
        match place {
            WriterPlace::Emitting => ResourceBound::of_work(self.emitting),
            WriterPlace::Completion => ResourceBound::of_work(self.completion),
        }
    }
}

/// The [`ResourceBound`] of writing a prepared text of `len` encoded bytes:
/// its header in one unit, each scalar in one unit of its bytes, and one
/// unit to complete; every byte reported once. A text of `len` bytes has at
/// most `len` scalars. Writing allocates nothing and retains nothing.
pub fn writer_bound<R>(len: u64) -> Result<ResourceBound, BoundedError<R>> {
    WriterTerms::of::<R>(len)?.bound()
}

impl<'a, P, A: Allocator<Permit = P>> Resumable<A> for TextPreparation<'a, P> {
    type Output = PreparedText<P>;
    type Error = BoundedError<A::Refusal>;
    type Position = Position;

    fn step(&mut self, allocator: &mut A) -> BoundedResult<Step<PreparedText<P>>, A> {
        TextPreparation::step(self, allocator)
    }

    fn position(&mut self) -> Position {
        TextPreparation::position(self)
    }
}

/// Borrows both owners for its entire lifetime; no allocation or normalization
/// occurs during writing. A refused step leaves the destination prefix intact.
///
/// The destination remains exclusively borrowed while a writer can resume.
///
/// ```compile_fail,E0506
/// use dcbor::bounded::text_cursor::pipeline::PreparedText;
/// fn overwrite(plan: &PreparedText<()>, output: &mut [u8]) {
///     let writer = plan.writer(output);
///     output[0] = 0;
///     drop(writer);
/// }
/// ```
///
/// A writer cannot outlive the plan owning its normalized scalars.
///
/// ```compile_fail,E0515
/// use dcbor::bounded::text_cursor::pipeline::{PreparedText, TextWriter};
/// fn escape<'a>(plan: PreparedText<()>, output: &'a mut [u8]) -> TextWriter<'a, 'a, ()> {
///     plan.writer(output)
/// }
/// ```
pub struct TextWriter<'p, 'o, P> {
    plan: &'p PreparedText<P>,
    output: &'o mut [u8],
    position: usize,
    scalar: usize,
    finished: bool,
}

impl<P> TextWriter<'_, '_, P> {
    pub fn position(&self) -> usize {
        self.position
    }
    pub fn emitted_prefix(&self) -> &[u8] {
        &self.output[..self.position]
    }

    /// One step. A wrong-sized destination is a terminal error; the writer
    /// is finished after it.
    pub fn step<B: Budget>(&mut self, budget: &mut B) -> BoundedResult<Step<()>, B> {
        if self.finished {
            return Ok(Step::Finished);
        }
        let result = self.advance(budget);
        if matches!(&result, Err(error) if !error.refused()) {
            self.finished = true;
        }
        result
    }

    fn advance<B: Budget>(&mut self, budget: &mut B) -> BoundedResult<Step<()>, B> {
        if widen(self.output.len())? != self.plan.length {
            return Err(BoundedError::OutputSize {
                measured: self.plan.length,
                provided: widen(self.output.len())?,
            });
        }
        if self.position == 0 {
            HEAD.admit(budget, self.plan.header_len as u64)?;
            self.output[..self.plan.header_len]
                .copy_from_slice(&self.plan.header[..self.plan.header_len]);
            self.position = self.plan.header_len;
        } else if self.scalar < self.plan.count {
            let ch = self.plan.chars.as_slice()[self.scalar];
            SCALAR.admit(budget, ch.len_utf8() as u64)?;
            let mut bytes = [0; 4];
            let encoded = ch.encode_utf8(&mut bytes).as_bytes();
            let end = self.position + encoded.len();
            self.output[self.position..end].copy_from_slice(encoded);
            self.position = end;
            self.scalar += 1;
        } else {
            DONE.admit(budget)?;
            self.finished = true;
            return Ok(Step::Complete(()));
        }
        Ok(Step::Progress)
    }
}

impl<P, B: Budget> Resumable<B> for TextWriter<'_, '_, P> {
    type Output = ();
    type Error = BoundedError<B::Refusal>;
    type Position = usize;

    fn step(&mut self, budget: &mut B) -> BoundedResult<Step<()>, B> {
        TextWriter::step(self, budget)
    }

    fn position(&mut self) -> usize {
        TextWriter::position(self)
    }
}

/// Place attribution of a text write, which this crate's tests record under
/// `std`.
#[cfg(all(test, feature = "std"))]
mod attribution {
    use super::*;
    use crate::CBOR;
    use crate::bounded::places::{self, Factor, Ledgered, Run, WORK};
    use crate::bounded::{Limits, Reservation, within};
    use core::ops::ControlFlow;

    /// Every place of a write is within its term ([`writer_bound`]) on an
    /// empty text, a long one of one-byte scalars and one of four-byte
    /// scalars, each written exactly as the symbolic encoding; every
    /// admission is made at some place; each place's witness charges it, and
    /// fails without its term.
    #[test]
    fn every_place_of_a_text_write_is_within_its_term() {
        let mut runs = Vec::new();
        let mut witnesses = Vec::new();
        for (name, source) in [
            ("empty", String::new()),
            ("ascii", "x".repeat(300)),
            ("astral", "\u{1f600}".repeat(40)),
        ] {
            let mut preparation = TextPreparation::new(&source);
            let mut limits = Limits::unlimited();
            let prepared = preparation_bound::<Reservation, ()>(TextShape::of(&source))
                .expect("the bound of a text fits in u64");
            let plan = within("text preparation", prepared, || {
                match preparation
                    .step(&mut limits)
                    .expect("an unlimited preparation completes")
                {
                    Step::Complete(plan) => ControlFlow::Break(plan),
                    Step::Progress => ControlFlow::Continue(()),
                    Step::Finished => unreachable!("a preparation publishes its plan"),
                }
            });
            let mut bytes =
                vec![0; usize::try_from(plan.len()).expect("a text plan fits in memory")];
            let written = writer_bound::<()>(plan.len()).expect("the bound fits in u64");
            let mut policy = Ledgered::new();
            let mut writer = plan.writer(&mut bytes);
            within("text write", written, || {
                match writer
                    .step(&mut policy)
                    .expect("an unlimited policy never refuses")
                {
                    Step::Progress => ControlFlow::Continue(()),
                    Step::Complete(()) => ControlFlow::Break(()),
                    Step::Finished => unreachable!("a write completes before it finishes"),
                }
            });
            assert_eq!(bytes, CBOR::from(source.as_str()).to_cbor_data(), "{name}");
            if name == "astral" {
                witnesses.push((runs.len(), WriterPlace::Emitting));
                witnesses.push((runs.len(), WriterPlace::Completion));
            }
            runs.push(Run {
                outcome: places::Outcome::Published,
                name: name.to_string(),
                policy,
                terms: WriterTerms::of::<()>(plan.len()).expect("the bound fits in u64"),
            });
        }
        places::check(&runs);
        places::witnessed(&runs, &witnesses);
        places::Tightness::new("text_write")
            .places(&runs, &witnesses, |place| match place {
                WriterPlace::Emitting | WriterPlace::Completion => Factor::Measured,
            })
            .joint(
                &runs,
                "ascii",
                WORK,
                "one-byte scalars: a scalar per byte, the most units a text's bytes allow",
            )
            .finish();
    }
}
