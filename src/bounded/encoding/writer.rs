use super::*;

impl<P> Writer<'_, '_, P> {
    pub fn emitted_prefix(&self) -> &[u8] {
        &self.output[..self.written]
    }
    pub fn step<B: Budget>(
        &mut self,
        b: &mut B,
    ) -> BoundedResult<text_cursor::pipeline::EmitStep, B> {
        use text_cursor::pipeline::EmitStep;
        if self.finished {
            return Ok(EmitStep::Finished);
        }
        if self.output.len() != self.plan.len {
            return Err(BoundedError::OutputSize {
                measured: widen(self.plan.len)?,
                provided: widen(self.output.len())?,
            });
        }
        if self.plan.root_payload == Some(self.source) {
            return self.entry_step(b);
        }
        if let Some(&(start, skip)) = self.plan.holes.as_slice().get(self.hole)
            && self.source == start
        {
            b.traverse(1, 0).map_err(BoundedError::Refused)?;
            self.source += skip;
            self.hole += 1;
            return Ok(EmitStep::Progress);
        }
        if self.source == self.plan.bytes.len() {
            b.traverse(1, 0).map_err(BoundedError::Refused)?;
            if self.written != self.plan.len {
                return Err(BoundedError::PlanMismatch);
            }
            self.finished = true;
            return Ok(EmitStep::Complete);
        }
        let boundary = self
            .plan
            .holes
            .as_slice()
            .get(self.hole)
            .map_or(self.plan.bytes.len(), |h| h.0)
            .min(self.plan.root_payload.unwrap_or(self.plan.bytes.len()));
        let count = (boundary - self.source).min(64);
        b.traverse(1, widen(count)?)
            .map_err(BoundedError::Refused)?;
        self.output[self.written..self.written + count]
            .copy_from_slice(&self.plan.bytes.as_slice()[self.source..self.source + count]);
        self.source += count;
        self.written += count;
        Ok(EmitStep::Progress)
    }

    fn entry_step<B: Budget>(
        &mut self,
        b: &mut B,
    ) -> BoundedResult<text_cursor::pipeline::EmitStep, B> {
        use text_cursor::pipeline::EmitStep;
        let Some(entry) = self.plan.entries.as_slice().get(self.entry) else {
            b.traverse(1, 0).map_err(BoundedError::Refused)?;
            if self.written != self.plan.len {
                return Err(BoundedError::PlanMismatch);
            }
            self.finished = true;
            return Ok(EmitStep::Complete);
        };
        let length = entry
            .end
            .checked_sub(entry.start)
            .ok_or(BoundedError::PlanMismatch)?;
        let remaining = length
            .checked_sub(self.entry_offset)
            .ok_or(BoundedError::PlanMismatch)?;
        if remaining == 0 {
            b.traverse(1, 0).map_err(BoundedError::Refused)?;
            self.entry += 1;
            self.entry_offset = 0;
            return Ok(EmitStep::Progress);
        }
        let count = remaining.min(64);
        let source = entry
            .start
            .checked_add(self.entry_offset)
            .ok_or(BoundedError::Overflow)?;
        let source_end = source.checked_add(count).ok_or(BoundedError::Overflow)?;
        let output_end = self
            .written
            .checked_add(count)
            .ok_or(BoundedError::Overflow)?;
        let bytes = self
            .plan
            .bytes
            .as_slice()
            .get(source..source_end)
            .ok_or(BoundedError::PlanMismatch)?;
        let output = self
            .output
            .get_mut(self.written..output_end)
            .ok_or(BoundedError::PlanMismatch)?;
        b.traverse(1, widen(count)?)
            .map_err(BoundedError::Refused)?;
        output.copy_from_slice(bytes);
        self.entry_offset += count;
        self.written = output_end;
        Ok(EmitStep::Progress)
    }
}
