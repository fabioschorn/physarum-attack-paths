use gcd::Gcd;
use rand::Rng;

/// Memory-efficient random port-order iterator using the Linear Congruential
/// Generator (LCG) algorithm.
///
/// Visits every port in `start..=end` exactly once in pseudo-random order
/// without materialising the full range into a `Vec`.
///
/// The LCG formula is `N+1 = (N + step) % range_size`, where `step` is a
/// random coprime of `range_size` chosen from the middle quartile of the
/// range to avoid degenerate distributions.
///
/// Reference: <https://en.wikipedia.org/wiki/Linear_congruential_generator>
pub(crate) struct RangeIterator {
    active: bool,
    normalized_end: u32,
    normalized_first_pick: u32,
    normalized_pick: u32,
    actual_start: u32,
    step: u32,
}

impl RangeIterator {
    /// Create a new LCG iterator covering ports `start..=end`.
    pub(crate) fn new(start: u32, end: u32) -> Self {
        let normalized_end = end - start + 1;
        let step = pick_random_coprime(normalized_end);
        let normalized_first_pick = rand::thread_rng().gen_range(0..normalized_end);
        Self {
            active: true,
            normalized_end,
            step,
            normalized_first_pick,
            normalized_pick: normalized_first_pick,
            actual_start: start,
        }
    }
}

impl Iterator for RangeIterator {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.active {
            return None;
        }
        let current = self.normalized_pick;
        let next = (current + self.step) % self.normalized_end;
        if next == self.normalized_first_pick {
            self.active = false;
        }
        self.normalized_pick = next;
        Some(
            (self.actual_start + current)
                .try_into()
                .expect("port number exceeds u16::MAX"),
        )
    }
}

/// Pick a step value that is coprime with `end` for a well-distributed LCG.
///
/// Candidates are drawn from the middle two quartiles of the range to avoid
/// steps that produce near-sequential output (too small) or wrap-around artefacts
/// (too large). Falls back to `end - 1` (always coprime) after 10 failed attempts.
fn pick_random_coprime(end: u32) -> u32 {
    let boundary = end / 4;
    let lower = boundary;
    let upper = end - boundary;
    let mut rng = rand::thread_rng();
    let mut candidate = rng.gen_range(lower..upper);
    for _ in 0..10 {
        if end.gcd(candidate) == 1 {
            return candidate;
        }
        candidate = rng.gen_range(lower..upper);
    }
    end - 1
}

#[cfg(test)]
mod tests {
    use super::RangeIterator;

    #[test]
    fn covers_entire_range_small() {
        let mut result: Vec<u16> = RangeIterator::new(1, 10).collect();
        result.sort_unstable();
        assert_eq!(result, (1u16..=10).collect::<Vec<_>>());
    }

    #[test]
    fn covers_entire_range_large() {
        let mut result: Vec<u16> = RangeIterator::new(1, 65_535).collect();
        result.sort_unstable();
        assert_eq!(result, (1u16..=65_535).collect::<Vec<_>>());
    }

    #[test]
    fn covers_arbitrary_subrange() {
        let mut result: Vec<u16> = RangeIterator::new(1000, 2000).collect();
        result.sort_unstable();
        assert_eq!(result, (1000u16..=2000).collect::<Vec<_>>());
    }

    #[test]
    fn order_is_not_serial() {
        let result: Vec<u16> = RangeIterator::new(1, 100).collect();
        let serial: Vec<u16> = (1u16..=100).collect();
        assert_ne!(serial, result, "LCG should produce non-serial order");
    }

    #[test]
    fn no_duplicates() {
        let result: Vec<u16> = RangeIterator::new(1, 500).collect();
        let mut deduped = result.clone();
        deduped.sort_unstable();
        deduped.dedup();
        assert_eq!(result.len(), deduped.len());
    }
}
