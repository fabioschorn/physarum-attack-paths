//! Named scan timers for performance measurement.
//!
//! Ported from RustScan's `benchmark/mod.rs` and improved:
//! - `Benchmark` implements `Default`.
//! - `summary()` formats durations to millisecond precision.
//! - `NamedTimer` exposes `elapsed()` for inline checks without ending the timer.

use std::time::{Duration, Instant};

/// A collection of named timers accumulated during a scan.
///
/// # Example
/// ```
/// use physarum_scanner::benchmark::{Benchmark, NamedTimer};
///
/// let mut bm = Benchmark::new();
/// let mut t = NamedTimer::start("tcp-connect");
/// // ... do work ...
/// t.end();
/// bm.push(t);
/// println!("{}", bm.summary());
/// ```
#[derive(Debug, Default)]
pub struct Benchmark {
    timers: Vec<NamedTimer>,
}

impl Benchmark {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a completed (or in-progress) timer to the collection.
    pub fn push(&mut self, timer: NamedTimer) {
        self.timers.push(timer);
    }

    /// Format all completed timers as a human-readable summary table.
    ///
    /// Timers that have not been ended are omitted from the output.
    pub fn summary(&self) -> String {
        let mut s = String::from("\nScan Benchmark Summary");
        for t in &self.timers {
            if let Some(dur) = t.duration() {
                s.push_str(&format!(
                    "\n  {:<20} {:>8.3}s  ({:.0}ms)",
                    t.name,
                    dur.as_secs_f32(),
                    dur.as_secs_f64() * 1_000.0
                ));
            }
        }
        s
    }
}

/// A named timer with a start instant and an optional end instant.
#[derive(Debug)]
pub struct NamedTimer {
    name: &'static str,
    start: Option<Instant>,
    end: Option<Instant>,
}

impl NamedTimer {
    /// Create and immediately start a named timer.
    pub fn start(name: &'static str) -> Self {
        Self {
            name,
            start: Some(Instant::now()),
            end: None,
        }
    }

    /// Record the end time.
    pub fn end(&mut self) {
        self.end = Some(Instant::now());
    }

    /// Return the elapsed duration if the timer has been ended, otherwise `None`.
    pub fn duration(&self) -> Option<Duration> {
        match (self.start, self.end) {
            (Some(s), Some(e)) => Some(e.saturating_duration_since(s)),
            _ => None,
        }
    }

    /// Return the elapsed time since start (even if `end()` has not been called).
    pub fn elapsed(&self) -> Option<Duration> {
        self.start.map(|s| s.elapsed())
    }

    pub fn name(&self) -> &'static str {
        self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn completed_timer_has_duration() {
        let mut t = NamedTimer::start("test");
        sleep(Duration::from_millis(10));
        t.end();
        let d = t.duration().unwrap();
        assert!(d >= Duration::from_millis(10));
    }

    #[test]
    fn unended_timer_has_no_duration() {
        let t = NamedTimer::start("pending");
        assert!(t.duration().is_none());
        assert!(t.elapsed().is_some()); // but elapsed works
    }

    #[test]
    fn summary_includes_completed_excludes_pending() {
        let mut bm = Benchmark::new();

        let mut t1 = NamedTimer::start("udp-scan");
        sleep(Duration::from_millis(5));
        t1.end();
        bm.push(t1);

        bm.push(NamedTimer::start("not-ended")); // not ended — omitted

        let s = bm.summary();
        assert!(s.contains("Scan Benchmark Summary"));
        assert!(s.contains("udp-scan"));
        assert!(!s.contains("not-ended"));
    }

    #[test]
    fn empty_benchmark_summary() {
        let bm = Benchmark::new();
        assert!(bm.summary().contains("Scan Benchmark Summary"));
    }
}
