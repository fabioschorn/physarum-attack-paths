use crate::range_iterator::RangeIterator;
use rand::seq::SliceRandom;
use serde::Deserialize;

/// A contiguous range of port numbers.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn new(start: u16, end: u16) -> Self {
        Self { start, end }
    }

    /// Parse `"start-end"` notation, e.g. `"1-1000"`.
    pub fn parse(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.splitn(2, '-').collect();
        match parts.as_slice() {
            [start, end] => {
                let start = start
                    .parse::<u16>()
                    .map_err(|e| format!("invalid start port: {e}"))?;
                let end = end
                    .parse::<u16>()
                    .map_err(|e| format!("invalid end port: {e}"))?;
                if start > end {
                    return Err(format!("start ({start}) must be ≤ end ({end})"));
                }
                Ok(Self { start, end })
            }
            _ => Err("range format must be 'start-end', e.g. '1-1000'".into()),
        }
    }

    /// All 65 535 ports (1–65535).
    pub fn all() -> Self {
        Self {
            start: 1,
            end: 65_535,
        }
    }
}

/// Order in which ports are visited during a scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ScanOrder {
    /// Ascending numeric order: 1, 2, 3, …
    #[default]
    Serial,
    /// LCG pseudo-random order — covers every port exactly once without a Vec.
    Random,
}

/// Determines the sequence of port numbers fed to the scanner.
///
/// | Variant | Source | Order |
/// |---------|--------|-------|
/// | `Manual` | explicit `Vec<u16>` | as-given (optionally pre-shuffled) |
/// | `Serial` | `PortRange` | ascending |
/// | `Random` | `PortRange` | LCG pseudo-random, no allocation |
#[derive(Debug)]
pub enum PortStrategy {
    Manual(Vec<u16>),
    Serial(SerialRange),
    Random(RandomRange),
}

impl PortStrategy {
    /// Select a strategy from the given options.
    ///
    /// - If `ports` is `Some`, those ports are used (shuffled when `order == Random`).
    /// - If `ports` is `None`, `range` is consumed in the specified order.
    /// - Panics if both `ports` and `range` are `None`.
    pub fn pick(range: &Option<PortRange>, ports: Option<Vec<u16>>, order: ScanOrder) -> Self {
        match (order, ports) {
            (ScanOrder::Serial, None) => {
                let r = range
                    .as_ref()
                    .expect("PortRange required when no explicit ports");
                PortStrategy::Serial(SerialRange {
                    start: r.start,
                    end: r.end,
                })
            }
            (ScanOrder::Random, None) => {
                let r = range
                    .as_ref()
                    .expect("PortRange required when no explicit ports");
                PortStrategy::Random(RandomRange {
                    start: r.start,
                    end: r.end,
                })
            }
            (ScanOrder::Serial, Some(list)) => PortStrategy::Manual(list),
            (ScanOrder::Random, Some(mut list)) => {
                list.shuffle(&mut rand::thread_rng());
                PortStrategy::Manual(list)
            }
        }
    }

    /// Materialise the port sequence into a `Vec<u16>`.
    ///
    /// For `Serial` and `Random` variants backed by a `PortRange` this allocates
    /// a Vec of up to 65 535 elements; callers that need truly allocation-free
    /// iteration should use `order_iter()` instead.
    pub fn order(&self) -> Vec<u16> {
        match self {
            PortStrategy::Manual(ports) => ports.clone(),
            PortStrategy::Serial(r) => (r.start..=r.end).collect(),
            PortStrategy::Random(r) => RangeIterator::new(r.start.into(), r.end.into()).collect(),
        }
    }
}

/// Ascending port range.
#[derive(Debug, Clone)]
pub struct SerialRange {
    pub start: u16,
    pub end: u16,
}

/// Port range scanned in LCG pseudo-random order.
#[derive(Debug, Clone)]
pub struct RandomRange {
    pub start: u16,
    pub end: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_range_ascending_order() {
        let s = PortStrategy::Serial(SerialRange { start: 1, end: 100 });
        assert_eq!(s.order(), (1u16..=100).collect::<Vec<_>>());
    }

    #[test]
    fn random_range_covers_all_ports() {
        let s = PortStrategy::Random(RandomRange { start: 1, end: 100 });
        let mut result = s.order();
        result.sort_unstable();
        assert_eq!(result, (1u16..=100).collect::<Vec<_>>());
    }

    #[test]
    fn manual_serial_preserves_order() {
        let s = PortStrategy::pick(&None, Some(vec![80, 443, 22]), ScanOrder::Serial);
        assert_eq!(s.order(), vec![80, 443, 22]);
    }

    #[test]
    fn manual_random_covers_same_ports() {
        let ports: Vec<u16> = (1..=20).collect();
        let s = PortStrategy::pick(&None, Some(ports.clone()), ScanOrder::Random);
        let mut result = s.order();
        result.sort_unstable();
        assert_eq!(result, ports);
    }

    #[test]
    fn port_range_parse_valid() {
        assert_eq!(
            PortRange::parse("1-1000").unwrap(),
            PortRange {
                start: 1,
                end: 1000
            }
        );
        assert_eq!(
            PortRange::parse("80-80").unwrap(),
            PortRange { start: 80, end: 80 }
        );
    }

    #[test]
    fn port_range_parse_invalid() {
        assert!(PortRange::parse("bad").is_err());
        assert!(PortRange::parse("1000-1").is_err());
        assert!(PortRange::parse("70000-80000").is_err());
    }

    #[test]
    fn scan_order_serde_roundtrip() {
        #[derive(serde::Deserialize)]
        struct Wrapper {
            order: ScanOrder,
        }
        let s: Wrapper = toml::from_str("order = \"Serial\"").unwrap();
        assert_eq!(s.order, ScanOrder::Serial);
        let r: Wrapper = toml::from_str("order = \"Random\"").unwrap();
        assert_eq!(r.order, ScanOrder::Random);
    }
}
