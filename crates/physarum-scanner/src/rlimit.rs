//! Open-file-limit (RLIMIT_NOFILE) management.
//!
//! Ported from RustScan's ulimit handling in `input.rs` / `main.rs` and improved:
//! - Exposed as a plain function instead of buried in CLI arg processing.
//! - Returns `std::io::Result` instead of panicking.
//! - `get_open_file_limit` lets callers read the current limit before deciding
//!   on a batch_size.
//! - No-op on non-Unix platforms (Windows does not have RLIMIT_NOFILE).
//!
//! # Relationship to batch_size
//!
//! RustScan's rule of thumb: set `batch_size` to at most 80 % of the soft
//! RLIMIT_NOFILE value.  Each in-flight socket probe holds one file descriptor
//! open until the connect() resolves, so exceeding the FD limit causes
//! `EMFILE` / `ENFILE` errors that the scanner returns as `ScanError::TooManyOpenFiles`.

/// Set the OS open-file-descriptor soft limit to `limit`.
///
/// On success the limit is raised (or lowered) so the scanner can open up to
/// `limit` concurrent sockets.  Requires sufficient privilege when raising
/// above the current hard limit.
///
/// # Errors
/// Returns `Err` if `setrlimit(2)` fails (e.g. `limit > hard_limit` without
/// `CAP_SYS_RESOURCE`).
///
/// # Platform
/// No-op on non-Unix systems (returns `Ok(())`).
pub fn set_open_file_limit(limit: u64) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io;
        let rlim = libc::rlimit {
            rlim_cur: limit,
            rlim_max: limit,
        };
        // Safety: rlim is a valid libc::rlimit value.
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let _ = limit;
    Ok(())
}

/// Read the current soft open-file-descriptor limit.
///
/// Returns `None` on non-Unix platforms or if `getrlimit(2)` fails.
pub fn get_open_file_limit() -> Option<u64> {
    #[cfg(unix)]
    {
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // Safety: rlim is a valid output buffer.
        let ret = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) };
        if ret == 0 {
            return Some(rlim.rlim_cur);
        }
    }
    None
}

/// Suggest a safe `batch_size` based on the current open-file limit.
///
/// Returns 80 % of `get_open_file_limit()`, capped at 65 535 and floored at 100.
/// Falls back to 4 500 (RustScan's default) if the limit cannot be read.
pub fn recommended_batch_size() -> usize {
    infer_batch_size(4_500, get_open_file_limit().unwrap_or(8_000) as usize)
}

/// Adjust `desired_batch_size` to a safe value given the OS `ulimit`.
///
/// Ported from RustScan's `infer_batch_size()` in `main.rs`.
///
/// | ulimit vs desired | result |
/// |---|---|
/// | `ulimit < 3 000` (very small) | `ulimit / 2` |
/// | `ulimit < desired` but `ulimit ≥ 3 000` and `ulimit ≤ 8 000` | `ulimit - 100` |
/// | `ulimit < desired` but `ulimit > 8 000` | 3 000 (safe average) |
/// | `ulimit ≥ desired` | `desired` unchanged |
///
/// The constants 3 000 and 8 000 come from RustScan's empirical tuning on
/// Ubuntu (average default NOFILE = 8 000, safe average batch = 3 000).
pub fn infer_batch_size(desired_batch_size: usize, ulimit: usize) -> usize {
    const AVERAGE_BATCH_SIZE: usize = 3_000;
    const DEFAULT_FD_LIMIT: usize = 8_000;

    if ulimit < desired_batch_size {
        if ulimit < AVERAGE_BATCH_SIZE {
            // Very small ulimit — halve it to stay safe.
            ulimit / 2
        } else if ulimit > DEFAULT_FD_LIMIT {
            // ulimit is large but still below desired — cap at safe average.
            AVERAGE_BATCH_SIZE
        } else {
            // ulimit is moderate — leave a small headroom for other FDs.
            ulimit - 100
        }
    } else {
        desired_batch_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_limit_returns_some_on_unix() {
        #[cfg(unix)]
        {
            let limit = get_open_file_limit();
            assert!(limit.is_some());
            assert!(limit.unwrap() > 0);
        }
    }

    #[test]
    fn recommended_batch_size_in_range() {
        let bs = recommended_batch_size();
        assert!(bs >= 100 && bs <= 65_535);
    }

    #[test]
    #[cfg(unix)]
    fn set_limit_roundtrip() {
        let original = get_open_file_limit().unwrap();
        let lower = (original / 2).max(64);
        if set_open_file_limit(lower).is_ok() {
            let current = get_open_file_limit().unwrap();
            assert_eq!(current, lower);
            let _ = set_open_file_limit(original);
        }
    }

    // infer_batch_size — ported directly from RustScan's main.rs tests.

    #[test]
    fn batch_size_lowered_when_ulimit_very_small() {
        // ulimit=120 < AVERAGE(3000) → batch = ulimit/2 = 60
        assert_eq!(infer_batch_size(50_000, 120), 60);
    }

    #[test]
    fn batch_size_lowered_to_average_when_ulimit_above_default_fd_limit() {
        // ulimit=9000 > DEFAULT_FD_LIMIT(8000) → batch = AVERAGE(3000)
        assert_eq!(infer_batch_size(50_000, 9_000), 3_000);
    }

    #[test]
    fn batch_size_equals_ulimit_minus_100_when_moderate() {
        // ulimit=5000 in [3000, 8000] → batch = 5000-100 = 4900
        assert_eq!(infer_batch_size(50_000, 5_000), 4_900);
    }

    #[test]
    fn batch_size_unchanged_when_ulimit_higher() {
        // ulimit=1_000_000 > desired=10 → desired unchanged
        assert_eq!(infer_batch_size(10, 1_000_000), 10);
    }

    #[test]
    fn batch_size_unchanged_when_ulimit_equals_desired() {
        assert_eq!(infer_batch_size(5_000, 5_000), 5_000);
    }
}
