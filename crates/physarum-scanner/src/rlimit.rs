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
    match get_open_file_limit() {
        Some(limit) => {
            let suggested = ((limit as f64) * 0.8) as usize;
            suggested.clamp(100, 65_535)
        }
        None => 4_500,
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
        // Lower the limit temporarily (raising requires root on many systems).
        let lower = (original / 2).max(64);
        if set_open_file_limit(lower).is_ok() {
            let current = get_open_file_limit().unwrap();
            assert_eq!(current, lower);
            // Restore.
            let _ = set_open_file_limit(original);
        }
        // If set fails (no privilege), test still passes.
    }
}
