//! Terminal output macros for the scanner.
//!
//! Ported from RustScan's `tui.rs` and improved:
//! - Uses raw ANSI escape codes (no external color crate required).
//! - All macros have both a simple 1-arg form and a 3-arg greppable/accessible form.
//! - `scanner_banner!` picks a random quote using the workspace `rand` crate.
//!
//! For structured library logging, prefer `tracing` over these macros.
//! These are intended for binary entry points that print human-readable output.
//!
//! # Modes
//! - **normal**     — colored `[!]` / `[~]` / `[>]` prefixes.
//! - **accessible** — plain text, no ANSI codes (screen-reader friendly).
//! - **greppable**  — completely silent (only open port lines are printed elsewhere).

/// Print a warning line: `[!] message` in bold red.
///
/// ```no_run
/// use physarum_scanner::scanner_warning;
/// scanner_warning!("batch_size exceeds recommended limit");
/// scanner_warning!("host unreachable", greppable: false, accessible: false);
/// ```
#[macro_export]
macro_rules! scanner_warning {
    ($msg:expr) => {
        eprintln!("\x1b[1;31m[!]\x1b[0m {}", $msg);
    };
    ($msg:expr, greppable: $g:expr, accessible: $a:expr) => {
        if !$g {
            if $a {
                eprintln!("{}", $msg);
            } else {
                eprintln!("\x1b[1;31m[!]\x1b[0m {}", $msg);
            }
        }
    };
}

/// Print a detail line: `[~] message` in bold blue.
///
/// ```no_run
/// use physarum_scanner::scanner_detail;
/// scanner_detail!("scanning 1-1000 with batch_size 500");
/// ```
#[macro_export]
macro_rules! scanner_detail {
    ($msg:expr) => {
        eprintln!("\x1b[1;34m[~]\x1b[0m {}", $msg);
    };
    ($msg:expr, greppable: $g:expr, accessible: $a:expr) => {
        if !$g {
            if $a {
                eprintln!("{}", $msg);
            } else {
                eprintln!("\x1b[1;34m[~]\x1b[0m {}", $msg);
            }
        }
    };
}

/// Print an output line: `[>] message` in bold green.
///
/// ```no_run
/// use physarum_scanner::scanner_output;
/// scanner_output!("Open 10.0.0.1:22");
/// ```
#[macro_export]
macro_rules! scanner_output {
    ($msg:expr) => {
        println!("\x1b[1;32m[>]\x1b[0m {}", $msg);
    };
    ($msg:expr, greppable: $g:expr, accessible: $a:expr) => {
        if !$g {
            if $a {
                println!("{}", $msg);
            } else {
                println!("\x1b[1;32m[>]\x1b[0m {}", $msg);
            }
        }
    };
}

/// Print a random banner quote.
///
/// Silenced in greppable mode.  Call at program startup before scanning.
///
/// ```no_run
/// use physarum_scanner::{scanner_banner, output};
/// scanner_banner!();
/// scanner_banner!(greppable: false, accessible: false);
/// ```
#[macro_export]
macro_rules! scanner_banner {
    () => {
        $crate::output::print_banner(false, false);
    };
    (greppable: $g:expr, accessible: $a:expr) => {
        $crate::output::print_banner($g, $a);
    };
}

const QUOTES: &[&str] = &[
    "Scanning ports faster than you can say 'SYN ACK'",
    "Real hackers hack time ⌛",
    "Open ports, closed hearts.",
    "physarum: growing through every open socket",
    "TCP handshake? More like a friendly high-five!",
    "Port scanning: the virtual equivalent of knocking on doors.",
    "You miss 100% of the ports you don't scan.",
    "With physarum-scanner, I scan ports so fast even my firewall gets whiplash.",
    "To scan or not to scan? That is the question.",
    "Breaking and entering... into the world of open ports.",
    "RustScan? More like slowscan. 🐢",
    "physarum: where bio-inspired meets blazing fast.",
];

/// Internal implementation called by `scanner_banner!`.
pub fn print_banner(greppable: bool, accessible: bool) {
    if greppable {
        return;
    }
    use rand::seq::SliceRandom;
    if let Some(q) = QUOTES.choose(&mut rand::thread_rng()) {
        if accessible {
            println!("{q}\n");
        } else {
            println!("\x1b[1;36m{q}\x1b[0m\n");
        }
    }
}
