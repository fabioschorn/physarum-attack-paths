//! UDP payload map derived from Nmap's `nmap-payloads` database.
//!
//! The `assets/nmap-payloads` file is embedded at compile time via
//! `include_str!`.  The parser runs once on first access (lazy, via
//! `OnceLock`) and returns a `&'static HashMap<u16, Vec<u8>>` that maps each
//! UDP port number to the bytes Nmap sends to elicit a service response.
//!
//! # Why not build.rs?
//!
//! RustScan uses `build.rs` to pre-generate a Rust source file containing the
//! parsed map as hard-coded `vec![…]` literals.  Embedding with `include_str!`
//! and parsing on first access is simpler, produces identical results, and
//! avoids the additional compilation step.
//!
//! # License note
//!
//! The embedded `nmap-payloads` file is © 1996–2022 Nmap Software LLC and
//! distributed under the Nmap Public Source License (NPSL).  Review that
//! license before distributing binaries that embed this data.

use std::collections::HashMap;
use std::sync::OnceLock;

static PAYLOADS: OnceLock<HashMap<u16, Vec<u8>>> = OnceLock::new();

const NMAP_PAYLOADS_RAW: &str = include_str!("../assets/nmap-payloads");

/// Return the Nmap UDP payload map.
///
/// Built from the embedded `nmap-payloads` database on first call and cached
/// for the lifetime of the process.  Each entry maps a UDP port number to the
/// payload bytes that should be sent to elicit a service response.
///
/// Ports not present in the map should be probed with an empty datagram.
pub fn nmap_udp_payloads() -> &'static HashMap<u16, Vec<u8>> {
    PAYLOADS.get_or_init(|| parse_nmap_payloads(NMAP_PAYLOADS_RAW))
}

fn parse_nmap_payloads(text: &str) -> HashMap<u16, Vec<u8>> {
    // Phase 1: collect logical "udp" blocks.  A block starts with a "udp"
    // line and may span continuation lines with additional quoted payloads.
    let mut blocks: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut capturing = false;

    for line in text.lines() {
        if line.trim_start().starts_with('#') || line.trim().is_empty() {
            continue;
        }

        if line.starts_with("udp") {
            if !current.is_empty() {
                blocks.push(current.clone());
                current.clear();
            }
            capturing = true;
        }

        if capturing {
            if !current.is_empty() {
                current.push(' ');
            }
            current.push_str(line);
        }
    }
    if !current.is_empty() {
        blocks.push(current);
    }

    // Phase 2: parse each block into port → payload entries.
    let mut map: HashMap<u16, Vec<u8>> = HashMap::new();

    for block in &blocks {
        let ports = parse_ports(block);
        let payload = parse_payload(block);

        // Blocks without a payload are skipped; those ports fall back to
        // empty datagrams in the scanner (same as unrecognised ports).
        if ports.is_empty() || payload.is_empty() {
            continue;
        }

        for port in ports {
            // Multiple payload entries for the same port are concatenated,
            // matching nmap's "multiple payloads per port" behaviour.
            map.entry(port).or_default().extend_from_slice(&payload);
        }
    }

    map
}

/// Extract the port list from a block like `"udp 53,69,5353 \"…\""`.
///
/// Port ranges use `start-end` notation with an *exclusive* end, matching
/// RustScan's original `for port in start..end` loop.
fn parse_ports(block: &str) -> Vec<u16> {
    let after_udp = block.trim_start_matches("udp").trim_start();
    let port_token = after_udp.split_whitespace().next().unwrap_or("");

    let mut ports = Vec::new();
    for segment in port_token.split(',') {
        let segment = segment.trim();
        if segment.contains('-') {
            let mut parts = segment.splitn(2, '-');
            if let (Some(s), Some(e)) = (parts.next(), parts.next()) {
                if let (Ok(start), Ok(end)) = (s.parse::<u16>(), e.parse::<u16>()) {
                    ports.extend(start..end);
                }
            }
        } else if let Ok(p) = segment.parse::<u16>() {
            ports.push(p);
        }
    }
    ports
}

/// Decode all `\xHH` escape sequences from the quoted payload section of a block.
fn parse_payload(block: &str) -> Vec<u8> {
    let Some(quote_pos) = block.find('"') else {
        return Vec::new();
    };
    decode_hex_escapes(&block[quote_pos + 1..])
}

/// Convert `\xHH` sequences to bytes; all other characters are ignored.
fn decode_hex_escapes(s: &str) -> Vec<u8> {
    let chars: Vec<char> = s.chars().collect();
    let mut bytes = Vec::new();
    let mut i = 0;

    while i < chars.len() {
        if chars[i] == '\\' && chars.get(i + 1) == Some(&'x') {
            if let (Some(&hi), Some(&lo)) = (chars.get(i + 2), chars.get(i + 3)) {
                if hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit() {
                    let byte = u8::from_str_radix(&format!("{hi}{lo}"), 16).unwrap_or(0);
                    bytes.push(byte);
                    i += 4;
                    continue;
                }
            }
        }
        i += 1;
    }

    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads_map_is_non_empty() {
        let map = nmap_udp_payloads();
        assert!(!map.is_empty());
    }

    #[test]
    fn dns_port_53_has_payload() {
        let map = nmap_udp_payloads();
        assert!(map.contains_key(&53));
        assert!(!map[&53].is_empty());
    }

    #[test]
    fn dhcp_port_67_has_payload() {
        let map = nmap_udp_payloads();
        assert!(map.contains_key(&67));
    }

    #[test]
    fn decode_basic_hex_escapes() {
        assert_eq!(decode_hex_escapes(r"\x00\x0a\xff"), vec![0x00, 0x0a, 0xff]);
    }

    #[test]
    fn parse_ports_comma_list() {
        assert_eq!(parse_ports("udp 53,69,5353 \"data\""), vec![53, 69, 5353]);
    }

    #[test]
    fn parse_ports_range_exclusive_end() {
        // RustScan uses start..end (exclusive), so 100-105 → [100,101,102,103,104].
        assert_eq!(
            parse_ports("udp 100-105 \"data\""),
            vec![100, 101, 102, 103, 104]
        );
    }

    #[test]
    fn once_lock_returns_same_reference() {
        let a = nmap_udp_payloads() as *const _;
        let b = nmap_udp_payloads() as *const _;
        assert_eq!(a, b);
    }
}
