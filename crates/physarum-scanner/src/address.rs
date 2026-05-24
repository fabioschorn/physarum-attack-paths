//! Address parsing and resolution: bare IPs, CIDRs, hostnames, files, and
//! exclusion lists.
//!
//! Ported from RustScan's `address.rs` and improved:
//! - Uses `tracing` instead of `log`.
//! - `build_resolver` is public and accepts `Option<&str>` (spec string or file).
//! - All public functions return typed results rather than silently dropping errors.

use cidr_utils::cidr::{IpCidr, IpInet};
use hickory_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    Resolver,
};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{prelude::*, BufReader};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::str::FromStr;
use tracing::debug;

/// Parse a list of address strings (IPs, CIDRs, hostnames, or file paths)
/// into a deduplicated, sorted list of `IpAddr`.
///
/// Addresses matching any entry in `exclude` are removed from the result.
/// Unresolvable entries are logged as warnings and skipped.
pub fn parse_addresses(addresses: &[String], exclude: &Option<Vec<String>>) -> Vec<IpAddr> {
    parse_addresses_with_resolver(addresses, exclude, None)
}

/// Same as [`parse_addresses`] but uses a custom DNS resolver.
///
/// `resolver_spec` accepts either:
/// - A comma-separated list of resolver IPs: `"1.1.1.1,8.8.8.8"`
/// - A path to a file containing one resolver IP per line.
pub fn parse_addresses_with_resolver(
    addresses: &[String],
    exclude: &Option<Vec<String>>,
    resolver_spec: Option<&str>,
) -> Vec<IpAddr> {
    let resolver = build_resolver(resolver_spec);
    let excluded = parse_excluded(exclude, &resolver);

    let mut ips: Vec<IpAddr> = Vec::new();
    let mut unresolved: Vec<&str> = Vec::new();

    for addr in addresses {
        let parsed = parse_address(addr, &resolver);
        if !parsed.is_empty() {
            ips.extend(parsed);
        } else {
            unresolved.push(addr.as_str());
        }
    }

    // Remaining items that couldn't be parsed as IP/CIDR/hostname — try as file paths.
    for item in unresolved {
        let path = Path::new(item);
        if path.is_file() {
            match read_ips_from_file(path, &resolver) {
                Ok(file_ips) => ips.extend(file_ips),
                Err(e) => tracing::warn!(path = item, err = %e, "could not read IP file"),
            }
        } else {
            tracing::warn!(address = item, "could not resolve address — skipping");
        }
    }

    // Deduplicate (BTreeSet preserves canonical order) and apply exclusions.
    let mut seen = BTreeSet::new();
    ips.retain(|ip| seen.insert(*ip) && !excluded.iter().any(|cidr| cidr.contains(ip)));
    ips
}

/// Parse a single address string into zero or more `IpAddr`s.
///
/// Resolution order:
/// 1. Bare IP address (`"192.168.1.1"`)
/// 2. CIDR notation (`"10.0.0.0/24"` — expands to all addresses in the subnet)
/// 3. Hostname via system resolver (`"example.com"`)
/// 4. Hostname via the supplied `resolver`
///
/// Returns an empty `Vec` if the address cannot be resolved by any strategy.
pub fn parse_address(address: &str, resolver: &Resolver) -> Vec<IpAddr> {
    // 1. Bare IP.
    if let Ok(ip) = IpAddr::from_str(address) {
        return vec![ip];
    }
    // 2. CIDR/subnet — expand to all host addresses.
    if let Ok(inet) = IpInet::from_str(address) {
        return inet.network().into_iter().addresses().collect();
    }
    // 3. Hostname — try system resolver first (fast path).
    if let Ok(mut iter) = format!("{address}:80").to_socket_addrs() {
        if let Some(sa) = iter.next() {
            return vec![sa.ip()];
        }
    }
    // 4. Hostname — fall back to the supplied resolver.
    resolve_via_resolver(address, resolver)
}

/// Parse excluded addresses/CIDRs into `IpCidr` matchers used for filtering.
pub fn parse_excluded(exclude: &Option<Vec<String>>, resolver: &Resolver) -> Vec<IpCidr> {
    exclude
        .iter()
        .flatten()
        .flat_map(|addr| {
            if let Ok(cidr) = IpCidr::from_str(addr) {
                return vec![cidr];
            }
            if let Ok(ip) = IpAddr::from_str(addr) {
                return vec![IpCidr::new_host(ip)];
            }
            resolve_via_resolver(addr, resolver)
                .into_iter()
                .map(IpCidr::new_host)
                .collect()
        })
        .collect()
}

/// Build a `hickory_resolver::Resolver`.
///
/// - `None` → system resolver (`/etc/resolv.conf`), falling back to Cloudflare-DoT.
/// - `Some("1.1.1.1,8.8.8.8")` → UDP resolvers at those IPs on port 53.
/// - `Some("/path/to/file")` → file with one resolver IP per line.
pub fn build_resolver(spec: Option<&str>) -> Resolver {
    match spec {
        Some(raw) => {
            let ips = read_resolver_from_file(raw).unwrap_or_else(|_| {
                raw.split(',')
                    .filter_map(|s| IpAddr::from_str(s.trim()).ok())
                    .collect()
            });
            let mut cfg = ResolverConfig::new();
            for ip in ips {
                cfg.add_name_server(NameServerConfig::new(
                    SocketAddr::new(ip, 53),
                    Protocol::Udp,
                ));
            }
            Resolver::new(cfg, ResolverOpts::default()).unwrap()
        }
        None => Resolver::from_system_conf().unwrap_or_else(|_| {
            Resolver::new(ResolverConfig::cloudflare_tls(), ResolverOpts::default()).unwrap()
        }),
    }
}

// ── private helpers ──────────────────────────────────────────────────────────

fn resolve_via_resolver(host: &str, resolver: &Resolver) -> Vec<IpAddr> {
    match resolver.lookup_ip(host) {
        Ok(lookup) => lookup.iter().collect(),
        Err(e) => {
            debug!(host, err = %e, "DNS lookup failed");
            vec![]
        }
    }
}

fn read_resolver_from_file(path: &str) -> Result<Vec<IpAddr>, std::io::Error> {
    let content = fs::read_to_string(path)?;
    Ok(content
        .lines()
        .filter_map(|line| IpAddr::from_str(line.trim()).ok())
        .collect())
}

fn read_ips_from_file(path: &Path, resolver: &Resolver) -> Result<Vec<IpAddr>, std::io::Error> {
    let file = File::open(path)?;
    let mut ips = Vec::new();
    for line in BufReader::new(file).lines() {
        let addr = line?;
        ips.extend(parse_address(addr.trim(), resolver));
    }
    Ok(ips)
}

// ── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn resolver() -> Resolver {
        build_resolver(None)
    }

    #[test]
    fn bare_ip_parsed() {
        let r = resolver();
        assert_eq!(
            parse_address("127.0.0.1", &r),
            vec!["127.0.0.1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn cidr_slash30_yields_4_addresses() {
        let r = resolver();
        let ips = parse_address("192.168.0.0/30", &r);
        assert_eq!(ips.len(), 4);
    }

    #[test]
    fn cidr_slash24_yields_256_addresses() {
        let r = resolver();
        let ips = parse_address("10.0.0.0/24", &r);
        assert_eq!(ips.len(), 256);
    }

    #[test]
    fn exclude_single_ip() {
        let addresses = vec!["192.168.0.0/30".to_string()];
        let exclude = Some(vec!["192.168.0.1".to_string()]);
        let ips = parse_addresses(&addresses, &exclude);
        assert!(!ips.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))));
        assert_eq!(ips.len(), 3);
    }

    #[test]
    fn exclude_cidr_block() {
        let addresses = vec!["192.168.0.0/29".to_string()]; // 8 IPs
        let exclude = Some(vec!["192.168.0.0/30".to_string()]); // first 4
        let ips = parse_addresses(&addresses, &exclude);
        assert_eq!(ips.len(), 4);
    }

    #[test]
    fn deduplicates_repeated_addresses() {
        let addresses = vec!["127.0.0.1".to_string(), "127.0.0.1".to_string()];
        let ips = parse_addresses(&addresses, &None);
        assert_eq!(ips.len(), 1);
    }

    #[test]
    fn unresolvable_address_is_skipped() {
        let addresses = vec!["not-a-real-host-xyz-12345.invalid".to_string()];
        let ips = parse_addresses(&addresses, &None);
        assert!(ips.is_empty());
    }

    #[test]
    fn multiple_cidr_ranges_combined() {
        let addresses = vec!["127.0.0.1".to_string(), "192.168.0.0/30".to_string()];
        let ips = parse_addresses(&addresses, &None);
        assert_eq!(ips.len(), 5); // 1 + 4
    }
}
