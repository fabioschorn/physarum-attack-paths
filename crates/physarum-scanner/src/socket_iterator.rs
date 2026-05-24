use std::net::{IpAddr, SocketAddr};

/// Memory-efficient cartesian product iterator over a slice of IPs and a slice
/// of ports.
///
/// For each port, all IPs are emitted before the iterator advances to the next
/// port:
///
/// ```text
/// ips = [A, B], ports = [22, 80]
/// yields: A:22, B:22, A:80, B:80
/// ```
///
/// This "port-major" order matches RustScan's approach: spreading connection
/// attempts across all targets before repeating a port reduces per-host
/// connection bursts and is friendlier to rate-limiting firewalls.
///
/// The iterator holds only two indices rather than materialising the full
/// `IpAddr × port` product into a `Vec`, which matters at scale (e.g. 65 535
/// ports × 256 hosts = ~16 M sockets).
pub(crate) struct SocketIterator<'s> {
    ips: &'s [IpAddr],
    ports: &'s [u16],
    port_idx: usize,
    ip_idx: usize,
}

impl<'s> SocketIterator<'s> {
    pub(crate) fn new(ips: &'s [IpAddr], ports: &'s [u16]) -> Self {
        Self {
            ips,
            ports,
            port_idx: 0,
            ip_idx: 0,
        }
    }
}

impl Iterator for SocketIterator<'_> {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.port_idx >= self.ports.len() {
            return None;
        }
        let socket = SocketAddr::new(self.ips[self.ip_idx], self.ports[self.port_idx]);
        self.ip_idx += 1;
        if self.ip_idx >= self.ips.len() {
            self.ip_idx = 0;
            self.port_idx += 1;
        }
        Some(socket)
    }
}

#[cfg(test)]
mod tests {
    use super::SocketIterator;
    use std::net::{IpAddr, SocketAddr};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn port_major_ordering() {
        let ips = vec![ip("127.0.0.1"), ip("192.168.0.1")];
        let ports = vec![22u16, 80, 443];
        let result: Vec<SocketAddr> = SocketIterator::new(&ips, &ports).collect();
        assert_eq!(
            result,
            vec![
                sa("127.0.0.1:22"),
                sa("192.168.0.1:22"),
                sa("127.0.0.1:80"),
                sa("192.168.0.1:80"),
                sa("127.0.0.1:443"),
                sa("192.168.0.1:443"),
            ]
        );
    }

    #[test]
    fn total_count_equals_product() {
        let ips: Vec<IpAddr> = (0..5).map(|i| ip(&format!("10.0.0.{i}"))).collect();
        let ports: Vec<u16> = vec![22, 80, 443, 8080, 8443];
        let count = SocketIterator::new(&ips, &ports).count();
        assert_eq!(count, ips.len() * ports.len());
    }

    #[test]
    fn empty_ports_yields_nothing() {
        let ips = vec![ip("10.0.0.1")];
        let ports: Vec<u16> = vec![];
        assert_eq!(SocketIterator::new(&ips, &ports).count(), 0);
    }

    #[test]
    fn single_ip_single_port() {
        let ips = vec![ip("10.0.0.1")];
        let ports = vec![9001u16];
        let result: Vec<SocketAddr> = SocketIterator::new(&ips, &ports).collect();
        assert_eq!(result, vec![sa("10.0.0.1:9001")]);
    }
}
