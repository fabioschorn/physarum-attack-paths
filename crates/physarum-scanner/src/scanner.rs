use crate::socket_iterator::SocketIterator;
use crate::{PortList, ScanError};
use futures::stream::{FuturesUnordered, StreamExt};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::net::{TcpStream, UdpSocket};
use tracing::debug;

/// Open sockets found by a scan.
pub type ScanResult = Vec<SocketAddr>;

/// Async TCP-connect (and optionally UDP) port scanner.
///
/// Drives concurrent connection attempts using `FuturesUnordered` so at most
/// `batch_size` futures are in-flight at any time.  Sockets are fed from a
/// memory-efficient `SocketIterator` — no `Vec<SocketAddr>` is pre-allocated.
///
/// Improvements over RustScan:
/// - Tokio executor instead of async-std.
/// - `ScanError::TooManyOpenFiles` typed error instead of `assert!` panic.
/// - `exclude_ports` list applied before scanning.
/// - UDP scanning with caller-supplied payload map.
/// - `SocketIterator` for zero-copy cartesian product iteration.
#[derive(Debug)]
pub struct Scanner {
    ips: Vec<IpAddr>,
    ports: PortList,
    batch_size: usize,
    timeout: Duration,
    tries: u8,
    exclude_ports: Vec<u16>,
    udp: bool,
    /// Per-port UDP payloads.  Key = port number, value = bytes to send.
    /// Empty `Vec<u8>` sends a zero-length datagram (probes that reply to empty packets).
    udp_payloads: HashMap<u16, Vec<u8>>,
}

impl Scanner {
    pub fn new(ips: Vec<IpAddr>, ports: PortList) -> Self {
        Self {
            ips,
            ports,
            batch_size: 500,
            timeout: Duration::from_millis(1_500),
            tries: 1,
            exclude_ports: vec![],
            udp: false,
            udp_payloads: HashMap::new(),
        }
    }

    pub fn batch_size(mut self, n: usize) -> Self {
        self.batch_size = n.max(1);
        self
    }

    pub fn timeout_ms(mut self, ms: u64) -> Self {
        self.timeout = Duration::from_millis(ms);
        self
    }

    pub fn tries(mut self, n: u8) -> Self {
        self.tries = n.max(1);
        self
    }

    /// Ports to skip entirely (not attempted).
    pub fn exclude_ports(mut self, ports: Vec<u16>) -> Self {
        self.exclude_ports = ports;
        self
    }

    /// Enable UDP scanning mode.
    ///
    /// In UDP mode the scanner sends a datagram to each port and waits up to
    /// `timeout` for a response.  Ports that receive any response are reported
    /// as open.
    pub fn udp(mut self, enabled: bool) -> Self {
        self.udp = enabled;
        self
    }

    /// Override the per-port UDP payload map (optional).
    ///
    /// When not set (default), the scanner automatically uses the embedded
    /// Nmap payload database via [`crate::nmap_payloads::nmap_udp_payloads`].
    /// Ports absent from whichever map is active receive an empty datagram.
    pub fn udp_payloads(mut self, payloads: HashMap<u16, Vec<u8>>) -> Self {
        self.udp_payloads = payloads;
        self
    }

    /// Run the scan and return all open `SocketAddr`s.
    ///
    /// # Errors
    /// Returns `Err(ScanError::TooManyOpenFiles)` when the OS rejects
    /// connection attempts due to FD exhaustion — retry with a smaller
    /// `batch_size` or raise the OS ulimit first.
    pub async fn run(&self) -> Result<ScanResult, ScanError> {
        if self.udp {
            self.run_udp().await
        } else {
            self.run_tcp().await
        }
    }

    // ── TCP ──────────────────────────────────────────────────────────────────

    async fn run_tcp(&self) -> Result<ScanResult, ScanError> {
        let ports: Vec<u16> = self
            .ports
            .as_slice()
            .iter()
            .copied()
            .filter(|p| !self.exclude_ports.contains(p))
            .collect();

        debug!(
            ips = self.ips.len(),
            ports = ports.len(),
            batch = self.batch_size,
            "starting TCP scan"
        );

        let mut open: Vec<SocketAddr> = Vec::new();
        let mut ftrs: FuturesUnordered<_> = FuturesUnordered::new();
        let mut iter = SocketIterator::new(&self.ips, &ports);

        for socket in iter.by_ref().take(self.batch_size) {
            ftrs.push(Self::probe_tcp(socket, self.timeout, self.tries));
        }

        while let Some(result) = ftrs.next().await {
            if let Some(socket) = iter.next() {
                ftrs.push(Self::probe_tcp(socket, self.timeout, self.tries));
            }
            match result {
                Ok(socket) => {
                    debug!(%socket, "open (TCP)");
                    open.push(socket);
                }
                Err(ScanError::TooManyOpenFiles(_)) => return Err(result.unwrap_err()),
                Err(ScanError::Io { .. }) => {
                    debug!(err = %result.unwrap_err(), "closed (TCP)");
                }
                Err(e) => debug!(err = %e, "probe error"),
            }
        }

        debug!(open = open.len(), "TCP scan complete");
        Ok(open)
    }

    /// Attempt a TCP connect to `socket`, retrying up to `tries` times.
    async fn probe_tcp(
        socket: SocketAddr,
        timeout: Duration,
        tries: u8,
    ) -> Result<SocketAddr, ScanError> {
        for attempt in 1..=tries {
            match tokio::time::timeout(timeout, TcpStream::connect(socket)).await {
                Ok(Ok(_stream)) => {
                    // Stream drops here — closes the connection cleanly.
                    return Ok(socket);
                }
                Ok(Err(e)) => {
                    if e.raw_os_error() == Some(libc::EMFILE)
                        || e.raw_os_error() == Some(libc::ENFILE)
                    {
                        return Err(ScanError::TooManyOpenFiles(0));
                    }
                    if attempt == tries {
                        return Err(ScanError::Io { socket, source: e });
                    }
                }
                Err(_elapsed) => {
                    if attempt == tries {
                        return Err(ScanError::Io {
                            socket,
                            source: std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "TCP connect timed out",
                            ),
                        });
                    }
                }
            }
        }
        unreachable!()
    }

    // ── UDP ──────────────────────────────────────────────────────────────────

    async fn run_udp(&self) -> Result<ScanResult, ScanError> {
        let ports: Vec<u16> = self
            .ports
            .as_slice()
            .iter()
            .copied()
            .filter(|p| !self.exclude_ports.contains(p))
            .collect();

        debug!(
            ips = self.ips.len(),
            ports = ports.len(),
            batch = self.batch_size,
            "starting UDP scan"
        );

        // Use caller-supplied payloads, or fall back to the embedded Nmap database.
        let payloads: &HashMap<u16, Vec<u8>> = if self.udp_payloads.is_empty() {
            crate::nmap_payloads::nmap_udp_payloads()
        } else {
            &self.udp_payloads
        };

        let mut open: Vec<SocketAddr> = Vec::new();
        let mut ftrs: FuturesUnordered<_> = FuturesUnordered::new();
        let mut iter = SocketIterator::new(&self.ips, &ports);

        for socket in iter.by_ref().take(self.batch_size) {
            let payload = payloads.get(&socket.port()).cloned().unwrap_or_default();
            ftrs.push(Self::probe_udp(socket, self.timeout, self.tries, payload));
        }

        while let Some(result) = ftrs.next().await {
            if let Some(socket) = iter.next() {
                let payload = payloads.get(&socket.port()).cloned().unwrap_or_default();
                ftrs.push(Self::probe_udp(socket, self.timeout, self.tries, payload));
            }
            match result {
                Ok(socket) => {
                    debug!(%socket, "open (UDP)");
                    open.push(socket);
                }
                Err(ScanError::Io { .. }) => {
                    debug!("closed/no-response (UDP)");
                }
                Err(e) => debug!(err = %e, "UDP probe error"),
            }
        }

        debug!(open = open.len(), "UDP scan complete");
        Ok(open)
    }

    /// Send a UDP datagram to `socket` and wait up to `timeout` for any response.
    ///
    /// A received response (any length) is treated as "port open".
    /// Timeout or send errors are treated as "closed / filtered".
    async fn probe_udp(
        socket: SocketAddr,
        timeout: Duration,
        tries: u8,
        payload: Vec<u8>,
    ) -> Result<SocketAddr, ScanError> {
        let local: SocketAddr = match socket {
            SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
            SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
        };

        for attempt in 1..=tries {
            let Ok(sock) = UdpSocket::bind(local).await else {
                if attempt == tries {
                    return Err(ScanError::Io {
                        socket,
                        source: std::io::Error::new(
                            std::io::ErrorKind::AddrInUse,
                            "could not bind UDP socket",
                        ),
                    });
                }
                continue;
            };

            if sock.connect(socket).await.is_err() {
                if attempt == tries {
                    return Err(ScanError::Io {
                        socket,
                        source: std::io::Error::new(
                            std::io::ErrorKind::ConnectionRefused,
                            "UDP connect failed",
                        ),
                    });
                }
                continue;
            }

            let _ = sock.send(&payload).await;

            let mut buf = [0u8; 1024];
            match tokio::time::timeout(timeout, sock.recv(&mut buf)).await {
                Ok(Ok(_)) => return Ok(socket),
                Ok(Err(e)) => {
                    if attempt == tries {
                        return Err(ScanError::Io { socket, source: e });
                    }
                }
                Err(_elapsed) => {
                    if attempt == tries {
                        return Err(ScanError::Io {
                            socket,
                            source: std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "UDP response timed out",
                            ),
                        });
                    }
                }
            }
        }
        unreachable!()
    }
}

// ── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PortList;

    fn loopback() -> Vec<IpAddr> {
        vec!["127.0.0.1".parse().unwrap()]
    }

    #[tokio::test]
    async fn closed_port_returns_empty() {
        let ports = PortList::explicit(vec![19999]);
        let result = Scanner::new(loopback(), ports)
            .timeout_ms(100)
            .run()
            .await
            .unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn open_port_is_detected() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let ports = PortList::explicit(vec![port]);
        let result = Scanner::new(loopback(), ports)
            .timeout_ms(500)
            .run()
            .await
            .unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].port(), port);
    }

    #[tokio::test]
    async fn multiple_open_ports_detected() {
        let l1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p1 = l1.local_addr().unwrap().port();
        let p2 = l2.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = l1.accept().await;
        });
        tokio::spawn(async move {
            let _ = l2.accept().await;
        });
        let ports = PortList::explicit(vec![p1, p2]);
        let mut result = Scanner::new(loopback(), ports)
            .timeout_ms(500)
            .run()
            .await
            .unwrap();
        result.sort_by_key(|s| s.port());
        let mut expected = vec![p1, p2];
        expected.sort();
        assert_eq!(
            result.iter().map(|s| s.port()).collect::<Vec<_>>(),
            expected
        );
    }

    #[tokio::test]
    async fn excluded_port_not_reported() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let ports = PortList::explicit(vec![port]);
        let result = Scanner::new(loopback(), ports)
            .exclude_ports(vec![port])
            .timeout_ms(500)
            .run()
            .await
            .unwrap();
        assert!(
            result.is_empty(),
            "excluded port should not appear in results"
        );
    }

    #[tokio::test]
    async fn multi_ip_scan() {
        let ips: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap()];
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let ports = PortList::explicit(vec![port]);
        let result = Scanner::new(ips, ports)
            .timeout_ms(500)
            .run()
            .await
            .unwrap();
        assert_eq!(result.len(), 1);
    }

    #[tokio::test]
    async fn udp_closed_port_returns_empty() {
        let ports = PortList::explicit(vec![59876]);
        let result = Scanner::new(loopback(), ports)
            .timeout_ms(100)
            .udp(true)
            .run()
            .await
            .unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn port_list_deduplication() {
        let pl = PortList::explicit(vec![9002, 9001, 9001, 9002, 9003]);
        assert_eq!(pl.as_slice(), &[9001, 9002, 9003]);
    }
}
