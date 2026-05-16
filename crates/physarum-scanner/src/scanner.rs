use crate::{PortList, ScanError};
use futures::stream::{FuturesUnordered, StreamExt};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::net::TcpStream;
use tracing::debug;

/// Open sockets found by a scan.
pub type ScanResult = Vec<SocketAddr>;

/// Async TCP connect port scanner.
///
/// Drives concurrent connection attempts using `FuturesUnordered` so the
/// concurrency is naturally limited to `batch_size` in-flight futures at
/// any point.  This mirrors RustScan's approach but runs on the tokio
/// executor instead of async-std.
#[derive(Debug)]
pub struct Scanner {
    ips: Vec<IpAddr>,
    ports: PortList,
    batch_size: usize,
    timeout: Duration,
    tries: u8,
}

impl Scanner {
    pub fn new(ips: Vec<IpAddr>, ports: PortList) -> Self {
        Self {
            ips,
            ports,
            batch_size: 500,
            timeout: Duration::from_millis(1_500),
            tries: 1,
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

    /// Run the scan and return all open `SocketAddr`s.
    ///
    /// Returns `Err(ScanError::TooManyOpenFiles)` when the OS rejects
    /// connection attempts due to file-descriptor exhaustion — callers should
    /// retry with a smaller `batch_size`.  In RustScan this was a panic; here
    /// it is a typed error so the caller can recover gracefully.
    pub async fn run(&self) -> Result<ScanResult, ScanError> {
        let sockets: Vec<SocketAddr> = self
            .ips
            .iter()
            .flat_map(|ip| {
                self.ports
                    .as_slice()
                    .iter()
                    .map(move |&p| SocketAddr::new(*ip, p))
            })
            .collect();

        debug!(
            ips = self.ips.len(),
            ports = self.ports.as_slice().len(),
            targets = sockets.len(),
            batch = self.batch_size,
            "starting scan"
        );

        let mut open: Vec<SocketAddr> = Vec::new();
        let mut ftrs: FuturesUnordered<_> = FuturesUnordered::new();
        let mut iter = sockets.into_iter();

        // Seed up to batch_size concurrent futures.
        for socket in iter.by_ref().take(self.batch_size) {
            ftrs.push(Self::probe(socket, self.timeout, self.tries));
        }

        while let Some(result) = ftrs.next().await {
            // Refill: one future completed, enqueue the next socket.
            if let Some(socket) = iter.next() {
                ftrs.push(Self::probe(socket, self.timeout, self.tries));
            }

            match result {
                Ok(socket) => {
                    debug!(%socket, "open");
                    open.push(socket);
                }
                Err(ScanError::TooManyOpenFiles(_)) => return Err(result.unwrap_err()),
                Err(ScanError::Io { .. }) => {
                    // Connection refused / timed out — port closed, not an error.
                    debug!(err = %result.unwrap_err(), "closed");
                }
            }
        }

        debug!(open = open.len(), "scan complete");
        Ok(open)
    }

    /// Attempt a TCP connect to `socket`, retrying up to `tries` times.
    async fn probe(
        socket: SocketAddr,
        timeout: Duration,
        tries: u8,
    ) -> Result<SocketAddr, ScanError> {
        for attempt in 1..=tries {
            match tokio::time::timeout(timeout, TcpStream::connect(socket)).await {
                Ok(Ok(_stream)) => {
                    // Stream is dropped here, which closes the connection cleanly.
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
                                "connection timed out",
                            ),
                        });
                    }
                }
            }
        }
        unreachable!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PortList;

    fn loopback() -> Vec<IpAddr> {
        vec!["127.0.0.1".parse().unwrap()]
    }

    // Scanning a port where nothing listens should return empty (not panic).
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

    // Scanning a real listener must return that socket.
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

    // Scanning multiple closed ports stays hermetic and returns empty.
    #[tokio::test]
    async fn multiple_closed_ports_return_empty() {
        let ports = PortList::explicit(vec![19991, 19992, 19993]);
        let result = Scanner::new(loopback(), ports)
            .timeout_ms(100)
            .run()
            .await
            .unwrap();
        assert!(result.is_empty());
    }

    // Scanning two open ports returns both.
    #[tokio::test]
    async fn two_open_ports_detected() {
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
        let result_ports: Vec<u16> = result.iter().map(|s| s.port()).collect();
        assert_eq!(result_ports, expected);
    }

    // PortList deduplication.
    #[test]
    fn port_list_deduplicates() {
        let pl = PortList::explicit(vec![9002, 9001, 9001, 9002, 9003]);
        assert_eq!(pl.as_slice(), &[9001, 9002, 9003]);
    }
}
