use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("too many open files — reduce batch_size (current: {0})")]
    TooManyOpenFiles(usize),

    #[error("I/O error on {socket}: {source}")]
    Io {
        socket: std::net::SocketAddr,
        #[source]
        source: std::io::Error,
    },
}
