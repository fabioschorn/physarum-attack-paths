use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("too many open files — reduce batch_size (current: {0}) or raise ulimit")]
    TooManyOpenFiles(usize),

    #[error("I/O error on {socket}: {source}")]
    Io {
        socket: std::net::SocketAddr,
        #[source]
        source: std::io::Error,
    },

    #[error("address parse error: {0}")]
    AddressParse(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("script error: {0}")]
    Script(String),
}

impl From<anyhow::Error> for ScanError {
    fn from(e: anyhow::Error) -> Self {
        ScanError::Script(e.to_string())
    }
}
