#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("malformed {0}")]
    Malformed(&'static str),
    #[error("invalid signature on {0}")]
    BadSignature(&'static str),
    #[error("no valid genesis change for this identity")]
    NoIdentity,
    #[error("the change log has a change from a newer protocol version this software can't read")]
    Unreadable,
    #[error("not allowed: {0}")]
    Refused(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("node error {status}: {message}")]
    Node { status: u16, message: String },
    #[error("network: {0}")]
    Network(String),
    #[error("wrong password or damaged backup file")]
    BadPassword,
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::Network(e.to_string())
    }
}
