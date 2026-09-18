use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("parse error: {0}")]
    Parse(String),
    #[error("validation error: {0}")]
    Validate(String),
    #[error("store error: {0}")]
    Store(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("cedar error: {0}")]
    Cedar(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
