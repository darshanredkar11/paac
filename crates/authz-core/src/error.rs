use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthzError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("policy error: {0}")]
    Policy(String),
    #[error("cedar error: {0}")]
    Cedar(String),
    #[error("entity error: {0}")]
    Entity(String),
}
