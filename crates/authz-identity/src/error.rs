use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("identity error: {0}")]
    Msg(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("jwt error: {0}")]
    Jwt(String),
}
