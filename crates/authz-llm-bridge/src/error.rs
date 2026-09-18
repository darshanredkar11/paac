use thiserror::Error;

#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("bridge error: {0}")]
    Msg(String),
    #[error(transparent)]
    Authz(#[from] authz_core::AuthzError),
}
