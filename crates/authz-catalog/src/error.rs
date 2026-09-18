use thiserror::Error;

#[derive(Debug, Error)]
pub enum CatalogError {
    #[error("catalog io: {0}")]
    Io(#[from] std::io::Error),
    #[error("catalog parse: {0}")]
    Parse(String),
    #[error("catalog validate: {0}")]
    Validate(String),
}
