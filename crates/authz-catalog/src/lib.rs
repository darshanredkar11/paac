//! Resource catalog mapping production assets and tools to policy resources.

mod catalog;
mod error;

pub use catalog::{
    CatalogResource, ResourceCatalog, ToolMapping, load_catalog, validate_catalog,
};
pub use error::CatalogError;
