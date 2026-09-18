//! Persistent SQLite state — off the authz hot path except buffered audit writes.

mod db;
mod error;
mod migrations;

pub use db::PaacStore;
pub use error::StoreError;
