//! Durable SQLite schema and note/channel records.
//!
//! Entry points are the migration runner and explicit note/channel queries.
//! This layer depends on SQLite, not on HTTP delivery.

pub(crate) mod migrations;
pub(crate) mod notes;
