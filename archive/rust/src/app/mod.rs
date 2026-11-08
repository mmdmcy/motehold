//! Process bootstrap, environment configuration, server state, and database opening.
//!
//! The entry point is [`serve`]. This layer may wire HTTP, persistence, note
//! policy, and security capabilities without owning their behavior.

mod config;
mod database;
mod server;
mod state;

pub(crate) use config::Config;
pub(crate) use server::serve;
pub(crate) use state::AppState;
