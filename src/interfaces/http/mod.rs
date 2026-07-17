//! Axum routing, request handlers, component status, and HTML presentation.
//!
//! The entry point is [`build_router`]. Handlers depend on app state, note
//! policy, persistence, and security capabilities.

mod component_status;
mod notes;
pub(crate) mod presentation;
mod router;

pub(crate) use router::build_router;
