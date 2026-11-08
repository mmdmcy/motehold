//! Authentication, OIDC trust flow, session policy, and publication safety.
//!
//! Entry points support the HTTP authentication routes and the public-audit CLI.
//! This layer may use application state, SQLite, provider protocols, and HTML
//! presentation required by authentication responses.

pub(crate) mod auth;
pub(crate) mod oidc;
pub(crate) mod public_audit;
