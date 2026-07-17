# Motehold Architecture

Motehold is a small Rust/Axum application organized by product ownership. The
binary only selects a CLI command and hands control to the owning capability.

## Runtime Shape

- One Rust process serves Axum routes and uses one SQLite database.
- `src/main.rs` dispatches the existing CLI commands; `src/app/` loads
  configuration, opens storage, creates shared state, and starts the server.
- The browser UI is an HTTP presentation over explicit note, persistence, and
  authentication modules.

## Core Boundaries

| Capability | Ownership | Entry points | Permitted dependencies |
| --- | --- | --- | --- |
| Process and configuration | `src/app/` | `app::serve` | Features, HTTP router, persistence, security |
| Notes and channels policy | `src/features/notes/` | Upload limits and validation rules | No application infrastructure |
| Public-tree audit | `src/security/public_audit.rs` | `audit_public_cmd` | Git and filesystem process boundaries |
| HTTP delivery | `src/interfaces/http/` | `build_router`, route handlers | App state, features, persistence, security |
| HTML presentation | `src/interfaces/http/presentation.rs` | `page`, `notes_page` | Note query projections and note policy constants |
| Durable storage | `src/persistence/` | Migrations and note/channel queries | SQLite and note policy types only |
| Authentication, OIDC, and publication safety | `src/security/` | Auth configuration, guards, login/logout, OIDC start/callback, public-tree audit | App state, HTML presentation, SQLite, provider protocol, Git |

Dependency direction is startup to interfaces/features/persistence/security,
HTTP interfaces to note policy and persistence, and persistence to SQLite.

## Data Model

- Versioned migrations own channels, notes, attachments, app sessions, and
  pending OIDC flows.
- Note and channel SQL is isolated in `src/persistence/notes.rs`.
- The ownership refactor does not change the SQLite schema or migration order.

## Trust, Privacy, And Cost Boundaries

- Authentication, session hashing, OIDC validation, and publication auditing
  stay under `src/security/`.
- OIDC remains optional. Local authentication and standalone mode do not need
  an identity provider to be available.
- Upload limits remain note policy and are enforced by the HTTP boundary.

## Extension Points

- Add note policy in `src/features/notes/`, storage operations in
  `src/persistence/notes.rs`, and delivery routes in `src/interfaces/http/`.
- Add startup wiring in `src/app/`; keep `src/main.rs` limited to CLI/bootstrap.

## Verification

```bash
cargo fmt --all --check
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo test
cargo run --quiet -- audit-public
cargo katrust inspect
git diff --check
```
