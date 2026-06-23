# Motehold

Motehold is a private channel-based note board for a trusted local network. It
now runs as a small Rust web service with SQLite storage.

It is meant for localhost, LAN, VPN, or tailnet access. It is not a public
internet app.

## Features

- Channels with message history.
- Optional PNG, JPEG, GIF, or WebP image attachments.
- SQLite storage.
- Phone-friendly chat layout.
- Optional password auth with Argon2 password hashes.

## Run

```sh
cargo run -- serve
```

By default Motehold binds to `127.0.0.1:8787`, stores data in
`data/motehold.sqlite`, and has auth disabled for trusted local development.

For a password-protected instance:

```sh
cargo run -- hash-password --stdin
MOTEHOLD_AUTH_DISABLED=0 MOTEHOLD_PASSWORD_HASH='$argon2id$...' cargo run -- serve
```

## Configuration

```text
MOTEHOLD_BIND=127.0.0.1:8787
MOTEHOLD_DB=data/motehold.sqlite
MOTEHOLD_AUTH_DISABLED=1
MOTEHOLD_PASSWORD_HASH=<argon2 hash>
MOTEHOLD_COOKIE_SECRET=<random hex, optional>
```

Keep real `.env` files, databases, uploads, logs, and host-specific deployment
state out of this repository.

## Checks

```sh
cargo fmt --check
cargo test
cargo run -- audit-public
```
