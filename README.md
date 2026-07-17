# Motehold

Motehold is a private channel-based note board for a trusted local network. It
now runs as a small Rust web service with SQLite storage.

It is meant for localhost, LAN, VPN, or tailnet access. It is not a public
internet app.

## Features

- Channels with message history.
- Scrollable message cards with one-click copy actions.
- Optional PNG, JPEG, GIF, or WebP image attachments.
- Markdown (`.md`/`.markdown`) attachments with a bounded in-chat preview and
  full copy/download actions.
- SQLite storage.
- Phone-friendly chat layout.
- Local password auth with Argon2 password hashes.
- Optional OpenID Connect organization login with Authorization Code, S256
  PKCE, state, nonce, and app-owned opaque sessions.

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
MOTEHOLD_COOKIE_SECRET=<stable random hex, at least 32 bytes>
MOTEHOLD_COOKIE_SECURE=0
```

Set `MOTEHOLD_COOKIE_SECRET` explicitly whenever authentication is enabled.
Keep the same deployment-managed value across restarts and all instances; a
64-character value from `openssl rand -hex 32` is sufficient. If the value is
absent, invalid hex, or shorter than 32 decoded bytes, Motehold generates an
ephemeral process-local key. That development fallback invalidates sessions
and pending OIDC flows on restart and cannot support multiple instances.

Motehold remains fully standalone. Managed login is an optional dogfood-alpha
integration, not an enterprise-readiness or certification claim. To enable it,
set all four values below, set `MOTEHOLD_AUTH_DISABLED=0`, and keep
`MOTEHOLD_PASSWORD_HASH` configured as an independent local break-glass path:

```text
MOTEHOLD_OIDC_ISSUER=https://identity.example.invalid
MOTEHOLD_OIDC_CLIENT_ID=motehold
MOTEHOLD_OIDC_CLIENT_SECRET=<oidc client secret>
MOTEHOLD_OIDC_REDIRECT_URL=https://motehold.example.invalid/auth/oidc/callback
```

The issuer and redirect URL must use HTTPS. Loopback HTTP is accepted only for
explicit local dogfood testing. Discovered authorization, token, userinfo, and
JWKS endpoints follow the same rule, and discovery redirects are refused. The
client prefers advertised `client_secret_post`, supports
`client_secret_basic`, uses the standards default of `client_secret_basic` when
the discovery field is absent, and rejects providers that advertise neither.
Provider access, refresh, and ID tokens are not stored after the callback. If
the provider is unavailable, organization login can fail without disabling the
local login form.

For local service discovery and health checks, Motehold exposes a minimal,
unauthenticated status envelope at
`/.well-known/linuxmice/component`. It contains no notes, attachment metadata,
database paths, credentials, or identity endpoints. Its `identity_mode` is
`disabled`, `local`, or `oidc+local` according to the active configuration.
The matching optional catalog declaration is `linuxmice-component.toml`;
Motehold does not require the LinuxMice hub or identity service to run.

Keep real `.env` files, databases, uploads, logs, and host-specific deployment
state out of this repository.

## Checks

```sh
cargo fmt --check
cargo test
cargo run -- audit-public
```
