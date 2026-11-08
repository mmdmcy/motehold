# Motehold

Motehold is a private channel-based note board for a trusted local network. It
is one Go program built from the standard library only: no third-party modules,
no database library and no cgo. Its records live in a checksummed JSON file and
its images and attachments in a folder beside it.

It is meant for localhost, LAN, VPN, or tailnet access. It is not a public
internet app.

## Features

- Channels with message history.
- Scrollable message cards with one-click copy actions.
- Optional PNG, JPEG, GIF, or WebP image attachments.
- Markdown (`.md`/`.markdown`) attachments with a bounded in-chat preview and
  full copy/download actions.
- A standard-library file store (see Storage).
- Phone-friendly chat layout.
- Local password auth with PBKDF2-HMAC-SHA256 password hashes.
- Optional OpenID Connect organization login with Authorization Code, S256
  PKCE, state, nonce, and app-owned opaque sessions.

## Run

```sh
go build -o motehold .
printf '%s' 'the password' | ./motehold hash-password --stdin
MOTEHOLD_PASSWORD_HASH='$pbkdf2-sha256$...' ./motehold serve
```

By default Motehold binds to `127.0.0.1:8787`, keeps its store next to
`data/motehold.sqlite` (as `data/motehold.json` and `data/motehold.blobs/`),
and requires a local password.

For auth-free local development on loopback only:

```sh
MOTEHOLD_AUTH_DISABLED=1 ./motehold serve
```

Motehold refuses to start when auth is disabled and `MOTEHOLD_BIND` is not a
loopback address. To knowingly serve an unauthenticated board on a LAN or
tailnet address, set `MOTEHOLD_ALLOW_OPEN_BIND=1` together with
`MOTEHOLD_AUTH_DISABLED=1`.

## Configuration

```text
MOTEHOLD_BIND=127.0.0.1:8787
MOTEHOLD_DB=data/motehold.sqlite
MOTEHOLD_AUTH_DISABLED=0
MOTEHOLD_ALLOW_OPEN_BIND=0
MOTEHOLD_PASSWORD_HASH=<hash from hash-password>
MOTEHOLD_COOKIE_SECRET=<stable random hex, at least 32 bytes>
MOTEHOLD_COOKIE_SECURE=0
MOTEHOLD_USER=motehold
```

`MOTEHOLD_DB` keeps the name it had when Motehold used SQLite: the store is the
same path with `.json` for the records and `.blobs` for the files, so
`/srv/motehold/motehold.sqlite` means `/srv/motehold/motehold.json` and
`/srv/motehold/motehold.blobs/`. A path ending in `.json` names the store
directly.

Only PBKDF2-SHA256 hashes from `hash-password` are accepted
(`$pbkdf2-sha256$i=600000,l=32$SALT$HASH`; 600,000 iterations is OWASP's
recommendation for PBKDF2-HMAC-SHA256). The Argon2 hashes of the Rust version
cannot be checked without an Argon2 implementation, which Go's standard library
does not have: Motehold refuses to start with one and names the command that
makes a new hash. `MOTEHOLD_USER` is the user name for HTTP Basic credentials.
After five rejected passwords or Basic credentials from one client address
within ten minutes, further attempts from that address are refused with `429`
until the oldest failure is ten minutes old.

Set `MOTEHOLD_COOKIE_SECRET` explicitly whenever authentication is enabled.
Keep the same deployment-managed value across restarts and all instances; a
64-character value from `openssl rand -hex 32` is sufficient. If the value is
absent, invalid hex, or shorter than 32 decoded bytes, Motehold generates an
ephemeral process-local key. That development fallback invalidates sessions
and pending OIDC flows on restart.

Motehold remains fully standalone. Managed login is an optional dogfood-alpha
integration, not an enterprise-readiness or certification claim. To enable it,
set all four values below, set `MOTEHOLD_AUTH_DISABLED=0`, and keep
`MOTEHOLD_PASSWORD_HASH` configured as an independent local break-glass path:

```text
MOTEHOLD_OIDC_ISSUER=https://identity.example.invalid
MOTEHOLD_OIDC_CLIENT_ID=motehold
MOTEHOLD_OIDC_CLIENT_SECRET=<oidc client secret>
MOTEHOLD_OIDC_REDIRECT_URL=https://motehold.example.invalid/auth/oidc/callback
MOTEHOLD_OIDC_ALLOWED_SUBJECTS=<comma-separated sub claims>
MOTEHOLD_OIDC_ALLOWED_EMAILS=<comma-separated email claims>
```

A verified ID token only creates a session when its `sub` is listed in
`MOTEHOLD_OIDC_ALLOWED_SUBJECTS` or its `email` (case-insensitive) is listed in
`MOTEHOLD_OIDC_ALLOWED_EMAILS`; other identities get `403` and a log line with
the subject. When neither list is set, every identity the issuer vouches for
is accepted and Motehold prints a startup warning saying so. Email matching
trusts the issuer's `email` claim, so prefer subjects where the provider
allows users to change their address.

The issuer and redirect URL must use HTTPS. Loopback HTTP is accepted only for
explicit local dogfood testing. Discovered authorization, token, userinfo, and
JWKS endpoints follow the same rule, and discovery redirects are refused. The
client prefers advertised `client_secret_post`, supports
`client_secret_basic`, uses the standards default of `client_secret_basic` when
the discovery field is absent, and rejects providers that advertise neither.
ID tokens signed with EdDSA (Ed25519), RS256, ES256 or HS256 are checked
against the provider's advertised algorithms and keys. Provider access,
refresh, and ID tokens are not stored after the callback. If the provider is
unavailable, organization login can fail without disabling the local login
form.

For local service discovery and health checks, Motehold exposes a minimal,
unauthenticated status envelope at
`/.well-known/linuxmice/component`. It contains no notes, attachment metadata,
database paths, credentials, or identity endpoints. Its `identity_mode` is
`disabled`, `local`, or `oidc+local` according to the active configuration.
The matching optional catalog declaration is `linuxmice-component.toml`;
Motehold does not require the LinuxMice hub or identity service to run.

Keep real `.env` files, stores, uploads, logs, and host-specific deployment
state out of this repository.

## Storage

- **One record file**, `motehold.json`. Its first line names the format and
  the SHA-256 of the rest; a file whose checksum, JSON or rules do not hold is
  refused, never repaired.
- **One file per image or attachment** in `motehold.blobs/`, named by its
  SHA-256 and checked against it when Motehold starts and whenever it is read.
- **Atomic writes:** a change writes a new owner-only file beside the old one,
  syncs it, renames it over the old one and syncs the folder.
- **One process:** Motehold holds an exclusive lock on `motehold.json.lock`
  while it runs.
- **The SQL schema's rules are enforced in Go:** channel names unique without
  regard to ASCII case, notes pointing at an existing channel (deleting a
  channel deletes its notes), unique import sources, ids that are never reused.

### Moving from the Rust version

`import-sqlite` reads a copy of the Rust version's SQLite database once,
through the system's `sqlite3` command (read-only, immutable, schema 3), and
writes the store where `MOTEHOLD_DB` points. Channels and notes keep their ids,
times, images and attachments; sessions stay behind, so people sign in again.
It never overwrites a store and prints only counts.

```sh
sqlite3 -readonly data/motehold.sqlite ".backup /tmp/motehold-copy.sqlite"
MOTEHOLD_DB=data/motehold.sqlite ./motehold import-sqlite --from /tmp/motehold-copy.sqlite
```

The Rust version's Argon2 password hashes are not accepted (see
Configuration): make a new one with `hash-password --stdin`.

The Rust version is kept, buildable, in `archive/rust/`.

## Checks

```sh
gofmt -l .
go vet ./...
go test ./...
go run . audit-public
go list -m all   # only github.com/mmdmcy/motehold: no third-party modules
```
