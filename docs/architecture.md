# Motehold Architecture

Motehold is one Go program in one package, built from the standard library
only. `main.go` selects a CLI command; each file owns one capability.

## Runtime Shape

- One Go process serves HTTP with `net/http` and keeps its data in a
  standard-library file store (`store.go`): a checksummed JSON file for the
  records and a folder of content-named files for images and attachments.
- The browser UI is server-rendered HTML with a little inline JavaScript, as
  before; no frontend build step.

## Core Boundaries

| Capability | File | Entry points | Uses |
| --- | --- | --- | --- |
| Process and configuration | `main.go` | `serve`, `configFromEnv`, `newApp` | Every capability below |
| HTTP delivery | `web.go` | `router`, `response`, form/query/path parsing | Nothing app-specific |
| Notes and channels | `notes.go` | Upload limits, validation rules, note handlers | Store, auth guards, pages |
| HTML presentation | `pages.go`, `page.css` | `page`, `notesPage`, `loginBody` | Note rows and policy constants |
| Durable storage | `store.go` | `openStore`, `view`, `update`, blobs | Filesystem only |
| One-time import | `importer.go` | `import-sqlite` | The system's `sqlite3`, store |
| Local authentication | `auth.go`, `password.go` | Guards, login/logout, sessions, throttle, `hash-password` | Store, pages |
| OIDC sign-in | `oidc.go` | `oidcStart`, `oidcCallback` | `net/http`, `crypto/*`, store |
| Status envelope | `status.go` | The component status route (see README) | Auth config |
| Public-tree audit | `audit.go` | `audit-public` | Git and the filesystem |

## Data Model

- `storeData` holds channels, notes, app sessions, pending OIDC flows and the
  next ids. `validate` enforces what the SQL schema did: unique channel names
  without regard to ASCII case, notes pointing at a channel, unique import
  sources, the session method's allowed values, ids that are never reused.
- Every change goes through `store.update`: it works on a copy, validates it,
  writes the file atomically and only then replaces the data in memory.

## Trust, Privacy, And Cost Boundaries

- Session tokens and OIDC state are stored only as HMAC-SHA256 digests keyed
  with `MOTEHOLD_COOKIE_SECRET`.
- OIDC remains optional. Local authentication and standalone mode do not need
  an identity provider to be available.
- Upload limits remain note policy and are enforced at the HTTP boundary.

## Verification

```bash
gofmt -l .
go vet ./...
go test ./...
go run . audit-public
go list -m all
git diff --check
```
